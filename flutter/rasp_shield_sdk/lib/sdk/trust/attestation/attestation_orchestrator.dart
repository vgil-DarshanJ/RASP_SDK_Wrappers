import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../../activation_manager.dart';
import '../../device_identity.dart';
import '../../sdk_config.dart';
import 'attestation_challenge.dart';
import 'attestation_replay_guard.dart';
import 'attestation_result.dart';
import 'play_integrity.dart';

/// Runs the full challenge → native token → backend verify → normalize
/// lifecycle for Android Play Integrity, and caches the outcome for
/// [TrustAnchorCollector] to read.
///
/// See `docs/PLAY_INTEGRITY_NATIVE_AUDIT.md` for the end-to-end architecture
/// this class assembles: [PlayIntegrityAttestor] (native token), the
/// backend's `/api/v1/sdk/attestation/challenge` + `/attestation/verify`
/// (server-issued nonce, server-authoritative verification), and
/// [AttestationReplayGuard] (this device's own defense-in-depth mirror of
/// the server's binding/replay checks — the server's checks are the ones
/// that actually matter; see that class's doc comment).
///
/// ## Why this is cached, not run inline on every scan
///
/// Requesting a Play Integrity token is a real network+native call to
/// Google (and consumes that app's own Play Integrity quota), and this flow
/// adds two more backend round-trips on top of that. Running it on every
/// `TrustAnchorCollector.collect()` — which `SecurityCenterController`
/// invokes on every scan cycle — would multiply Google API traffic by the
/// scan frequency for no benefit: an attestation verdict does not change
/// between scans a few seconds apart. [run] is wired to fire once, at
/// session start (`RaspSdk.initialize()`, only once activation actually
/// grants features — never for a PENDING/unlicensed device), not on every
/// heartbeat: the heartbeat interval can be configured as low as one minute
/// (`RemoteConfigManager.heartbeatIntervalMinutes`), and re-running a real
/// Google Play Integrity request that often would burn a production app's
/// daily token quota for no benefit — device trust state does not change
/// between heartbeats a minute apart either. [lastResult] is what
/// `TrustAnchorCollector` actually reads on every scan.
///
/// ## Token handling
///
/// The raw token this class receives from [PlayIntegrityAttestor.requestToken]
/// is placed in exactly one outbound request body (the POST to
/// `/attestation/verify`) and never logged, never cached on this object
/// beyond that call's stack, and never written to any storage.
class AttestationOrchestrator {
  AttestationOrchestrator({Dio? dio, PlayIntegrityAttestor? attestor})
      : _dio = dio ??
            Dio(
              BaseOptions(
                baseUrl: SdkConfig.sdkApiBaseUrl,
                connectTimeout: SdkConfig.networkTimeout,
                receiveTimeout: SdkConfig.networkTimeout,
                sendTimeout: SdkConfig.networkTimeout,
                headers: {'Content-Type': 'application/json'},
                // Non-2xx bodies are interpreted here, matching
                // ActivationManager's convention — not thrown as exceptions.
                validateStatus: (_) => true,
              ),
            ),
        _attestor = attestor ?? PlayIntegrityAttestor();

  final Dio _dio;
  final PlayIntegrityAttestor _attestor;
  static const _replayGuard = AttestationReplayGuard();

  /// The most recent completed attestation, or `null` before [run] has ever
  /// completed in this process. `TrustAnchorCollector.collect()` reads this
  /// directly; it does not trigger a run itself, for the reason in the class
  /// doc comment above.
  static AttestationResult? lastResult;

  /// Nonces this process has already presented for this attestation flow's
  /// own defensive (non-authoritative) replay check — mirrors what
  /// [AttestationReplayGuard] needs. The backend's
  /// `attestation_challenges.consumed_at` column is the actual authority;
  /// this is only the local mirror `AttestationReplayGuard`'s doc comment
  /// describes.
  static final Set<String> _consumedNonces = <String>{};

  /// Runs one full attestation cycle and updates [lastResult]. Never throws:
  /// any failure at any stage resolves to [AttestationStatus.unavailable] or
  /// [AttestationStatus.error], exactly like every other trust anchor in
  /// this SDK — never fabricated as valid.
  Future<AttestationResult> run() async {
    if (defaultTargetPlatform != TargetPlatform.android) {
      return _finish(AttestationResult.unavailable(
        platform: AttestationPlatform.android,
        reason: 'attestation is only implemented for Android in this SDK',
      ));
    }

    try {
      final available = await _attestor.isAvailable();
      if (!available) {
        return _finish(AttestationResult.unavailable(
          platform: AttestationPlatform.android,
          reason: 'Play Store not present on this device',
        ));
      }

      final deviceId = await DeviceIdentity.get();
      final bundleId = await ActivationManager.bundleId();

      final challenge =
          await _requestChallenge(deviceId: deviceId, bundleId: bundleId);
      if (challenge == null) {
        return _finish(AttestationResult.unavailable(
          platform: AttestationPlatform.android,
          reason: 'could not obtain an attestation challenge from the backend',
        ));
      }

      final token = await _attestor.requestToken(challenge);
      if (token == null) {
        return _finish(AttestationResult(
          platform: AttestationPlatform.android,
          provider: AttestationProvider.playIntegrity,
          status: AttestationStatus.unavailable,
          nonce: challenge.nonce,
          error: _attestor.lastErrorCode ?? 'native token request failed',
        ));
      }

      final verified = await _verify(
        deviceId: deviceId,
        nonce: challenge.nonce,
        token: token,
      );
      if (verified == null) {
        return _finish(AttestationResult(
          platform: AttestationPlatform.android,
          provider: AttestationProvider.playIntegrity,
          status: AttestationStatus.error,
          nonce: challenge.nonce,
          error: 'attestation verification request failed',
        ));
      }

      // Defense-in-depth: this device's own view of binding/replay/freshness.
      // Can only downgrade a claimed VALID; the backend's verdict is what
      // actually matters (see AttestationReplayGuard's doc comment).
      final guarded = _replayGuard.validate(
        verified,
        challenge: challenge,
        expectedBundleId: bundleId,
        expectedDeviceId: deviceId,
        consumedNonces: _consumedNonces,
      );
      _consumedNonces.add(challenge.nonce);

      return _finish(guarded);
    } catch (e) {
      return _finish(AttestationResult(
        platform: AttestationPlatform.android,
        provider: AttestationProvider.playIntegrity,
        status: AttestationStatus.error,
        error: 'attestation flow threw: ${e.runtimeType}',
      ));
    }
  }

  AttestationResult _finish(AttestationResult result) {
    lastResult = result;
    // Mirrors ActivationManager's [RASP-TRACE] convention. Deliberately
    // reports only the normalized outcome — status/provider/error/nonce —
    // never the raw token, which never reaches this method in the first
    // place (it lives only inside `_verify`'s request body).
    debugPrint(
      '[RASP-TRACE] ATTESTATION result status=${result.status.wireName} '
      'provider=${result.provider.name} nonce=${result.nonce} '
      'error=${result.error}',
    );
    return result;
  }

  Future<AttestationChallenge?> _requestChallenge({
    required String deviceId,
    required String bundleId,
  }) async {
    try {
      final res = await _dio.post<dynamic>('/attestation/challenge', data: {
        'license_key_hash': ActivationManager.licenseKeyHash,
        'bundle_id': bundleId,
        'device_id': deviceId,
        'platform': 'ANDROID',
      });
      if (res.statusCode != 200 || res.data is! Map) return null;
      final body = (res.data as Map).cast<String, dynamic>();
      final nonce = body['nonce'] as String?;
      final expiresAt = body['expires_at'] as String?;
      if (nonce == null || expiresAt == null) return null;
      return AttestationChallenge(
        nonce: nonce,
        bundleId: bundleId,
        deviceId: deviceId,
        issuedAt: DateTime.now().toUtc(),
        expiresAt: DateTime.parse(expiresAt).toUtc(),
      );
    } on DioException {
      return null;
    } catch (_) {
      return null;
    }
  }

  Future<AttestationResult?> _verify({
    required String deviceId,
    required String nonce,
    required String token,
  }) async {
    try {
      final res = await _dio.post<dynamic>('/attestation/verify', data: {
        'license_key_hash': ActivationManager.licenseKeyHash,
        'device_id': deviceId,
        'nonce': nonce,
        'platform': 'ANDROID',
        'provider': 'playIntegrity',
        'token': token,
      });
      if (res.statusCode != 200 || res.data is! Map) return null;
      return _resultFromWire((res.data as Map).cast<String, dynamic>());
    } on DioException {
      return null;
    } catch (_) {
      return null;
    }
  }

  AttestationResult _resultFromWire(Map<String, dynamic> body) {
    final statusName = (body['status'] as String? ?? 'ERROR').toLowerCase();
    final statusValue = AttestationStatus.values.firstWhere(
      (s) => s.name == statusName,
      orElse: () => AttestationStatus.error,
    );
    final timestampStr = body['timestamp'] as String?;
    return AttestationResult(
      platform: AttestationPlatform.android,
      provider: AttestationProvider.playIntegrity,
      status: statusValue,
      appIntegrity: body['app_integrity'] as bool?,
      deviceIntegrity: body['device_integrity'] as bool?,
      signingIdentity: body['signing_identity'] as String?,
      packageIdentity: body['package_identity'] as String?,
      nonce: body['nonce'] as String?,
      timestamp: timestampStr == null ? null : DateTime.tryParse(timestampStr),
      error: body['detail'] as String?,
    );
  }
}
