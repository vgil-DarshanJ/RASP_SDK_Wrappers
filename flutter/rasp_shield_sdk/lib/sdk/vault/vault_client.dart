import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../activation_manager.dart';
import '../device_identity.dart';
import '../license_manager.dart';
import '../sdk_config.dart';
import '../security/request_signer.dart';
import '../tls/tls_pinning_dio.dart';
import 'secure_vault_store.dart';
import 'vault_result.dart';

/// `RaspShield.vault` — the public Secure Vault client.
///
/// Authenticated identically to every other post-activation SDK call
/// (`RequestSigner.sign` for the HMAC headers, plus
/// `ActivationManager.deviceProofHeadersFor` for the device-key signature
/// when this device has one) — no new signing mechanism, mirroring
/// `SecurityEventReporter`'s own transport shape exactly.
///
/// ## What "get" actually does
///
/// 1. If a still-fresh cached value exists (within the TTL the backend
///    itself set on the last successful fetch), return it — no network
///    call. This is what keeps a legitimate, healthy app from re-fetching
///    the same secret every scan cycle.
/// 2. Otherwise call the backend. A definitive answer (AVAILABLE, DENIED,
///    EXPIRED, REVOKED, NOT_CONFIGURED) is cached (if AVAILABLE) and
///    returned as-is.
/// 3. Only on a genuine transport failure (offline, timeout, 5xx) does this
///    ever consider the cache as a **fallback** — and only when the
///    secret's own policy explicitly allowed offline use on the last
///    successful fetch (`CachedVaultEntry.isUsableOffline`). See
///    `docs/SECURE_VAULT.md`'s "Offline Behavior" section — there is no
///    universal offline rule.
class RaspShieldVault {
  RaspShieldVault._();

  static final RaspShieldVault instance = RaspShieldVault._();

  final Dio _dio = _buildDio();

  static Dio _buildDio() {
    final dio = Dio(
      BaseOptions(
        baseUrl: SdkConfig.sdkApiBaseUrl,
        connectTimeout: SdkConfig.networkTimeout,
        receiveTimeout: SdkConfig.networkTimeout,
        sendTimeout: SdkConfig.networkTimeout,
        headers: {'Content-Type': 'application/json'},
        validateStatus: (_) => true,
      ),
    );
    configureTlsPinning(dio);
    return dio;
  }

  final SecureVaultStore _store = const SecureVaultStore();

  /// Retrieves one vault secret by name.
  ///
  /// Never returns `null` — every path returns a [VaultResult] with a
  /// [VaultResult.reason], including [VaultSecretState.unavailable] when
  /// the SDK itself is not yet licensed to write (no activation), matching
  /// `SecurityEventReporter.flush`'s own "PENDING/BLOCKED/REVOKED may not
  /// write" gate.
  Future<VaultResult> get(
    String secretName, {
    String environment = 'production',
  }) async {
    final now = DateTime.now().toUtc();

    final cached = await _store.load(secretName: secretName, environment: environment);
    if (cached != null && cached.isFresh(now)) {
      return VaultResult.available(
        secretName: secretName, value: cached.value, version: cached.version,
        expiresAt: cached.expiresAt,
      );
    }

    if (!LicenseManager.status.value.grantsFeatures) {
      return _offlineFallbackOr(
        secretName, cached, now, VaultResult.unavailable(secretName, reason: 'NOT_LICENSED'),
      );
    }
    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) {
      return _offlineFallbackOr(
        secretName, cached, now, VaultResult.unavailable(secretName, reason: 'NOT_ACTIVATED'),
      );
    }

    try {
      final deviceId = await DeviceIdentity.get();
      final body = {
        'license_key_hash': ActivationManager.licenseKeyHash,
        'device_id': deviceId,
        'activation_token': token,
        'secret_name': secretName,
        'environment': environment,
      };
      final bodyJson = jsonEncode(body);
      final bodyBytes = utf8.encode(bodyJson);
      final signatureHeaders = RequestSigner.sign(
        activationToken: token,
        method: 'POST',
        path: '/api/v1/sdk/vault/provision',
        bodyBytes: bodyBytes,
      );
      final proofHeaders = await ActivationManager.deviceProofHeadersFor(
        method: 'POST',
        path: '/api/v1/sdk/vault/provision',
        bodyBytes: bodyBytes,
        signatureHeaders: signatureHeaders,
      );

      final response = await _dio.post<dynamic>(
        '/vault/provision',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: {...signatureHeaders, ...proofHeaders},
        ),
      );

      if (response.statusCode == 200 && response.data is Map) {
        final wire = (response.data as Map).map((k, v) => MapEntry(k.toString(), v));
        final result = VaultResult.fromWire(wire);
        debugPrint('[RASP-TRACE] VAULT-PROVISION status=${result.state.name} '
            'secret=$secretName');
        if (result.state == VaultSecretState.available &&
            result.value != null && result.version != null && result.expiresAt != null) {
          await _store.save(
            secretName: secretName, environment: environment,
            value: result.value!, version: result.version!,
            expiresAt: result.expiresAt!,
            offlineAllowed: wire['offline_allowed'] as bool? ?? false,
            offlineMaxAgeSeconds: wire['offline_max_age_seconds'] as int? ?? 0,
          );
        } else if (result.state == VaultSecretState.revoked ||
            result.state == VaultSecretState.expired) {
          // A revoked/expired verdict from the backend must not leave a
          // stale, still-"usable" copy sitting in the cache.
          await _store.clear(secretName: secretName, environment: environment);
        }
        return result;
      }

      debugPrint('[RASP-TRACE] VAULT-PROVISION FAIL status=${response.statusCode}');
      return _offlineFallbackOr(
        secretName, cached, now,
        VaultResult.unavailable(secretName, reason: 'HTTP_${response.statusCode}'),
      );
    } catch (e) {
      debugPrint('[RASP-TRACE] VAULT-PROVISION FAIL error=${e.runtimeType}');
      return _offlineFallbackOr(
        secretName, cached, now, VaultResult.unavailable(secretName, reason: 'TRANSPORT_ERROR'),
      );
    }
  }

  VaultResult _offlineFallbackOr(
    String secretName, CachedVaultEntry? cached, DateTime now, VaultResult fallback,
  ) {
    if (cached != null && cached.isUsableOffline(now)) {
      return VaultResult.available(
        secretName: secretName, value: cached.value, version: cached.version,
        expiresAt: cached.expiresAt, servedFromOfflineCache: true,
      );
    }
    return fallback;
  }
}
