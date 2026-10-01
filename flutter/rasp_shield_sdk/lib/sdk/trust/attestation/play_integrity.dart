import 'package:flutter/services.dart';

import 'attestation_challenge.dart';
import 'attestation_result.dart';

/// Android's Google Play Integrity API boundary.
///
/// ## Real native implementation
///
/// [PlayIntegrityAttestor.requestToken] calls `requestPlayIntegrityToken` on
/// `com.shieldsdk.security/security` — the channel `MainActivity.kt` already
/// registers and every other on-device detector in this SDK already uses.
/// The native side (`MainActivity.requestPlayIntegrityToken`) calls the real
/// `com.google.android.play:integrity` client library
/// (`IntegrityManager.requestIntegrityToken`) and returns Google's genuine
/// token, or an explicit `PlatformException` error code (never a silent
/// `null`-only failure) — see `docs/PLAY_INTEGRITY_NATIVE_AUDIT.md`.
///
/// This class deliberately does **not** use the separate
/// `com.shieldsdk.rasp/native_bridge` scaffolding
/// (`RaspNativeBridgePlugin`): that channel has no `FlutterPlugin`
/// registration and is not part of the `:app` Gradle build graph, so it is
/// inert. Reusing the proven, working channel avoids standing up a second,
/// parallel native boundary for no architectural benefit.
///
/// A device producing a real Play Integrity token still requires Google Play
/// Services and a package registered in the Google Play Console; decoding
/// and verifying that token requires a Google Cloud service account on the
/// **backend** — neither of the latter two exist in this development
/// environment. **PRODUCTION/PLAY-CONSOLE CREDENTIALS REQUIRED** for the
/// backend half of this to produce a genuinely-verified result; see
/// `docs/PLAY_INTEGRITY_NATIVE_AUDIT.md` and `docs/ATTESTATION_ARCHITECTURE.md` §3.
class PlayIntegrityAttestor {
  PlayIntegrityAttestor();

  static const MethodChannel _channel =
      MethodChannel('com.shieldsdk.security/security');

  /// Heuristic-only "does Play Integrity look reachable" probe (Play Store
  /// presence). Not authoritative — see [requestToken]'s own outcome for the
  /// real signal — but lets a caller skip an attestation attempt that is
  /// obviously hopeless (no Play Store on this device at all).
  Future<bool> isAvailable() async {
    try {
      return await _channel.invokeMethod<bool>('playIntegrityIsAvailable') ??
          false;
    } on MissingPluginException {
      return false;
    } catch (_) {
      return false;
    }
  }

  /// Requests a raw, opaque, base64 Play Integrity token bound to
  /// [challenge]'s nonce — the SERVER-issued challenge nonce, never a
  /// locally-generated one. Never throws: a missing native implementation,
  /// an unavailable Play Services install, or any other failure is reported
  /// as `null`, which the caller treats as [AttestationStatus.unavailable].
  /// The failure reason (Google's own error code, e.g. `NETWORK_ERROR`,
  /// `PLAY_STORE_NOT_FOUND`) is available via [lastErrorCode] for
  /// diagnostics — never the raw token, which this method never logs.
  Future<String?> requestToken(AttestationChallenge challenge) async {
    _lastErrorCode = null;
    try {
      final token = await _channel.invokeMethod<String>(
        'requestPlayIntegrityToken',
        {'nonce': challenge.nonce},
      );
      return (token == null || token.isEmpty) ? null : token;
    } on MissingPluginException {
      _lastErrorCode = 'MISSING_PLUGIN';
      return null;
    } on PlatformException catch (e) {
      _lastErrorCode = e.code;
      return null;
    } catch (_) {
      _lastErrorCode = 'UNKNOWN';
      return null;
    }
  }

  String? _lastErrorCode;

  /// The native error code from the most recent [requestToken] failure, or
  /// `null` after a success or before any call. Diagnostic only — never the
  /// token itself, and never persisted by this class.
  String? get lastErrorCode => _lastErrorCode;
}

/// Normalizes a **decoded** Play Integrity API response into an
/// [AttestationResult].
///
/// ## Why "decoded," and what that means for how far this parser reaches
///
/// A Play Integrity token is opaque and Google-encrypted; only Google's
/// `playintegrity.googleapis.com` `decodeIntegrityToken` API can decode and
/// verify it — there is no offline verification path (`ATTESTATION_ARCHITECTURE.md`
/// §3). This parser starts from the **decoded JSON shape Google's API
/// documents and returns** (`requestDetails`/`appIntegrity`/`deviceIntegrity`/
/// `accountDetails`), which is real, stable, publicly documented Google
/// schema — not invented here — and turns it into this SDK's normalized
/// model. It never claims to have performed the decryption/verification step
/// itself; that step is the backend's job (`attestation_router.py`), calling
/// a real Google credential this environment does not have.
///
/// Pure and deterministic: no I/O, so it is exhaustively testable against
/// fixtures shaped like Google's documented response format.
class PlayIntegrityVerdictParser {
  const PlayIntegrityVerdictParser();

  /// [decoded] is the JSON body Google's `decodeIntegrityToken` API returns.
  AttestationResult parse(Map<String, dynamic> decoded) {
    try {
      final requestDetails = decoded['requestDetails'] as Map<String, dynamic>?;
      final appIntegrityMap = decoded['appIntegrity'] as Map<String, dynamic>?;
      final deviceIntegrityMap = decoded['deviceIntegrity'] as Map<String, dynamic>?;

      if (requestDetails == null) {
        return const AttestationResult(
          platform: AttestationPlatform.android,
          provider: AttestationProvider.playIntegrity,
          status: AttestationStatus.unknown,
          error: 'response has no requestDetails',
        );
      }

      final nonce = requestDetails['nonce'] as String?;
      final packageName = requestDetails['requestPackageName'] as String?;
      final timestampMillis = requestDetails['timestampMillis'];
      final timestamp = timestampMillis is String
          ? DateTime.fromMillisecondsSinceEpoch(
              int.parse(timestampMillis), isUtc: true)
          : null;

      // Google's real verdict vocabulary — documented at
      // developer.android.com/google/play/integrity/verdicts. Reproduced
      // here as literal strings (not an invented enum) because that is
      // exactly what a real decoded response contains.
      final appRecognitionVerdict =
          appIntegrityMap?['appRecognitionVerdict'] as String?;
      final deviceRecognitionVerdicts =
          (deviceIntegrityMap?['deviceRecognitionVerdict'] as List?)
                  ?.cast<String>() ??
              const <String>[];

      final evidence = <AttestationEvidence>[
        if (appRecognitionVerdict != null)
          AttestationEvidence('app_recognition_verdict', appRecognitionVerdict),
        for (final verdict in deviceRecognitionVerdicts)
          AttestationEvidence('device_recognition_verdict', verdict),
      ];

      final appIntegrity =
          appRecognitionVerdict == null ? null : appRecognitionVerdict == 'PLAY_RECOGNIZED';
      // Google's own guidance: MEETS_DEVICE_INTEGRITY (or the stronger
      // MEETS_STRONG_INTEGRITY) is the bar for "this is a genuine,
      // unmodified device" — MEETS_BASIC_INTEGRITY alone still permits a
      // rooted/emulated device. Both are treated as passing here because
      // this parser reports what Google reported, not a policy decision;
      // whether MEETS_BASIC_INTEGRITY alone is "good enough" is a policy
      // question for `ProtectionPolicy`, not this normalization layer.
      final deviceIntegrity = deviceRecognitionVerdicts.isEmpty
          ? false
          : deviceRecognitionVerdicts.any((v) =>
              v == 'MEETS_DEVICE_INTEGRITY' ||
              v == 'MEETS_STRONG_INTEGRITY' ||
              v == 'MEETS_BASIC_INTEGRITY');

      final status = (appIntegrity == true && deviceIntegrity)
          ? AttestationStatus.valid
          : AttestationStatus.invalid;

      final certDigests =
          (appIntegrityMap?['certificateSha256Digest'] as List?)?.cast<String>();

      return AttestationResult(
        platform: AttestationPlatform.android,
        provider: AttestationProvider.playIntegrity,
        status: status,
        appIntegrity: appIntegrity,
        deviceIntegrity: deviceRecognitionVerdicts.isEmpty ? null : deviceIntegrity,
        signingIdentity: (certDigests != null && certDigests.isNotEmpty)
            ? certDigests.first
            : null,
        packageIdentity: packageName,
        nonce: nonce,
        timestamp: timestamp,
        evidence: evidence,
      );
    } catch (e) {
      return AttestationResult(
        platform: AttestationPlatform.android,
        provider: AttestationProvider.playIntegrity,
        status: AttestationStatus.error,
        error: 'malformed Play Integrity response',
      );
    }
  }
}
