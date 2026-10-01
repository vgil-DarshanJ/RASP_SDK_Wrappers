import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'package:rasp_shield/sdk/sdk_config.dart';

/// Whether a production certificate pin is configured for this build.
///
/// **No fingerprint is ever fabricated here.** The pin is supplied entirely
/// at build time by whoever owns the production backend's certificate —
/// see `docs/PRODUCTION_CERTIFICATE_PINNING.md`.
enum CertificatePinStatus {
  /// A well-formed SHA-256 fingerprint is configured.
  configured,

  /// No `RASP_BACKEND_CERT_PIN_SHA256` was supplied at build time.
  missing,

  /// A value was supplied but is not a 64-character hex SHA-256 digest —
  /// treated as absent for pinning purposes, never as "close enough".
  invalidConfiguration,
}

/// Outcome of actually attempting to pin-check a live connection.
enum CertificatePinCheckResult {
  /// The presented certificate's SHA-256 matches the configured pin.
  match,

  /// It does not — a real MITM signal, or a legitimate but unplanned
  /// certificate rotation (both must be treated the same at this layer;
  /// only an operator, not the SDK, can tell them apart).
  mismatch,

  /// No pin is configured, or the connection attempt itself failed before a
  /// certificate could be inspected (offline, DNS failure, timeout) — never
  /// conflated with [match].
  notAttempted,
}

/// Build-time production certificate pin configuration.
///
/// ```
/// flutter build apk --release \
///   --dart-define=RASP_BACKEND_CERT_PIN_SHA256=<hex SHA-256 of the DER-encoded cert>
/// ```
///
/// Get the value with, e.g.:
/// `openssl s_client -connect api.yourbank.com:443 </dev/null 2>/dev/null | openssl x509 -outform der | sha256sum`
class CertificatePinConfig {
  CertificatePinConfig._();

  static const String _raw = String.fromEnvironment('RASP_BACKEND_CERT_PIN_SHA256');

  static final RegExp _hex64 = RegExp(r'^[0-9a-f]{64}$');

  /// Pure decision logic — independent of the real (compile-time-frozen)
  /// [String.fromEnvironment] value, so a test can exercise every branch.
  /// [status] is the version every real caller should use.
  @visibleForTesting
  static CertificatePinStatus evaluatePinStatus(String rawValue) {
    if (rawValue.isEmpty) return CertificatePinStatus.missing;
    final normalized = rawValue.replaceAll(':', '').replaceAll(' ', '').toLowerCase();
    return _hex64.hasMatch(normalized)
        ? CertificatePinStatus.configured
        : CertificatePinStatus.invalidConfiguration;
  }

  static String get _normalized =>
      _raw.replaceAll(':', '').replaceAll(' ', '').toLowerCase();

  static CertificatePinStatus get status => evaluatePinStatus(_raw);

  /// The normalized 64-hex-char pin, or `null` unless [status] is
  /// [CertificatePinStatus.configured].
  static String? get pinnedSha256Hex =>
      status == CertificatePinStatus.configured ? _normalized : null;

  /// Pure decision logic for the production pinning guard — see
  /// [SdkConfig.evaluateProductionLicenseGuard], the same pattern.
  @visibleForTesting
  static ProductionPinningGuardResult evaluateProductionPinningGuard({
    required bool isDebug,
    required CertificatePinStatus pinStatus,
    required String environment,
  }) {
    if (isDebug) return ProductionPinningGuardResult.debugExempt;
    switch (pinStatus) {
      case CertificatePinStatus.configured:
        return ProductionPinningGuardResult.ok;
      case CertificatePinStatus.invalidConfiguration:
        return ProductionPinningGuardResult.invalidConfigurationInRelease;
      case CertificatePinStatus.missing:
        return environment.toLowerCase() == 'staging'
            ? ProductionPinningGuardResult.missingInStaging
            : ProductionPinningGuardResult.missingInRelease;
    }
  }

  /// Non-throwing — mirrors `SdkConfig.checkProductionLicenseGuard()`'s
  /// shape so both guards read the same way at a call site. Applies this
  /// build's real compile-time values to [evaluateProductionPinningGuard].
  static ProductionPinningGuardResult checkProductionPinningGuard() =>
      evaluateProductionPinningGuard(
        isDebug: kDebugMode,
        pinStatus: status,
        environment: SdkConfig.buildEnvironment,
      );
}

/// Outcome of [CertificatePinConfig.checkProductionPinningGuard].
enum ProductionPinningGuardResult {
  /// A valid pin is configured, or this is a debug/staging build where its
  /// absence is expected.
  ok,

  /// `kDebugMode` — the guard never applies to a debug build.
  debugExempt,

  /// No pin, but `RASP_BUILD_ENVIRONMENT=staging` explicitly allows it.
  missingInStaging,

  /// No pin in what this build declares (or defaults to) as `production`.
  missingInRelease,

  /// A pin value was supplied but is not a well-formed SHA-256 hex digest —
  /// always a hard failure, staging included, since this is a build
  /// mistake rather than an intentional absence.
  invalidConfigurationInRelease,
}

class SslPinningService {
  static const _securityChannel = MethodChannel(
    'com.shieldsdk.security/security',
  );

  /// Detects if a MITM attack is likely via native proxy detection or a
  /// certificate-pin mismatch against the SDK's own configured backend.
  ///
  /// Pin checking runs only when [CertificatePinConfig.status] is
  /// [CertificatePinStatus.configured] — with no pin configured, this
  /// method still runs the native proxy check but reports no result for
  /// pinning itself (see [checkCertificatePin] to distinguish
  /// [CertificatePinCheckResult.notAttempted] from an actual
  /// [CertificatePinCheckResult.mismatch] where that distinction matters).
  static Future<bool> isMitmDetected() async {
    final bool nativeProxyDetected = await _checkNativeProxy();
    if (nativeProxyDetected) return true;

    final pinResult = await checkCertificatePin();
    return pinResult == CertificatePinCheckResult.mismatch;
  }

  static Future<bool> _checkNativeProxy() async {
    try {
      return await _securityChannel.invokeMethod<bool>('isMitmDetected') ??
          false;
    } catch (e) {
      return false;
    }
  }

  /// Checks the live certificate presented by the SDK's configured backend
  /// host against [CertificatePinConfig.pinnedSha256Hex].
  ///
  /// Uses `SecurityContext(withTrustedRoots: false)` so
  /// `badCertificateCallback` fires for **every** certificate, not only
  /// ones that already fail the platform's normal trust validation — a
  /// certificate can be validly issued by a trusted CA and still not be
  /// the pinned one (a compromised or coerced CA, a misconfigured proxy
  /// with a real enterprise root installed). Pinning that only inspects
  /// already-invalid certificates would miss exactly that case.
  static Future<CertificatePinCheckResult> checkCertificatePin({
    String? host,
    int port = 443,
    Duration timeout = const Duration(seconds: 5),
  }) async {
    final pin = CertificatePinConfig.pinnedSha256Hex;
    if (pin == null) return CertificatePinCheckResult.notAttempted;

    final targetHost = host ?? _backendHost();
    if (targetHost == null) return CertificatePinCheckResult.notAttempted;

    final client = HttpClient(context: SecurityContext(withTrustedRoots: false));
    X509Certificate? presented;
    client.badCertificateCallback = (cert, certHost, certPort) {
      presented = cert;
      return false; // Never trust at this layer; the pin comparison decides.
    };
    try {
      final request = await client
          .getUrl(Uri(scheme: 'https', host: targetHost, port: port))
          .timeout(timeout);
      await request.close().timeout(timeout);
    } catch (_) {
      // Connection/handshake failure before (or instead of) a certificate
      // being presented — offline, DNS failure, timeout. Not a mismatch.
    } finally {
      client.close(force: true);
    }

    final cert = presented;
    if (cert == null) return CertificatePinCheckResult.notAttempted;
    final actual = sha256.convert(cert.der).toString();
    return actual == pin
        ? CertificatePinCheckResult.match
        : CertificatePinCheckResult.mismatch;
  }

  static String? _backendHost() {
    if (!SdkConfig.isConfigured) return null;
    try {
      return Uri.parse(SdkConfig.sdkApiBaseUrl).host;
    } catch (_) {
      return null;
    }
  }
}
