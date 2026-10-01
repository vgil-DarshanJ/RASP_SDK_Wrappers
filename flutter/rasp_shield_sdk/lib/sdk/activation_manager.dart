import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:package_info_plus/package_info_plus.dart';

import 'device/device.dart';
import 'device_identity.dart';
import 'location_manager.dart';
import 'tls/tls_pinning_dio.dart';
import 'log_reporter.dart';
import 'sdk_config.dart';
import 'security/request_signer.dart';

/// Raw result of an activation or heartbeat call.
class ActivationResult {
  /// Server-reported status: ACTIVE, GRACE, PENDING, REVOKED, EXPIRED,
  /// SUSPENDED, or one of the SDK-local codes below.
  final String status;
  final Map<String, dynamic> payload;
  final String message;

  /// Set when the call failed before the server could answer.
  final bool networkFailure;

  const ActivationResult({
    required this.status,
    this.payload = const {},
    this.message = '',
    this.networkFailure = false,
  });

  bool get isSuccess => status == 'ACTIVE' || status == 'GRACE';
}

/// Performs the challenge–response handshake that proves this build possesses
/// the license key, without ever transmitting the key itself.
///
/// 1. `POST /challenge` with the SHA-256 of the key → server returns a nonce.
/// 2. HMAC-SHA256 the nonce (bound to device, bundle, and SDK version) using
///    the key as the HMAC secret.
/// 3. `POST /activate` with that signature. The nonce is single-use and
///    short-lived, so a captured request cannot be replayed.
class ActivationManager {
  static final Dio _dio = _buildDio();

  static Dio _buildDio() {
    final dio = Dio(
      BaseOptions(
        baseUrl: SdkConfig.sdkApiBaseUrl,
        connectTimeout: SdkConfig.networkTimeout,
        receiveTimeout: SdkConfig.networkTimeout,
        sendTimeout: SdkConfig.networkTimeout,
        headers: {'Content-Type': 'application/json'},
        // We interpret non-2xx bodies ourselves rather than throwing.
        validateStatus: (_) => true,
      ),
    );
    // Dynamic TLS Certificate Pinning — the activation/heartbeat channel is
    // the SDK's own backend traffic, so this is the client whose pinning
    // failures feed `TlsPinningController.recordEnforcementFailure`'s
    // recovery-demotion path (see that method's doc for why only this
    // traffic is eligible for it).
    configureTlsPinning(dio);
    return dio;
  }

  /// Set when this device joined via email-verified enrollment instead of a
  /// packaged licence key (see EnrollmentManager). Such a build has no key to
  /// hash, so the hash is supplied by the enrollment response instead.
  static String? enrolledLicenseKeyHash;

  /// SHA-256 of the license key — the server's lookup index.
  ///
  /// An enrolled device has no licence key at all, so its hash comes from the
  /// enrollment response; hashing the (empty) SdkConfig.licenseKey there would
  /// produce a hash that matches no licence and fail every heartbeat.
  static String get licenseKeyHash =>
      enrolledLicenseKeyHash ??
      sha256.convert(utf8.encode(SdkConfig.licenseKey.trim())).toString();

  // ── Device binding (Cryptographic Per-Device License Binding) ──────────
  //
  // The licence HMAC below proves possession of the LICENCE. These members
  // carry the second, independent assertion: proof of possession of a
  // non-exportable key held by THIS DEVICE. Neither replaces the other —
  // see docs/LICENSE_DEVICE_BINDING.md §5.

  static const DeviceKeyManager _deviceKeys = DeviceKeyManager();

  /// The server's most recent verdict on this seat's device binding.
  ///
  /// `unbound` until a server response says otherwise, which is the correct
  /// default for every build and every seat that predates this milestone.
  static DeviceBindingLifecycle deviceBindingStatus =
      DeviceBindingLifecycle.unbound;

  /// Whether the server accepted the most recent device proof this install
  /// produced. `null` when none has been presented — the normal state
  /// offline, and for a client with no device key.
  static bool? lastProofAccepted;

  /// Reset the observed binding state. Test-only: production code learns
  /// this from the server and never needs to forget it.
  @visibleForTesting
  static void resetDeviceBindingForTesting() {
    deviceBindingStatus = DeviceBindingLifecycle.unbound;
    lastProofAccepted = null;
  }

  /// Absorb the `device_binding` block a server response may carry.
  ///
  /// Additive and defensive: a server that predates this milestone sends no
  /// such block, and the state is then left exactly as it was rather than
  /// being reset to a weaker value on every call.
  static void _absorbDeviceBinding(Map<String, dynamic> body) {
    final raw = body['device_binding'];
    if (raw is! Map) return;
    final status = raw['status'];
    if (status != null) {
      deviceBindingStatus = DeviceBindingLifecycleX.parse(status);
    }
    final accepted = raw['proof_accepted'];
    if (accepted is bool) lastProofAccepted = accepted;
  }

  /// This device's binding identity as the licence validator sees it.
  ///
  /// Loads read-only — it must never mint a key, or a cloned install would
  /// silently heal itself and the mismatch would be undetectable. Only
  /// [activate] creates one.
  static Future<LicenseBindingObservation> bindingObservation({
    String? tenantId,
  }) async {
    final key = await _deviceKeys.load();
    return LicenseBindingObservation(
      tenantId: tenantId,
      bundleId: await bundleId(),
      deviceId: await DeviceIdentity.get(),
      signingCertificate: await signingCertSha256(),
      deviceKey: key,
      keyBacking: DeviceKeyManager.lastBacking,
      keystoreAvailable: DeviceKeyManager.keystoreAvailable,
      lifecycle: deviceBindingStatus,
      proofAccepted: lastProofAccepted,
    );
  }

  /// The two device-binding headers for a signed request, or `{}` when this
  /// device holds no key.
  ///
  /// Reuses the *same* canonical string [RequestSigner] just signed, taken
  /// from the headers it returned rather than rebuilt, so the HMAC and the
  /// device proof can never describe different bytes.
  static Future<Map<String, String>> deviceProofHeadersFor({
    required String method,
    required String path,
    required List<int> bodyBytes,
    required Map<String, String> signatureHeaders,
  }) async {
    final key = await _deviceKeys.load();
    if (key == null || !key.isUsable) return const {};

    final timestamp = signatureHeaders['X-Rasp-Timestamp'];
    final nonce = signatureHeaders['X-Rasp-Nonce'];
    if (timestamp == null || nonce == null) return const {};

    final signature = await _deviceKeys.sign(DeviceProof.requestMessage(
      canonicalRequest: DeviceProof.canonicalRequestFor(
        method: method,
        path: path,
        timestamp: timestamp,
        nonce: nonce,
        bodyBytes: bodyBytes,
      ),
      keyId: key.keyId,
    ));
    return DeviceProof.headers(keyId: key.keyId, signature: signature);
  }

  /// HMAC-SHA256 over the canonical challenge string, keyed by the license key.
  ///
  /// Throws [CanonicalFieldError] when [nonce], [deviceId] or [bundleId]
  /// contains the canonical delimiter — mirrors
  /// `tokens.activation_signature`'s identical validation on the backend.
  static String signChallenge({
    required String nonce,
    required String deviceId,
    required String bundleId,
  }) {
    CanonicalField.assertSafe('nonce', nonce);
    CanonicalField.assertSafe('device_id', deviceId);
    CanonicalField.assertSafe('bundle_id', bundleId);
    CanonicalField.assertSafe('sdk_version', SdkConfig.sdkVersion);
    final message = '$nonce|$deviceId|$bundleId|${SdkConfig.sdkVersion}';
    final hmac = Hmac(sha256, utf8.encode(SdkConfig.licenseKey.trim()));
    return hmac.convert(utf8.encode(message)).toString();
  }

  static Future<String> bundleId() async {
    try {
      final info = await PackageInfo.fromPlatform();
      return info.packageName;
    } catch (_) {
      // Honest "could not determine" rather than a plausible-looking but
      // wrong identity — this SDK is distributed to customers who are never
      // the reference app itself (P0-1 native-plugin extraction: this
      // fallback used to be the reference app's own hardcoded package name).
      return '';
    }
  }

  /// Native channel used to read this build's own signing certificate.
  static const MethodChannel _securityChannel =
      MethodChannel('com.shieldsdk.security/security');

  /// SHA-256 of this build's signing certificate, uppercase bare hex.
  ///
  /// Sent on `/activate` so the backend can enforce the fingerprint the
  /// customer pinned for this app. The bundle id only states which app a caller
  /// *claims* to be — a repackaged build keeps the bundle id and can carry a
  /// license key lifted out of the original binary, so this is the field that
  /// makes bundle enforcement mean anything.
  ///
  /// Returns `''` when unavailable (non-mobile, or the platform call fails).
  /// The server treats an absent fingerprint against a pinned app as a failure,
  /// which is the intended fail-closed behaviour — never send a placeholder.
  static Future<String> signingCertSha256() async {
    try {
      final value =
          await _securityChannel.invokeMethod<String>('getSigningCertSha256');
      return value ?? '';
    } catch (_) {
      return '';
    }
  }

  static Future<Map<String, String>> _deviceDescriptors() async {
    if (kIsWeb || defaultTargetPlatform != TargetPlatform.android) {
      return {'device_model': 'unknown', 'os_version': 'unknown', 'manufacturer': ''};
    }
    try {
      final info = await DeviceInfoPlugin().androidInfo;
      return {
        'device_model': '${info.manufacturer} ${info.model}'.trim(),
        'os_version': 'Android ${info.version.release} (API ${info.version.sdkInt})',
        // Sent alongside the folded device_model above so dashboards can
        // render "Manufacturer" as its own field (Top Manufacturer stat,
        // Device Security Panel) without re-parsing device_model.
        'manufacturer': info.manufacturer,
      };
    } catch (_) {
      return {'device_model': 'unknown', 'os_version': 'unknown', 'manufacturer': ''};
    }
  }

  static Future<String> _appVersion() async {
    try {
      final info = await PackageInfo.fromPlatform();
      return info.version;
    } catch (_) {
      return '0.0.0';
    }
  }

  /// Interpret a licensing response body into a normalised result.
  static ActivationResult _interpret(Response<dynamic> res) {
    final data = res.data;
    final body = data is Map ? Map<String, dynamic>.from(data) : <String, dynamic>{};

    if (res.statusCode == 200 || res.statusCode == 202) {
      _absorbDeviceBinding(body);
      return ActivationResult(
        status: (body['status'] as String?) ?? 'ACTIVE',
        payload: body,
        message: (body['message'] as String?) ?? '',
      );
    }

    // FastAPI puts structured errors under `detail`.
    final detail = body['detail'];
    if (detail is Map) {
      // A rejected device proof is reported here, not in a 200 body, so the
      // binding state has to be absorbed from the failure path too —
      // otherwise the SDK would keep believing its last accepted proof.
      _absorbDeviceBinding(Map<String, dynamic>.from(detail));
      return ActivationResult(
        status: (detail['code'] as String?) ?? 'ERROR',
        message: (detail['message'] as String?) ?? 'Licensing request rejected',
      );
    }
    if (res.statusCode == 426) {
      return const ActivationResult(
        status: 'SDK_UPGRADE_REQUIRED',
        message: 'This app version is no longer supported. Please update.',
      );
    }
    return ActivationResult(
      status: 'ERROR',
      message: detail is String ? detail : 'Licensing request failed (${res.statusCode})',
    );
  }

  /// Run the full challenge → activate handshake.
  static Future<ActivationResult> activate() async {
    try {
      final deviceId = await DeviceIdentity.get();
      final bundle = await bundleId();
      final keyHash = licenseKeyHash;

      final challengeBody = {
        'license_key_hash': keyHash,
        'bundle_id': bundle,
        'device_id': deviceId,
      };
      final challengeSw = Stopwatch()..start();
      final challengeRes = await _dio.post<dynamic>('/challenge', data: challengeBody);
      challengeSw.stop();
      _trace('CHALLENGE', '${_dio.options.baseUrl}/challenge', challengeRes.statusCode,
          challengeBody, challengeRes.data, challengeSw.elapsedMilliseconds);
      if (challengeRes.statusCode != 200) return _interpret(challengeRes);

      final nonce = (challengeRes.data as Map)['nonce'] as String;
      final descriptors = await _deviceDescriptors();

      // Phase 4 — device binding. The ONE place a device key is created:
      // the key is the identity a seat is issued to, so it comes into being
      // at the moment the seat does. Every other caller loads read-only.
      //
      // The public key is submitted together with a signature over the
      // server's own single-use challenge nonce, so the server never has to
      // trust a client-asserted public key on its own word — an unproven
      // key would let anyone bind a seat to a keypair they do not hold and
      // then "prove" possession of it later.
      final deviceKey = await _deviceKeys.ensure();
      final deviceProof = deviceKey == null
          ? null
          : await _deviceKeys.sign(DeviceProof.activationMessage(
              nonce: nonce,
              deviceId: deviceId,
              bundleId: bundle,
              sdkVersion: SdkConfig.sdkVersion,
              keyId: deviceKey.keyId,
            ));

      final activateBody = {
        'license_key_hash': keyHash,
        'bundle_id': bundle,
        'device_id': deviceId,
        'sdk_version': SdkConfig.sdkVersion,
        'nonce': nonce,
        'signature': signChallenge(
          nonce: nonce,
          deviceId: deviceId,
          bundleId: bundle,
        ),
        'device_model': descriptors['device_model'],
        'os_version': descriptors['os_version'],
        'manufacturer': descriptors['manufacturer'],
        'app_version': await _appVersion(),
        'signing_cert_sha256': await signingCertSha256(),
        if (SdkConfig.buildId.isNotEmpty) 'build_id': SdkConfig.buildId,
        // Omitted entirely when this device has no keystore, so the server
        // sees a legacy/unbound client rather than a failed proof. Those are
        // different verdicts and must stay different.
        if (deviceKey != null && deviceProof != null) ...{
          ...deviceKey.toRegistrationJson(),
          'device_proof': deviceProof,
        },
      };
      final activateSw = Stopwatch()..start();
      final activateRes = await _dio.post<dynamic>('/activate', data: activateBody);
      activateSw.stop();
      _trace('ACTIVATE', '${_dio.options.baseUrl}/activate', activateRes.statusCode,
          activateBody, activateRes.data, activateSw.elapsedMilliseconds);
      return _interpret(activateRes);
    } on DioException catch (e) {
      _traceFail('ACTIVATE', '${_dio.options.baseUrl}/activate', e);
      return ActivationResult(
        status: 'NETWORK_ERROR',
        message: 'Cannot reach the licensing server: ${e.type.name}',
        networkFailure: true,
      );
    } catch (e) {
      return ActivationResult(
        status: 'ERROR',
        message: 'Activation failed: $e',
        networkFailure: true,
      );
    }
  }

  /// Re-validate the seat and pull fresh entitlements + remote config.
  /// Continuous Security Telemetry milestone: an optional, host-layer-set
  /// hook that folds a compact security-state snapshot into the outgoing
  /// heartbeat body — flattened top-level fields (`risk_score`,
  /// `risk_level`, `posture`, `protection_state`, `native_layer_state`,
  /// `reported_policy_version`, `last_scan_at`), the same shape
  /// `HeartbeatRequest` on the backend declares, and the same flattening
  /// convention the location block above already uses.
  ///
  /// `ActivationManager` is the HTTP layer beneath `RaspShield` — it has no
  /// access to `ProtectionResult`/`RiskAssessment` (those live above it) and
  /// must not import upward. This mirrors the exact pattern
  /// `LocationManager.provider` already uses for host-injected location: a
  /// nullable static function pointer, set once by whichever layer actually
  /// holds the data, read here without a compile-time dependency on it.
  /// `RaspShield` sets this to a closure over its own last scan result — see
  /// `RaspShield._buildHeartbeatSecurityState`.
  ///
  /// Deliberately small — a risk score, a posture word, a handful of state
  /// enums, never full evidence, never full location. `null` (the default,
  /// and what every build predating this milestone effectively has) sends a
  /// heartbeat identical to before.
  static Map<String, Object?> Function()? securityStateProvider;

  static Future<ActivationResult> heartbeat(String activationToken) async {
    try {
      final deviceId = await DeviceIdentity.get();
      // M_LOCATION_1: the device-context payload rides this existing heartbeat
      // rather than a second call. A null capture (permission declined, web,
      // nothing readable) leaves the body exactly as it was before.
      final location = await LocationManager.capture();
      // Refreshed on every heartbeat, not only at /activate, so an app that
      // gets updated (or moves to a new OS build) without a fresh activation
      // does not show stale details on the dashboards forever. The backend
      // ignores blank values rather than overwriting good data on file, so a
      // failed platform read here is harmless.
      final descriptors = await _deviceDescriptors();
      final securityState = securityStateProvider?.call();
      final body = {
        'license_key_hash': licenseKeyHash,
        'device_id': deviceId,
        'activation_token': activationToken,
        'sdk_version': SdkConfig.sdkVersion,
        'device_model': descriptors['device_model'],
        'os_version': descriptors['os_version'],
        'manufacturer': descriptors['manufacturer'],
        'app_version': await _appVersion(),
        if (SdkConfig.buildId.isNotEmpty) 'build_id': SdkConfig.buildId,
        if (location != null) ...location.toHeartbeatFields(),
        if (securityState != null) ...securityState,
      };
      final sw = Stopwatch()..start();
      // Sign the *exact* bytes sent, not a re-serialization of `body` — the
      // server hashes the raw bytes it receives (see request_integrity.py).
      final bodyJson = jsonEncode(body);
      final bodyBytes = utf8.encode(bodyJson);
      final signatureHeaders = RequestSigner.sign(
        activationToken: activationToken,
        method: 'POST',
        path: '/api/v1/sdk/heartbeat',
        bodyBytes: bodyBytes,
      );
      // Phase 6 — LICENSE BINDING alongside REQUEST AUTHENTICATION. Two
      // assertions over the same canonical request string: the HMAC above
      // says the request is fresh and from a token holder; this says it came
      // from the device the seat was issued to. A copied token satisfies the
      // first and cannot satisfy the second.
      final proofHeaders = await deviceProofHeadersFor(
        method: 'POST',
        path: '/api/v1/sdk/heartbeat',
        bodyBytes: bodyBytes,
        signatureHeaders: signatureHeaders,
      );
      final res = await _dio.post<dynamic>(
        '/heartbeat',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: {...signatureHeaders, ...proofHeaders},
        ),
      );
      sw.stop();
      _trace('HEARTBEAT', '${_dio.options.baseUrl}/heartbeat', res.statusCode,
          body, res.data, sw.elapsedMilliseconds);
      return _interpret(res);
    } on DioException catch (e) {
      _traceFail('HEARTBEAT', '${_dio.options.baseUrl}/heartbeat', e);
      return ActivationResult(
        status: 'NETWORK_ERROR',
        message: 'Heartbeat failed: ${e.type.name}',
        networkFailure: true,
      );
    } catch (e) {
      return ActivationResult(
        status: 'ERROR',
        message: 'Heartbeat failed: $e',
        networkFailure: true,
      );
    }
  }

  /// Secure AI Gateway — `POST /api/v1/sdk/ai/ask`.
  ///
  /// Authenticated identically to [heartbeat]: activation token + the same
  /// `X-Rasp-*` request signature, plus the device-binding proof when this
  /// device holds a key. No provider, model, or system-instruction field
  /// exists on this call — those are entirely a backend/tenant decision
  /// (see `app/ai/gateway.py`'s module doc). The message is the only
  /// client-authored content; everything else the response carries
  /// (risk score, risk level, policy version) is the backend's own,
  /// server-derived record, returned for display, never re-submitted by a
  /// later call as if the client had asserted it.
  static Future<ActivationResult> askAi({
    required String activationToken,
    required String message,
    required String useCase,
  }) async {
    try {
      final deviceId = await DeviceIdentity.get();
      final body = {
        'license_key_hash': licenseKeyHash,
        'device_id': deviceId,
        'activation_token': activationToken,
        'message': message,
        'use_case': useCase,
      };
      final bodyJson = jsonEncode(body);
      final bodyBytes = utf8.encode(bodyJson);
      final signatureHeaders = RequestSigner.sign(
        activationToken: activationToken,
        method: 'POST',
        path: '/api/v1/sdk/ai/ask',
        bodyBytes: bodyBytes,
      );
      final proofHeaders = await deviceProofHeadersFor(
        method: 'POST',
        path: '/api/v1/sdk/ai/ask',
        bodyBytes: bodyBytes,
        signatureHeaders: signatureHeaders,
      );
      final sw = Stopwatch()..start();
      final res = await _dio.post<dynamic>(
        '/ai/ask',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: {...signatureHeaders, ...proofHeaders},
        ),
      );
      sw.stop();
      _trace('AI-ASK', '${_dio.options.baseUrl}/ai/ask', res.statusCode,
          {...body, 'message': '(${message.length} chars, not logged)'},
          res.data, sw.elapsedMilliseconds);
      return _interpret(res);
    } on DioException catch (e) {
      _traceFail('AI-ASK', '${_dio.options.baseUrl}/ai/ask', e);
      return ActivationResult(
        status: 'NETWORK_ERROR',
        message: 'AI request failed: ${e.type.name}',
        networkFailure: true,
      );
    } catch (e) {
      return ActivationResult(status: 'ERROR', message: 'AI request failed: $e');
    }
  }

  // ── TEMPORARY debug trace — remove once the sideloaded-APK demo flow is
  // confirmed working live. Prints, for every licensing network call, exactly
  // what the task asks for: URL, method, headers (no secrets — the licence
  // key rides the request BODY, never a header), status, response body,
  // elapsed time, and any exception. Makes the handshake visible in the
  // `flutter run` console instead of failing silently.
  static String get _headers => _dio.options.headers.toString();

  static void _trace(String step, String url, int? status, Object requestBody,
      Object? responseBody, int elapsedMs) {
    final ok = status == 200 || status == 202;
    // Bodies carry license_key_hash/activation_token — never print them
    // outside a debug build. kDebugMode is a compile-time constant, so this
    // whole branch (and the string interpolations inside it) is tree-shaken
    // out of release/AOT builds, not merely skipped at runtime.
    if (kDebugMode) {
      debugPrint('[RASP-TRACE] $step ${ok ? "PASS" : "FAIL"} '
          'method=POST url=$url status=$status time=${elapsedMs}ms');
      debugPrint('[RASP-TRACE] $step headers=$_headers');
      debugPrint('[RASP-TRACE] $step request=$requestBody');
      debugPrint('[RASP-TRACE] $step response=$responseBody');
    }
    // Only failures are reported to the backend — a routine PASS here would
    // just duplicate what `last_seen_at`/`heartbeat_count` already show on
    // the dashboards, and would needlessly grow device_logs on every single
    // successful call.
    if (!ok) {
      DeviceLogReporter.instance.warning('RASP-TRACE', '$step failed', metadata: {
        'status': status,
        'elapsed_ms': elapsedMs,
      });
    }
  }

  static void _traceFail(String step, String url, DioException e) {
    if (kDebugMode) {
      debugPrint('[RASP-TRACE] $step FAIL method=POST url=$url '
          'headers=$_headers status=${e.response?.statusCode} '
          'type=${e.type.name} exception=${e.message} '
          'response=${e.response?.data}');
    }
    DeviceLogReporter.instance.error('RASP-TRACE', '$step network failure', metadata: {
      'type': e.type.name,
      'status': e.response?.statusCode,
    });
  }
}
