import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../core/detection_result.dart';
import '../core/detection_status.dart' show DetectionStatusX;
import '../device_identity.dart';
import '../detectors/rasp_native_channel.dart';

/// Ships [DetectionResult]s to the RASP Shield platform's ingestion API
/// (`POST <ingestion_url>`, see
/// `FROUNTEND_BACKEND_RASPOWN/BE/src/ingestion/routes.ts`) — the audit-trail
/// pipeline the platform's dashboard reads from.
///
/// ## Why this is pure Dart, not routed through the native MethodChannel
///
/// `android_core`'s `RaspEventShipper` (Kotlin) is the equivalent
/// mechanism for the pure-native Android SDK — but it is Android-only. A
/// Flutter app also targets iOS, and there is no native iOS
/// implementation of that class (nor should there be: shipping JSON over
/// HTTPS needs nothing platform-specific). Routing this through
/// `RaspNativeChannel` would silently do nothing on iOS the moment an iOS
/// native implementation lands, without this file changing at all — a
/// latent bug waiting to happen. `dio` already gives this SDK a working,
/// tested, cross-platform HTTP stack (see `SecurityEventReporter`'s
/// identical shape), so this class uses it directly instead.
///
/// ## Every request is HMAC-signed, not just key-authenticated
///
/// Earlier versions sent only `X-Api-Key` — a leaked key alone was then
/// sufficient to post events as this application, forever, until someone
/// noticed and revoked it. Every request now also carries `X-Timestamp`
/// and `X-Signature` (HMAC-SHA256 over `"<timestamp>.<raw body>"`, keyed
/// by the credential's `apiSecret`) — the exact same wire contract
/// `android_core`'s `RaspHmacSigner` and the backend's
/// `src/crypto/hmac.ts` implement, cross-verified to produce identical
/// signatures for identical inputs. The backend recomputes and compares
/// this, rejects stale timestamps, and rejects a replayed exact
/// signature even within the freshness window. A captured `X-Api-Key`
/// alone can no longer forge or replay a request. See
/// `docs/ANDROID_NATIVE_SDK_REFERENCE.md` for the full contract.
///
/// ## "Never disturb the app" — the actual contract
///
/// [shipDetectionResults] returns immediately — the HTTP call happens on
/// a fire-and-forget `Future` (deliberately `unawaited`), and every
/// failure (network, malformed credential, non-2xx response) is swallowed
/// after being reported to [onShipError] if one is set. There is no retry
/// queue in this version — a dropped batch on a flaky network is simply
/// gone, the same accepted trade-off `android_core`'s `RaspEventShipper`
/// documents: a banking app's runtime behavior must never depend on
/// telemetry delivery succeeding.
///
/// ## Usage
///
/// ```dart
/// final credentialJson = await File(credentialFilePath).readAsString();
/// await RaspSecurityEventShipper.configure(credentialJson);
///
/// // after a scan:
/// RaspSecurityEventShipper.shipDetectionResults(detections);
/// ```
class RaspSecurityEventShipper {
  RaspSecurityEventShipper._();

  /// SDK-wide version string, stamped onto every shipped event's
  /// `sdkVersion` field — matches `SdkConfig.sdkVersion`, kept as its own
  /// constant here so this file has no dependency on `SdkConfig`'s other,
  /// unrelated configuration surface.
  static const String sdkVersion = '2.0.0';

  static const int _maxBatchSize = 200; // matches the backend's batchSchema cap
  static const Duration _requestTimeout = Duration(seconds: 8);

  static _RaspEventCredential? _credential;
  static Dio? _dio;

  /// Where [configureAndPersist] stores the raw credential JSON — behind
  /// Android Keystore-backed encryption (EncryptedSharedPreferences under
  /// the hood), not a plain file or SharedPreferences value. This does not
  /// defeat a rooted device running Frida at runtime — nothing client-side
  /// can — but it does stop the credential from sitting in a plaintext,
  /// trivially-grepped location (a plain SharedPreferences XML file, an adb
  /// backup, a rooted file browser), and it is what makes [restore] able to
  /// survive an app restart at all, which [configure] alone never could.
  static const FlutterSecureStorage _secureStorage = FlutterSecureStorage();
  static const String _secureStorageKey = 'rasp_shield_ingestion_credential';

  /// Optional hook for a host app to observe shipping failures (network,
  /// non-2xx, malformed credential) — e.g. to log locally. Never allowed
  /// to throw back into the shipper; a throwing callback is caught and
  /// dropped, same rule as every logger hook elsewhere in this SDK.
  static void Function(String reason)? onShipError;

  /// Parses [credentialJson] (the JSON file downloaded from the RASP
  /// Shield platform's web UI after registering an application). On Android,
  /// also waits for the Kotlin lean-session engine to acknowledge the same
  /// credential. Returns `true` only when both applicable configurations
  /// succeeded; a native rejection is reported through [onShipError].
  static Future<bool> configure(String credentialJson) async {
    final parsed = _RaspEventCredential.tryParse(credentialJson);
    if (parsed == null) {
      _credential = null;
      return false;
    }

    // Android lean sessions ship in the Kotlin engine. Do not claim the
    // facade is configured until that engine has acknowledged the credential;
    // silently dropping this reply previously left the session unshipped.
    if (RaspNativeChannel.isSupportedPlatform) {
      final nativeConfigured = await RaspNativeChannel.boolCall(
        'configureLeanEventShipping',
        credentialJson,
      );
      if (nativeConfigured != true) {
        _credential = null;
        _reportError('Android native lean event shipping could not be configured');
        return false;
      }
    }

    _credential = parsed;
    return true;
  }

  static bool get isConfigured => _credential != null;

  /// Same as [configure], and also persists [credentialJson] to encrypted
  /// storage (see [_secureStorage]'s doc) so a later [restore] call — e.g.
  /// on the next app launch — can recover it without asking the user to
  /// paste it again. Returns `false` (and does not persist anything) on the
  /// same malformed-JSON condition [configure] already reports `false` for.
  static Future<bool> configureAndPersist(String credentialJson) async {
    final ok = await configure(credentialJson);
    if (ok) {
      try {
        await _secureStorage.write(key: _secureStorageKey, value: credentialJson);
      } catch (e) {
        _reportError('Configured, but could not persist credential securely: $e');
      }
    }
    return ok;
  }

  /// Loads a credential previously saved by [configureAndPersist], if any.
  /// Returns `true` only if one was found and parsed successfully — `false`
  /// covers both "nothing was ever persisted" and "what was persisted no
  /// longer parses" equally honestly; either way, [isConfigured] remains
  /// whatever it already was (never downgraded by a failed restore).
  static Future<bool> restore() async {
    try {
      final stored = await _secureStorage.read(key: _secureStorageKey);
      if (stored == null || stored.isEmpty) return false;
      return await configure(stored);
    } catch (e) {
      _reportError('Could not read persisted credential: $e');
      return false;
    }
  }

  /// Deletes any persisted credential (e.g. on user logout/sign-out) and
  /// clears the in-memory one. Idempotent, never throws.
  static Future<void> clearPersisted() async {
    _credential = null;
    unawaited(RaspNativeChannel.boolCall('clearLeanEventShipping'));
    try {
      await _secureStorage.delete(key: _secureStorageKey);
    } catch (e) {
      _reportError('Could not clear persisted credential: $e');
    }
  }

  /// Test-only reset.
  @visibleForTesting
  static void resetForTests() {
    _credential = null;
    _dio = null;
  }

  static Dio _buildDio() => Dio(
        BaseOptions(
          connectTimeout: _requestTimeout,
          sendTimeout: _requestTimeout,
          receiveTimeout: _requestTimeout,
          validateStatus: (_) => true, // handled explicitly below — never throws
        ),
      );

  /// Fire-and-forget: batches [results] (chunked at [_maxBatchSize]) and
  /// POSTs each chunk. Returns immediately — never blocks the caller,
  /// regardless of network state. A no-op (reported via [onShipError],
  /// not thrown) when [configure] was never called or failed to parse.
  static void shipDetectionResults(List<DetectionResult> results) {
    final credential = _credential;
    if (credential == null) {
      _reportError('Not configured — call RaspSecurityEventShipper.configure() first');
      return;
    }
    if (results.isEmpty) return;

    unawaited(_shipInternal(credential, results));
  }

  static Future<void> _shipInternal(
    _RaspEventCredential credential,
    List<DetectionResult> results,
  ) async {
    final deviceInfo = await _collectDeviceInfo();
    final dio = _dio ??= _buildDio();

    for (var i = 0; i < results.length; i += _maxBatchSize) {
      final chunk = results.sublist(
        i,
        i + _maxBatchSize > results.length ? results.length : i + _maxBatchSize,
      );
      try {
        // Built as a concrete JSON string FIRST, then signed, then sent
        // as that exact string — never a Map handed to dio for it to
        // encode itself. If the bytes signed and the bytes sent could
        // ever differ (whitespace, key order), the backend's
        // independently-recomputed signature would fail to match through
        // no fault of an attacker. See RaspHmacSigner's identical
        // discipline on the Kotlin side.
        final bodyJson = jsonEncode({
          'events': chunk.map((r) => _toIngestionEvent(r, deviceInfo)).toList(),
        });
        final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch.toString();
        final signature = computeSignatureForTesting(credential.apiSecret, timestamp, bodyJson);

        final response = await dio.post(
          credential.ingestionUrl,
          data: bodyJson,
          options: Options(headers: {
            'Content-Type': 'application/json',
            'X-Api-Key': credential.apiKey,
            'X-Timestamp': timestamp,
            'X-Signature': signature,
          }),
        );
        if (response.statusCode == null || response.statusCode! < 200 || response.statusCode! >= 300) {
          _reportError('Ingestion endpoint returned HTTP ${response.statusCode}');
        }
      } catch (e) {
        _reportError('Shipping failed: $e');
      }
    }
  }

  /// The exact wire contract `crypto/hmac.ts` (backend) and
  /// `RaspHmacSigner` (Kotlin) both implement — signing string is
  /// `<timestamp>` + `.` + the raw body bytes; signature is the lowercase
  /// hex HMAC-SHA256 digest of that, keyed by `apiSecret`. Cross-verified
  /// against both implementations to produce identical output for
  /// identical input — see this SDK's test suite.
  ///
  /// Public (not `_`-prefixed) despite the name, specifically so
  /// `test/sdk/events/security_event_shipper_test.dart` can assert the
  /// cross-language vector directly — `@visibleForTesting` marks the
  /// intent honestly rather than hiding a test seam behind a fake
  /// "internal" name.
  @visibleForTesting
  static String computeSignatureForTesting(String apiSecret, String timestamp, String body) {
    final signingBytes = utf8.encode('$timestamp.') + utf8.encode(body);
    final hmac = Hmac(sha256, utf8.encode(apiSecret));
    return hmac.convert(signingBytes).toString();
  }

  static Map<String, Object?> _toIngestionEvent(
    DetectionResult result,
    _DeviceInfo deviceInfo,
  ) {
    return {
      'detectorId': result.detectorId,
      // Backend enum is SECURE|DETECTED|UNAVAILABLE|UNKNOWN|ERROR
      // (uppercase); DetectionStatus.wireName is lowercase — uppercased
      // here at the wire boundary, not by changing wireName's own
      // contract elsewhere in the SDK.
      'status': result.status.wireName.toUpperCase(),
      'evidence': result.evidence.map((e) => e.toMap()).toList(),
      if (result.unavailableReason != null) 'reason': result.unavailableReason,
      if (deviceInfo.deviceId != null) 'deviceId': deviceInfo.deviceId,
      if (deviceInfo.deviceModel != null) 'deviceModel': deviceInfo.deviceModel,
      if (deviceInfo.manufacturer != null) 'manufacturer': deviceInfo.manufacturer,
      // Backend enum is strictly "android"|"ios" — an unrecognized
      // platform value is omitted rather than sent and rejecting the
      // whole batch's Zod validation.
      if (deviceInfo.osPlatform != null) 'osPlatform': deviceInfo.osPlatform,
      if (deviceInfo.osVersion != null) 'osVersion': deviceInfo.osVersion,
      if (deviceInfo.appVersion != null) 'appVersion': deviceInfo.appVersion,
      'sdkVersion': sdkVersion,
      'observedAt': result.observedAt.toIso8601String(),
    };
  }

  static void _reportError(String reason) {
    try {
      onShipError?.call(reason);
    } catch (_) {
      // A throwing callback must never propagate — dropped intentionally.
    }
  }

  static Future<_DeviceInfo> _collectDeviceInfo() async {
    String? deviceModel;
    String? manufacturer;
    String? osVersion;
    String? osPlatform;

    try {
      if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
        final info = await DeviceInfoPlugin().androidInfo;
        deviceModel = info.model;
        manufacturer = info.manufacturer;
        osVersion = info.version.release;
        osPlatform = 'android';
      } else if (!kIsWeb && defaultTargetPlatform == TargetPlatform.iOS) {
        final info = await DeviceInfoPlugin().iosInfo;
        deviceModel = info.utsname.machine;
        manufacturer = 'Apple';
        osVersion = info.systemVersion;
        osPlatform = 'ios';
      }
    } catch (_) {
      // Leave device fields null — never let a device-info read failure
      // block shipping the detection results themselves.
    }

    String? appVersion;
    try {
      final pkg = await PackageInfo.fromPlatform();
      appVersion = pkg.version;
    } catch (_) {
      // Leave appVersion null.
    }

    final deviceId = DeviceIdentity.cached ?? await _tryGetDeviceId();

    return _DeviceInfo(
      deviceId: deviceId,
      deviceModel: deviceModel,
      manufacturer: manufacturer,
      osVersion: osVersion,
      osPlatform: osPlatform,
      appVersion: appVersion,
    );
  }

  static Future<String?> _tryGetDeviceId() async {
    try {
      return await DeviceIdentity.get();
    } catch (_) {
      return null;
    }
  }
}

class _DeviceInfo {
  final String? deviceId;
  final String? deviceModel;
  final String? manufacturer;
  final String? osVersion;
  final String? osPlatform;
  final String? appVersion;

  const _DeviceInfo({
    this.deviceId,
    this.deviceModel,
    this.manufacturer,
    this.osVersion,
    this.osPlatform,
    this.appVersion,
  });
}

/// Mirrors `RaspEventCredential` (android_core, Kotlin) and the JSON shape
/// `FROUNTEND_BACKEND_RASPOWN/BE/src/credentials/routes.ts` issues.
class _RaspEventCredential {
  final String organizationId;
  final String applicationId;
  final String apiKey;
  final String apiSecret;
  final String ingestionUrl;

  const _RaspEventCredential({
    required this.organizationId,
    required this.applicationId,
    required this.apiKey,
    required this.apiSecret,
    required this.ingestionUrl,
  });

  /// `null` on any malformed/incomplete JSON — never throws, matching
  /// every other parsing boundary in this SDK.
  static _RaspEventCredential? tryParse(String json) {
    try {
      final decoded = jsonDecode(json);
      if (decoded is! Map<String, dynamic>) return null;
      final organizationId = decoded['organization_id'] as String?;
      final applicationId = decoded['application_id'] as String?;
      final apiKey = decoded['api_key'] as String?;
      final apiSecret = decoded['api_secret'] as String?;
      final ingestionUrl = decoded['ingestion_url'] as String?;
      if (organizationId == null ||
          organizationId.isEmpty ||
          applicationId == null ||
          applicationId.isEmpty ||
          apiKey == null ||
          apiKey.isEmpty ||
          apiSecret == null ||
          apiSecret.isEmpty ||
          ingestionUrl == null ||
          ingestionUrl.isEmpty) {
        return null;
      }
      return _RaspEventCredential(
        organizationId: organizationId,
        applicationId: applicationId,
        apiKey: apiKey,
        apiSecret: apiSecret,
        ingestionUrl: ingestionUrl,
      );
    } catch (_) {
      return null;
    }
  }
}
