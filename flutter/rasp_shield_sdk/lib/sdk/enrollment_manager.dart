import 'dart:convert';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:package_info_plus/package_info_plus.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../services/backend_override.dart';
import 'device/device_key.dart';
import 'device/device_key_manager.dart';
import 'device/device_proof.dart';
import 'device_identity.dart';

/// Email-verified enrollment for a *generic* (unkeyed) app build.
///
/// Why this exists
/// ---------------
/// The normal SDK activation path proves identity by HMAC-signing a server
/// nonce with the real licence key — which only works when the build was
/// packaged for one specific customer and ships that key inside it.
///
/// A single generic APK that anyone can install has no key to sign with. So
/// instead the user types the e-mail their company registered with RASP
/// Shield, the backend mails a one-time code to that address, and echoing the
/// code back creates a device seat that is **PENDING** against that one
/// company's licence — visible to the Super Admin and to that customer's
/// portal only.
///
/// The result is stored on the device so enrollment is a first-run step, not
/// something the user repeats on every launch.
class EnrollmentManager {
  EnrollmentManager._();

  static const _kEmail = 'rasp_enroll_email';
  static const _kCompany = 'rasp_enroll_company';
  static const _kToken = 'rasp_enroll_activation_token';
  static const _kKeyHash = 'rasp_enroll_license_key_hash';

  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static Dio _dio() => Dio(BaseOptions(
        baseUrl: '${BackendOverride.baseUrl}/api/v1/sdk',
        connectTimeout: const Duration(seconds: 15),
        receiveTimeout: const Duration(seconds: 30),
        headers: const {'Content-Type': 'application/json'},
      ));

  /// True once this device has completed the code exchange.
  ///
  /// Being enrolled does **not** mean the device is approved — it means the
  /// request reached the right customer. Approval is a separate, human step
  /// that the licence gate reports on afterwards.
  static Future<bool> isEnrolled() async {
    return (await _read(_kToken))?.isNotEmpty == true;
  }

  static Future<String?> enrolledEmail() => _read(_kEmail);
  static Future<String?> enrolledCompany() => _read(_kCompany);
  static Future<String?> activationToken() => _read(_kToken);
  static Future<String?> licenseKeyHash() => _read(_kKeyHash);

  /// Ask the backend to mail a one-time code to [email].
  ///
  /// Returns an error string on failure, or `null` on success. The backend
  /// deliberately answers identically for a registered and an unregistered
  /// address, so a `null` here means "the request was accepted", never
  /// "that address is a customer".
  static Future<String?> requestCode(String email) async {
    try {
      final deviceId = await DeviceIdentity.get();
      await _dio().post<Map<String, dynamic>>(
        '/enroll/request-code',
        data: {'email': email.trim(), 'device_id': deviceId},
      );
      return null;
    } on DioException catch (e) {
      return _friendlyError(e);
    } catch (_) {
      return 'Something went wrong. Please try again.';
    }
  }

  /// Exchange [code] for a pending device seat.
  ///
  /// On success the credentials needed for heartbeat/telemetry are persisted
  /// and `null` is returned; otherwise a human-readable error is returned.
  static Future<String?> verifyCode({
    required String email,
    required String code,
  }) async {
    try {
      final deviceId = await DeviceIdentity.get();
      final device = await _deviceDescriptors();
      final bundleId = await _bundleId();
      final trimmedCode = code.trim();

      // Device binding parity (end-to-end enrollment security milestone) —
      // the SAME key creation this build's `ActivationManager.activate()`
      // performs, so an enrolled device converges on the same bound-device
      // security state a keyed activation reaches, rather than being
      // permanently unbound. `DeviceKeyManager.ensure()` is still the ONE
      // place a key is created (see that class's own doc) — this is a second
      // *caller* of it, not a second key-creation mechanism. The now-verified
      // enrollment code stands in for the server nonce `/activate` signs,
      // exactly as the backend's `_require_device_proof_or_raise` expects.
      const deviceKeys = DeviceKeyManager();
      final deviceKey = await deviceKeys.ensure();
      final deviceProof = deviceKey == null
          ? null
          : await deviceKeys.sign(DeviceProof.activationMessage(
              nonce: trimmedCode,
              deviceId: deviceId,
              bundleId: bundleId,
              sdkVersion: '1.0.0',
              keyId: deviceKey.keyId,
            ));

      final res = await _dio().post<Map<String, dynamic>>(
        '/enroll/verify',
        data: {
          'email': email.trim(),
          'code': trimmedCode,
          'device_id': deviceId,
          'bundle_id': bundleId,
          'sdk_version': '1.0.0',
          'device_model': device['device_model'],
          'os_version': device['os_version'],
          'app_version': await _appVersion(),
          'manufacturer': device['manufacturer'],
          // Omitted entirely when this device has no keystore, so the
          // server sees a legacy/unbound client rather than a failed proof
          // — the same distinction `ActivationManager.activate()` already
          // preserves.
          if (deviceKey != null && deviceProof != null) ...{
            'device_public_key': deviceKey.publicKey,
            'device_key_algorithm': deviceKey.algorithm.wireName,
            'device_key_backing': deviceKey.backing.wireName,
            'device_proof': deviceProof,
          },
        },
      );
      final data = res.data;
      if (data == null) return 'Unexpected response from the server.';

      await _write(_kEmail, email.trim());
      await _write(_kCompany, (data['company_name'] ?? '').toString());
      await _write(_kToken, (data['activation_token'] ?? '').toString());
      await _write(_kKeyHash, (data['license_key_hash'] ?? '').toString());
      return null;
    } on DioException catch (e) {
      return _friendlyError(e);
    } catch (_) {
      return 'Something went wrong. Please try again.';
    }
  }

  /// Forget this device's enrollment (used by "use a different account").
  static Future<void> clear() async {
    for (final k in [_kEmail, _kCompany, _kToken, _kKeyHash]) {
      try {
        await _storage.delete(key: k);
      } catch (_) {}
      try {
        await (await SharedPreferences.getInstance()).remove(k);
      } catch (_) {}
    }
  }

  // The real package name is what a licence binds to, so it must be the value
  // the platform reports rather than a constant compiled in here.
  static Future<String> _bundleId() async {
    try {
      return (await PackageInfo.fromPlatform()).packageName;
    } catch (_) {
      // Honest "could not determine" rather than a plausible-looking but
      // wrong identity — see activation_manager.dart::bundleId().
      return '';
    }
  }

  static Future<String> _appVersion() async {
    try {
      return (await PackageInfo.fromPlatform()).version;
    } catch (_) {
      return '0.0.0';
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
        'manufacturer': info.manufacturer,
      };
    } catch (_) {
      return {'device_model': 'unknown', 'os_version': 'unknown', 'manufacturer': ''};
    }
  }

  /// Surfaces the backend's own message when it sent one, because those are
  /// already written for an end user ("no seats left", "contact your
  /// administrator") and are more useful than a generic network error.
  static String _friendlyError(DioException e) {
    final data = e.response?.data;
    if (data is Map && data['detail'] is Map) {
      final msg = (data['detail'] as Map)['message'];
      if (msg is String && msg.isNotEmpty) return msg;
    }
    if (data is Map && data['detail'] is String) {
      return data['detail'] as String;
    }
    if (data is String && data.isNotEmpty) {
      try {
        final decoded = jsonDecode(data);
        if (decoded is Map && decoded['detail'] is Map) {
          final msg = (decoded['detail'] as Map)['message'];
          if (msg is String && msg.isNotEmpty) return msg;
        }
      } catch (_) {}
    }
    if (e.type == DioExceptionType.connectionError ||
        e.type == DioExceptionType.connectionTimeout) {
      return 'Cannot reach the RASP Shield server at ${BackendOverride.baseUrl}. '
          'Check your connection, or update the server address in Settings.';
    }
    return 'Request failed. Please try again.';
  }

  // Secure storage first, SharedPreferences as the fallback — same pattern as
  // DeviceIdentity, so a keystore failure degrades to "still works" instead of
  // forcing the user to enroll again on every launch.
  static Future<void> _write(String key, String value) async {
    try {
      await _storage.write(key: key, value: value);
      return;
    } catch (_) {}
    try {
      await (await SharedPreferences.getInstance()).setString(key, value);
    } catch (_) {}
  }

  static Future<String?> _read(String key) async {
    try {
      final v = await _storage.read(key: key);
      if (v != null && v.isNotEmpty) return v;
    } catch (_) {}
    try {
      return (await SharedPreferences.getInstance()).getString(key);
    } catch (_) {
      return null;
    }
  }
}
