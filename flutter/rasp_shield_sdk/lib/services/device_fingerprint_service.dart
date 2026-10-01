import 'dart:convert';
import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

class DeviceFingerprintResult {
  final bool isRisk;
  final String reason;
  final List<String> failedChecks;

  /// `true` when the check could not complete — a malformed native payload,
  /// a secure-storage failure, or any other exception. [isRisk] is `false` in
  /// this case exactly as it was before this field existed, so an existing
  /// caller that only reads [isRisk] sees unchanged behaviour.
  ///
  /// **Why this exists:** the previous implementation caught every exception
  /// here and returned a plain clean result, indistinguishable from "checked
  /// and found nothing". A JSON-decode failure on the native fingerprint
  /// payload is a platform-side fault, not a clean device — see
  /// `docs/CONFIDENCE_MODEL.md` § DeviceFingerprintService error-handling fix.
  /// A caller that wants the four/five-state model (rather than the
  /// original boolean-only [isRisk]) should check this field and report
  /// `error`, not `secure`.
  final bool checkFailed;

  /// Diagnostic detail when [checkFailed] is `true`, or `null` otherwise.
  final String? failureReason;

  DeviceFingerprintResult({
    required this.isRisk,
    required this.reason,
    required this.failedChecks,
    this.checkFailed = false,
    this.failureReason,
  });
}

class DeviceFingerprintService {
  static const _storage = FlutterSecureStorage();
  static const _key = 'device_fingerprint_v2';
  static const _securityChannel = MethodChannel(
    'com.shieldsdk.security/security',
  );

  // HOW TO TEST:
  // screenLockEnabled → Go to Settings > Security > Screen Lock > set to None
  // adbEnabled → Go to Settings > Developer Options > turn on USB Debugging
  // selinuxEnforcing → Requires rooted device to disable (rarely possible on non-root)
  // installSource → Install app via "flutter run" (not Play Store) triggers this
  // Hardware change → Use "Device ID Changer" app from Play Store (requires root)

  static Future<DeviceFingerprintResult> checkDeviceRisk() async {
    try {
      final String jsonString =
          await _securityChannel.invokeMethod('getDeviceFingerprint') ?? '{}';
      final Map<String, dynamic> data = jsonDecode(jsonString);

      List<String> failedChecks = [];

      // 1. Immediate Security Checks
      if (data['screenLockEnabled'] == false) {
        failedChecks.add('Screen Lock Disabled');
      }
      if (data['adbEnabled'] == true) {
        failedChecks.add('ADB Debugging Enabled');
      }
      if (data['selinuxEnforcing'] == false) {
        failedChecks.add('SELinux Permissive');
      }

      final String installSource = data['installSource'] ?? 'unknown';
      if (installSource != 'com.android.vending' &&
          installSource != 'amazon.market.appstore') {
        // We allow some common stores, but mark others as risk (like sideloaded via ADB)
        failedChecks.add('Sideloaded (Source: $installSource)');
      }

      // 2. Hardware Baseline Check
      String hardwareId;
      if (data.containsKey('androidId')) {
        // Android-specific baseline
        hardwareId =
            '${data['androidId']}|${data['model']}|${data['board']}|${data['buildFingerprint']}';
      } else {
        // iOS-specific baseline
        hardwareId =
            '${data['identifierForVendor']}|${data['model']}|${data['systemName']}|${data['systemVersion']}';
      }

      final bytes = utf8.encode(hardwareId);
      final currentHash = sha256.convert(bytes).toString();

      final storedHash = await _storage.read(key: _key);
      if (storedHash == null) {
        await _storage.write(key: _key, value: currentHash);
      } else if (storedHash != currentHash) {
        failedChecks.add('Hardware Identity Changed');
      }

      bool isRisk = failedChecks.isNotEmpty;
      return DeviceFingerprintResult(
        isRisk: isRisk,
        reason: failedChecks.join(', '),
        failedChecks: failedChecks,
      );
    } catch (e) {
      // Preserved: isRisk stays false, so an existing caller reading only
      // that field sees identical behaviour to before this fix. checkFailed
      // is the new, additive signal a caller can use to tell "checked and
      // clean" apart from "the check itself failed" — see the field's doc
      // comment for why that distinction is a real defect fix, not a
      // stylistic change.
      return DeviceFingerprintResult(
        isRisk: false,
        reason: '',
        failedChecks: const [],
        checkFailed: true,
        failureReason: e.toString(),
      );
    }
  }
}
