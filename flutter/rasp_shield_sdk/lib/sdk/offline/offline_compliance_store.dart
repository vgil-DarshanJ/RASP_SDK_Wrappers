import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Persistence for offline-compliance state.
///
/// ## What is stored, and what deliberately is not
///
/// **Not stored: the trusted timestamp.** The anchor is the `issued_at`
/// claim inside the entitlement token that `LicenseManager` already keeps in
/// secure storage. Copying it into a second location would create a second,
/// *unsigned* copy of a security-critical value — trivially editable, and
/// authoritative for nothing. The token is read and its HMAC verified on
/// every evaluation instead, so tampering with it invalidates it rather than
/// shifting the deadline.
///
/// **Stored: the clock high-water mark only** — the highest wall-clock value
/// this device has been observed to report. It exists solely to catch a
/// clock rewound *between launches*, which comparing against the anchor
/// cannot see on its own.
///
/// ## Threat model for this one value
///
/// It is written to `FlutterSecureStorage` (Android
/// `encryptedSharedPreferences`, iOS Keychain) — the same store the licence
/// tokens use. That defeats casual editing (`adb shell`, a file browser, a
/// rooted-device text editor). It does **not** defeat an attacker who can
/// run code in the process, and it is not claimed to: see
/// `docs/OFFLINE_COMPLIANCE_THREAT_MODEL.md`.
///
/// Deleting it is the strongest thing an attacker gains, and that is
/// deliberately weak: a missing high-water mark disables *only* the
/// cross-launch rewind check. The anchor comparison — which needs no local
/// state, because the timestamp is inside a server-signed token — still
/// stands. There is no stored value whose deletion grants compliance.
///
/// Nothing here is a secret, so nothing here is logged, and no secret is
/// written to `SharedPreferences` or plain text.
class OfflineComplianceStore {
  static const _clockMarkKey = 'rasp_sdk_clock_high_water_mark';

  static const FlutterSecureStorage _defaultStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  final FlutterSecureStorage _storage;

  const OfflineComplianceStore({FlutterSecureStorage? storage})
      : _storage = storage ?? _defaultStorage;

  /// In-memory override so a test can drive the store with no platform
  /// channel. Test-only: guarded by [visibleForTesting] and never set by
  /// production code.
  @visibleForTesting
  static Map<String, String>? testValues;

  /// Forces the next read to fail, so the `error` branch of the evaluator is
  /// reachable in a test without breaking real storage.
  @visibleForTesting
  static bool testFailReads = false;

  /// The highest wall-clock value previously observed, or `null` if none has
  /// been recorded or the value is unreadable/corrupt.
  ///
  /// A corrupt value is treated as absent rather than as an error: it
  /// disables one defence-in-depth check, and failing the whole evaluation
  /// over it would let anyone force `error` by writing garbage.
  Future<DateTime?> readClockHighWaterMark() async {
    final raw = await _read(_clockMarkKey);
    if (raw == null || raw.isEmpty) return null;
    return DateTime.tryParse(raw)?.toUtc();
  }

  /// Records [now] when it is later than what is already stored.
  ///
  /// Monotonic by construction — it never moves backwards, which is the
  /// entire point. A write failure is swallowed: the check it powers is
  /// defence-in-depth, and an unwritable keystore must not break a scan.
  Future<void> recordClockObservation(DateTime now) async {
    final current = now.toUtc();
    final existing = await readClockHighWaterMark();
    if (existing != null && !current.isAfter(existing)) return;
    await _write(_clockMarkKey, current.toIso8601String());
  }

  /// Clears the mark. Used when a device legitimately re-activates.
  Future<void> clear() async {
    if (testValues != null) {
      testValues!.remove(_clockMarkKey);
      return;
    }
    try {
      await _storage.delete(key: _clockMarkKey);
    } catch (_) {
      // Nothing recoverable to do, and nothing security-relevant lost.
    }
  }

  /// `true` when storage is unreadable — surfaced so the evaluator can
  /// report `error` rather than guessing.
  Future<bool> readFailed() async {
    if (testFailReads) return true;
    if (testValues != null) return false;
    try {
      await _storage.read(key: _clockMarkKey);
      return false;
    } catch (_) {
      return true;
    }
  }

  Future<String?> _read(String key) async {
    if (testFailReads) return null;
    if (testValues != null) return testValues![key];
    try {
      return await _storage.read(key: key);
    } catch (_) {
      return null;
    }
  }

  Future<void> _write(String key, String value) async {
    if (testValues != null) {
      testValues![key] = value;
      return;
    }
    try {
      await _storage.write(key: key, value: value);
    } catch (_) {
      // See recordClockObservation.
    }
  }
}
