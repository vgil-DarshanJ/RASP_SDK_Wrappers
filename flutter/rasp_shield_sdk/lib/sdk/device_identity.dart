import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:uuid/uuid.dart';

import 'detectors/rasp_native_channel.dart';

/// Stable per-install device identifier used as the SDK activation seat key,
/// and as the `deviceId` every shipped security event carries.
///
/// Persisted in the Android Keystore-backed secure storage, with a
/// SharedPreferences fallback so a keystore failure degrades to "still works"
/// rather than minting a fresh seat on every launch.
///
/// ## Why this reads `ANDROID_ID` first, not just a random UUID
///
/// A value generated purely in Dart and saved to this app's own storage
/// (Keystore-backed prefs or plain SharedPreferences — both) is wiped the
/// instant this app is uninstalled: Android deletes all of an app's private
/// data on uninstall, no exceptions. That means every uninstall+reinstall of
/// the same physical phone used to mint a brand-new random id — the same
/// device showing up as a new "device" on the dashboard every time, exactly
/// the duplicate-device problem this class now avoids.
///
/// `ANDROID_ID` (`Settings.Secure.ANDROID_ID`, read via
/// [RaspNativeChannel.stringCall]'s `getAndroidId`) is scoped per device +
/// this app's signing key + user profile since Android 8 (O) — it survives
/// this exact app being uninstalled and reinstalled, and only changes on a
/// factory reset or a change of signing key. No permission required, and it
/// does not identify this device to any *other* app.
///
/// A device already running an older SDK version has an existing random-UUID
/// id in storage — that id is read and kept as-is (never replaced out from
/// under an install already counted on the dashboard); only a value read for
/// the *first* time (fresh install, or a platform/device where `ANDROID_ID`
/// could not be read) falls back to a freshly minted random id.
class DeviceIdentity {
  static const _key = 'rasp_sdk_device_id';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static String? _cached;

  /// The persisted device id this process has already loaded, or `null`
  /// before the first [get] call this session. Synchronous, for callers
  /// like `RaspShield.status()` that cannot await a storage read — never
  /// creates one (see [get] for that).
  static String? get cached => _cached;

  /// Return the persisted device id, creating one on first launch.
  static Future<String> get() async {
    final cached = _cached;
    if (cached != null) return cached;

    String? existing;
    try {
      existing = await _storage.read(key: _key);
    } catch (_) {
      existing = null;
    }

    if (existing == null || existing.isEmpty) {
      try {
        final prefs = await SharedPreferences.getInstance();
        existing = prefs.getString(_key);
      } catch (_) {
        existing = null;
      }
    }

    if (existing == null || existing.isEmpty) {
      // Nothing persisted yet — either a genuinely fresh install, or this
      // exact physical device reinstalling after a previous uninstall wiped
      // its old id. Try the stable, reinstall-surviving id first.
      final androidId = await RaspNativeChannel.stringCall('getAndroidId');
      existing = (androidId != null && androidId.isNotEmpty)
          ? androidId
          : const Uuid().v4().replaceAll('-', '');
      await _persist(existing);
    }

    _cached = existing;
    return existing;
  }

  static Future<void> _persist(String deviceId) async {
    try {
      await _storage.write(key: _key, value: deviceId);
    } catch (_) {
      // Keystore unavailable — fall through to plain preferences.
    }
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_key, deviceId);
    } catch (_) {
      // Nothing else to try; the in-memory cache still serves this session.
    }
  }
}
