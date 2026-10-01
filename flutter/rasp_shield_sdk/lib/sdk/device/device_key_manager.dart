import 'package:flutter/foundation.dart';

import '../detectors/rasp_native_channel.dart';
import 'device_key.dart';

/// The SDK's access to this device's cryptographic binding identity.
///
/// ## The private key never comes back across this boundary
///
/// Four native methods exist, and none of them returns private key
/// material:
///
/// | Method | Returns |
/// |---|---|
/// | `getDeviceKeyInfo` | key id, **public** key, algorithm, backing — or nothing |
/// | `ensureDeviceKey` | the same, creating the key first if absent |
/// | `signWithDeviceKey` | a signature over a caller-supplied message |
/// | `clearDeviceKey` | nothing |
///
/// The keypair is generated *inside* the platform keystore and marked
/// non-exportable there, so there is no native code path that could return
/// it even if one were asked for. This is what makes the whole scheme worth
/// more than a stored secret: a full copy of the app's data directory does
/// not carry the key, because the key was never in the data directory.
///
/// ## Read-only by default
///
/// [load] never creates a key. Only [ensure] does, and it is called from
/// exactly one place — activation. That separation is what makes a missing
/// key *detectable*: if verification could silently mint a replacement, a
/// cloned install would heal itself on first launch and the mismatch this
/// milestone detects would never be observable. It is the precise defect
/// `LICENSE_DEVICE_BINDING_AUDIT.md` §3.3 records in the legacy
/// `verifyDeviceBinding()`.
///
/// ## Failure model
///
/// Nothing here throws. Every failure resolves to a [DeviceKeyBacking] of
/// `unavailable` or `error` and a `null` key — never a fabricated one. See
/// `docs/DEVICE_KEY_LIFECYCLE.md`.
class DeviceKeyManager {
  const DeviceKeyManager();

  static const _infoMethod = 'getDeviceKeyInfo';
  static const _ensureMethod = 'ensureDeviceKey';
  static const _signMethod = 'signWithDeviceKey';
  static const _clearMethod = 'clearDeviceKey';

  /// Cached across calls within a process: reading it costs a platform hop
  /// and a keystore load, the answer cannot change without the app being
  /// restarted (a key is never removed except by [clear], which resets
  /// this), and every licensing evaluation asks for it.
  static DeviceKeyInfo? _cached;
  static DeviceKeyBacking _lastBacking = DeviceKeyBacking.unavailable;
  static bool _keystoreAvailable = false;

  /// The reason the most recent [load]/[ensure] returned no key.
  ///
  /// Consumed by `LicenseBindingValidator` to tell a platform with no
  /// keystore (indeterminate) from a working keystore that simply does not
  /// hold this seat's key (the clone signature).
  static DeviceKeyBacking get lastBacking => _lastBacking;

  /// Whether the platform keystore itself answered, independently of whether
  /// it holds a key for this seat.
  ///
  /// This is the distinction the whole clone detection turns on. "No key"
  /// means two completely different things:
  ///
  /// * *the keystore does not exist here* - a platform limitation, proving
  ///   nothing about the install;
  /// * *the keystore exists and does not contain this seat key* - which is
  ///   precisely what a copied install looks like, because the private key
  ///   was non-exportable and did not travel with the data directory.
  ///
  /// Collapsing the two would either lock out every device without a
  /// keystore or let every clone through. See `LicenseBindingValidator`.
  static bool get keystoreAvailable => _keystoreAvailable;

  /// The device-bound key id this process last loaded — the same value
  /// that already rides every canonical security event as
  /// `deviceBindingId`, and every `/heartbeat`/`/activate` call's
  /// `X-Rasp-Device-Key-Id` header. Exposed here as a synchronous read
  /// (`RaspShield.status()` is sync) for the "RASP Device ID" the
  /// Continuous Security Telemetry milestone surfaces — see
  /// `RaspShieldStatus.deviceId`'s doc for exactly what this is and is
  /// not: a public-key fingerprint the platform Keystore generated and
  /// will never export, never an IMEI/serial/MAC, never a value a client
  /// can pick.
  ///
  /// `null` until [load]/[ensure] has actually run this process — which
  /// activation already guarantees for a device that holds a key at all.
  /// Never a private key, and never anything beyond what
  /// `getDeviceKeyInfo`/`ensureDeviceKey` already return (see this class's
  /// own doc — no native path returns private key material to begin with).
  static String? get cachedKeyId => _cached?.keyId;

  /// Test override for the whole surface, so binding logic is exercised with
  /// no platform channel and no device.
  @visibleForTesting
  static DeviceKeyManagerOverride? testOverride;

  /// Drops the in-process cache. Test-only; production code has no reason to
  /// forget a key that cannot change.
  @visibleForTesting
  static void resetCacheForTesting() {
    _cached = null;
    _lastBacking = DeviceKeyBacking.unavailable;
    _keystoreAvailable = false;
  }

  /// Read this device's binding key **without creating one**.
  ///
  /// Returns `null` when no key exists, when the platform has no keystore,
  /// or when the read failed — [lastBacking] says which.
  Future<DeviceKeyInfo?> load() async {
    final override = testOverride;
    if (override != null) {
      _lastBacking = override.backing;
      _keystoreAvailable = override.keystoreAvailable;
      _cached = override.key;
      return override.key;
    }

    final cached = _cached;
    if (cached != null) return cached;

    return _readInto(_infoMethod);
  }

  /// Read this device's binding key, creating one if it does not exist.
  ///
  /// Called from activation only. A device that has never activated has no
  /// key, which is correct: the key is the identity a seat is issued *to*,
  /// so it comes into being at the moment the seat does.
  Future<DeviceKeyInfo?> ensure() async {
    final override = testOverride;
    if (override != null) {
      _lastBacking = override.backing;
      _keystoreAvailable = override.keystoreAvailable;
      _cached = override.key;
      return override.key;
    }

    final existing = _cached;
    if (existing != null) return existing;

    return _readInto(_ensureMethod);
  }

  Future<DeviceKeyInfo?> _readInto(String method) async {
    if (!RaspNativeChannel.isNativePlatform) {
      _lastBacking = DeviceKeyBacking.unavailable;
      _keystoreAvailable = false;
      return null;
    }
    final raw = await RaspNativeChannel.mapCall(method);
    if (raw == null) {
      // No handler registered, or the platform call itself failed. Never an
      // error verdict: we do not know that anything failed, only that
      // nothing answered.
      _lastBacking = DeviceKeyBacking.unavailable;
      _keystoreAvailable = false;
      return null;
    }

    _keystoreAvailable = raw['keystore_available'] == true;
    _lastBacking = DeviceKeyBackingX.parse(raw['backing']);

    final info = DeviceKeyInfo.fromMap(raw);
    if (info == null) {
      // Either the keystore holds no key for this seat, or it answered with
      // something unusable. [keystoreAvailable] above is what tells those
      // two apart downstream; this method deliberately does not decide.
      _cached = null;
      return null;
    }

    _lastBacking = info.backing;
    _cached = info;
    return info;
  }

  /// Sign [message] with the device's private key.
  ///
  /// Returns a base64 signature, or `null` when no key exists or the
  /// keystore refused. A `null` here is reported upstream as "no proof
  /// available", never as a proof that passed.
  ///
  /// [message] is a canonical string built by the caller — see
  /// `DeviceProof`. This method does not construct one, so there is exactly
  /// one place that decides what a device proof covers.
  Future<String?> sign(String message) async {
    if (message.isEmpty) return null;

    final override = testOverride;
    if (override != null) return override.sign?.call(message);

    if (!RaspNativeChannel.isNativePlatform) return null;
    final raw = await RaspNativeChannel.mapCall(_signMethod, {'message': message});
    final signature = raw?['signature']?.toString();
    if (signature == null || signature.isEmpty) return null;
    return signature;
  }

  /// Destroy this device's binding key.
  ///
  /// The **local** half of device replacement, and deliberately not enough
  /// on its own: clearing the key here does not re-authorise anything,
  /// because the server still holds the old key on the seat and will place
  /// the next, differently-keyed activation into `REPLACEMENT_PENDING`
  /// until an operator approves it. See `docs/DEVICE_REPLACEMENT.md`.
  Future<bool> clear() async {
    _cached = null;
    _lastBacking = DeviceKeyBacking.unavailable;
    _keystoreAvailable = false;

    final override = testOverride;
    if (override != null) return override.clearSucceeds;

    if (!RaspNativeChannel.isNativePlatform) return false;
    return await RaspNativeChannel.boolCall(_clearMethod) ?? false;
  }
}

/// Test double for [DeviceKeyManager]'s entire native surface.
@visibleForTesting
class DeviceKeyManagerOverride {
  final DeviceKeyInfo? key;
  final DeviceKeyBacking backing;
  final bool keystoreAvailable;
  final String? Function(String message)? sign;
  final bool clearSucceeds;

  const DeviceKeyManagerOverride({
    this.key,
    this.backing = DeviceKeyBacking.unavailable,
    this.keystoreAvailable = false,
    this.sign,
    this.clearSucceeds = true,
  });
}
