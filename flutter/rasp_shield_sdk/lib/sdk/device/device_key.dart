/// Public description of this device's cryptographic binding identity.
///
/// ## What this file may hold, and what it may never hold
///
/// **Public key material only.** The private key is generated inside the
/// platform keystore, is marked non-exportable there, and never crosses the
/// platform channel in either direction — the native layer exposes a
/// *signing operation*, never the key. Nothing in this file, and nothing
/// that consumes it, can obtain the private key, which is why it is safe to
/// put a [DeviceKeyInfo] in a request body, a log line, or a test fixture.
/// `device_binding_no_secret_test.dart` asserts this by construction.
///
/// See `docs/DEVICE_KEY_LIFECYCLE.md`.
library;

/// How strongly the device's private key is protected.
///
/// Four states, deliberately — the same discipline `DetectionStatus` and
/// `TrustAnchorState` already enforce. "We could not tell" is its own
/// outcome and is never folded into either usable state.
///
/// **Software-backed storage is not attestation and must never be described
/// as such.** A software-backed key still binds a licence to an install far
/// better than a copyable UUID does, but it can be lifted off a rooted
/// device; only [hardwareBacked] involves a TEE or secure element, and even
/// that is not the same as a hardware *attestation* (see
/// `docs/LICENSE_DEVICE_BINDING.md` §9).
enum DeviceKeyBacking {
  /// The private key lives in a TEE / StrongBox / Secure Enclave. Reported
  /// only when the platform itself says so — `KeyInfo.getSecurityLevel()` on
  /// API 31+, `KeyInfo.isInsideSecureHardware()` below it.
  hardwareBacked,

  /// A real, usable key that the platform did not report as living in
  /// secure hardware.
  softwareBacked,

  /// No key, and none can be created here — wrong platform, no keystore, or
  /// the native surface is not registered.
  unavailable,

  /// The keystore was reachable and the operation threw.
  error,
}

/// Semantics and wire form for [DeviceKeyBacking].
extension DeviceKeyBackingX on DeviceKeyBacking {
  /// Stable `SCREAMING_SNAKE_CASE` name — `HARDWARE_BACKED`,
  /// `SOFTWARE_BACKED`, `UNAVAILABLE`, `ERROR`. Sent to the backend and
  /// stored on the activation row.
  String get wireName => name
      .replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}')
      .toUpperCase();

  /// Whether a key exists that can actually sign. The only two states that
  /// can produce a device proof.
  bool get isUsable =>
      this == DeviceKeyBacking.hardwareBacked ||
      this == DeviceKeyBacking.softwareBacked;

  /// Whether the platform confirmed secure-hardware storage.
  ///
  /// Named as a question rather than compared inline so the one thing this
  /// SDK is forbidden from overclaiming has exactly one definition site.
  bool get isSecureHardware => this == DeviceKeyBacking.hardwareBacked;

  /// Parse a [wireName] back. Anything unrecognised — including `null` — is
  /// [DeviceKeyBacking.unavailable], never a usable state.
  static DeviceKeyBacking parse(Object? raw) {
    switch (raw?.toString().toUpperCase()) {
      case 'HARDWARE_BACKED':
        return DeviceKeyBacking.hardwareBacked;
      case 'SOFTWARE_BACKED':
        return DeviceKeyBacking.softwareBacked;
      case 'ERROR':
        return DeviceKeyBacking.error;
      default:
        return DeviceKeyBacking.unavailable;
    }
  }
}

/// The signature algorithm a device key uses.
///
/// One value today. It exists as an enum rather than a bare string so a
/// future StrongBox-only or RSA-fallback variant is a compile-time change
/// with a stable wire name, not a string literal copied into four files —
/// the mistake `RaspNativeChannel`'s doc comment describes for channel
/// names.
enum DeviceKeyAlgorithm {
  /// NIST P-256 ECDSA with SHA-256. Chosen over RSA because Android
  /// Keystore generates it in well under a second on the low-end hardware
  /// this SDK targets, StrongBox supports it where RSA is often refused,
  /// and its DER-encoded signatures verify unmodified with Python's
  /// `cryptography` on the backend.
  ecP256Sha256,
}

extension DeviceKeyAlgorithmX on DeviceKeyAlgorithm {
  String get wireName {
    switch (this) {
      case DeviceKeyAlgorithm.ecP256Sha256:
        return 'EC_P256_SHA256';
    }
  }

  /// `null` for anything unrecognised — an unknown algorithm is never
  /// silently treated as the one we support.
  static DeviceKeyAlgorithm? parse(Object? raw) {
    switch (raw?.toString().toUpperCase()) {
      case 'EC_P256_SHA256':
        return DeviceKeyAlgorithm.ecP256Sha256;
      default:
        return null;
    }
  }
}

/// This device's binding identity, as public data.
///
/// [keyId] is the SHA-256 of the DER `SubjectPublicKeyInfo`, uppercase hex —
/// computed identically on the device (`MainActivity.deviceKeyFingerprint`)
/// and on the backend (`app/licensing/device_binding.py::key_fingerprint`),
/// so the two never need to exchange a separate identifier.
class DeviceKeyInfo {
  /// SHA-256 of the DER SPKI, uppercase hex (64 chars).
  final String keyId;

  /// Base64 of the DER SPKI. Public material; safe to transmit.
  final String publicKey;

  final DeviceKeyAlgorithm algorithm;
  final DeviceKeyBacking backing;

  const DeviceKeyInfo({
    required this.keyId,
    required this.publicKey,
    required this.algorithm,
    required this.backing,
  });

  /// A key that exists, is well-formed, and can sign.
  bool get isUsable =>
      backing.isUsable && keyId.length == 64 && publicKey.isNotEmpty;

  /// Build from the native channel's map, or `null` when the payload is
  /// absent or malformed.
  ///
  /// A malformed payload yields `null` rather than a partially-populated
  /// object: a [DeviceKeyInfo] that exists is one the rest of the SDK may
  /// compare against a token claim, and a half-parsed one would be compared
  /// just as confidently.
  static DeviceKeyInfo? fromMap(Map<String, Object?>? raw) {
    if (raw == null) return null;
    final keyId = raw['key_id']?.toString().toUpperCase() ?? '';
    final publicKey = raw['public_key']?.toString() ?? '';
    final algorithm = DeviceKeyAlgorithmX.parse(raw['algorithm']);
    if (keyId.length != 64 || publicKey.isEmpty || algorithm == null) {
      return null;
    }
    return DeviceKeyInfo(
      keyId: keyId,
      publicKey: publicKey,
      algorithm: algorithm,
      backing: DeviceKeyBackingX.parse(raw['backing']),
    );
  }

  /// The fields sent to the backend at activation. Public material only.
  Map<String, Object?> toRegistrationJson() => {
        'device_key_id': keyId,
        'device_public_key': publicKey,
        'device_key_algorithm': algorithm.wireName,
        'device_key_backing': backing.wireName,
      };

  /// Identity-safe rendering. Deliberately truncates [keyId] and omits
  /// [publicKey] entirely, so an accidental interpolation into a log line
  /// cannot publish a full device identity.
  @override
  String toString() =>
      'DeviceKeyInfo(${keyId.substring(0, 8)}…, ${algorithm.wireName}, '
      '${backing.wireName})';

  @override
  bool operator ==(Object other) =>
      other is DeviceKeyInfo &&
      other.keyId == keyId &&
      other.publicKey == publicKey &&
      other.algorithm == algorithm &&
      other.backing == backing;

  @override
  int get hashCode => Object.hash(keyId, publicKey, algorithm, backing);
}
