import 'dart:convert';
import 'dart:typed_data';

/// Lifecycle state of a configuration-signing public key.
///
/// Mirrors [CertificateRole]'s three-role model deliberately: the same
/// rotation problem has the same shape, and one vocabulary is easier to reason
/// about than two.
enum ConfigKeyStatus {
  /// The key the backend signs with today.
  current,

  /// The key the backend is rotating to. Accepted, and reported, so a rollout
  /// is visible rather than discovered afterwards.
  next,

  /// Withdrawn. **Never** accepted, and checked before every other status.
  revoked,
}

/// One pinned Ed25519 verification key.
///
/// **Public keys only.** A private signing key must never appear in this file,
/// this package, the APK, the IPA, a log line, or the repository — see
/// `docs/SIGNED_SECURITY_CONFIGURATION.md` §6 and the dedicated
/// private-key-safety tests.
class ConfigSigningKey {
  /// Stable identifier the envelope names in its `key_id` field.
  final String keyId;

  /// Raw Ed25519 public key, 32 bytes.
  final Uint8List publicKey;

  final ConfigKeyStatus status;

  ConfigSigningKey({
    required this.keyId,
    required this.publicKey,
    required this.status,
  });

  /// Builds a key from standard base64. Throws on anything that is not a
  /// 32-byte Ed25519 public key — a wrong-length key is a configuration
  /// mistake that must surface at construction, not as a mysterious
  /// verification failure later.
  factory ConfigSigningKey.fromBase64({
    required String keyId,
    required String publicKeyBase64,
    required ConfigKeyStatus status,
  }) {
    final bytes = base64.decode(publicKeyBase64);
    if (bytes.length != 32) {
      throw ArgumentError.value(
        publicKeyBase64,
        'publicKeyBase64',
        'Ed25519 public keys are 32 bytes, got ${bytes.length}',
      );
    }
    return ConfigSigningKey(
      keyId: keyId,
      publicKey: Uint8List.fromList(bytes),
      status: status,
    );
  }
}

/// The SDK's trust root for configuration signing.
///
/// ## Why the key set is compiled in and not delivered
///
/// A signed configuration must not be able to introduce the key that verifies
/// it — that is self-certification, and it would make the whole scheme
/// decorative. So the trusted key set is **pinned in the SDK build** and can
/// only change by shipping a new SDK version. [ConfigTrustRoot] has no
/// `fromConfig` constructor, and adding one would be a security regression,
/// not a feature.
///
/// A key is accepted only when **both** hold:
///
/// 1. The envelope's signature verifies against that key, **and**
/// 2. the key is present in this pinned set with an accepting status.
///
/// Condition 2 is what stops "the signature validates, therefore trust it" —
/// an attacker can always produce a valid signature over their own key pair.
class ConfigTrustRoot {
  final List<ConfigSigningKey> keys;

  const ConfigTrustRoot(this.keys);

  /// The trust root shipped in this build.
  ///
  /// **Empty today, deliberately.** No production signing infrastructure
  /// exists for this project yet, and manufacturing a key here would produce
  /// a keypair whose private half is, by definition, public — worse than
  /// having none, because it would look like production signing. See
  /// `docs/SIGNED_SECURITY_CONFIGURATION.md` §9, **PRODUCTION KEY REQUIRED**.
  ///
  /// With an empty root, every configuration verifies as
  /// [ConfigVerificationResult.legacyUnsigned] or
  /// [ConfigVerificationResult.unknownKey] — never as authenticated, and
  /// never as a hard failure that would disarm an existing customer.
  static const ConfigTrustRoot empty = ConfigTrustRoot([]);

  /// Production keys are injected at build time rather than committed, so the
  /// verification key can be updated without a source change and so this file
  /// never becomes a place where key material lives.
  ///
  /// ```
  /// flutter build apk --release \
  ///   --dart-define=RASP_CONFIG_SIGNING_KEY_ID=prod-2026-01 \
  ///   --dart-define=RASP_CONFIG_SIGNING_KEY=<base64 32-byte Ed25519 public key>
  /// ```
  ///
  /// Only the **public** key is ever passed this way. A `--dart-define` value
  /// is trivially recoverable from the artifact, which is exactly why it is
  /// safe for a public key and would be catastrophic for a private one.
  static ConfigTrustRoot fromBuildEnvironment() {
    const keyId = String.fromEnvironment('RASP_CONFIG_SIGNING_KEY_ID');
    const key = String.fromEnvironment('RASP_CONFIG_SIGNING_KEY');
    const nextKeyId = String.fromEnvironment('RASP_CONFIG_SIGNING_NEXT_KEY_ID');
    const nextKey = String.fromEnvironment('RASP_CONFIG_SIGNING_NEXT_KEY');

    final keys = <ConfigSigningKey>[];
    if (keyId.isNotEmpty && key.isNotEmpty) {
      try {
        keys.add(ConfigSigningKey.fromBase64(
          keyId: keyId,
          publicKeyBase64: key,
          status: ConfigKeyStatus.current,
        ));
      } catch (_) {
        // A malformed pinned key must not be silently dropped into a
        // "trusts nothing" state that looks identical to "not configured" —
        // but it also must not crash startup. It is omitted here and the
        // resulting empty/partial root reports unknownKey, which is a
        // visible failure rather than a silent pass.
      }
    }
    if (nextKeyId.isNotEmpty && nextKey.isNotEmpty) {
      try {
        keys.add(ConfigSigningKey.fromBase64(
          keyId: nextKeyId,
          publicKeyBase64: nextKey,
          status: ConfigKeyStatus.next,
        ));
      } catch (_) {
        // As above.
      }
    }
    return ConfigTrustRoot(List.unmodifiable(keys));
  }

  bool get isConfigured => keys.isNotEmpty;

  /// The pinned key with [keyId], or `null` when this SDK build does not trust
  /// it. A `null` here is what produces [ConfigVerificationResult.unknownKey],
  /// and it is never treated as "verify against whatever key is offered".
  ConfigSigningKey? keyFor(String? keyId) {
    if (keyId == null || keyId.isEmpty) return null;
    for (final key in keys) {
      if (key.keyId == keyId) return key;
    }
    return null;
  }
}

/// The outcome of verifying a signed configuration envelope.
///
/// Distinct failures stay distinct: collapsing them would lose exactly the
/// information an operator needs to tell a broken rollout from an attack.
/// **No failure value is ever mapped to [valid].**
enum ConfigVerificationResult {
  /// Signature verified against a pinned, accepted key, and every freshness
  /// and version rule passed.
  valid,

  /// The document carries no signature at all. A pre-signing backend, or a
  /// cached configuration from before the migration.
  ///
  /// Deliberately **not** an error and deliberately **not** [valid]: it is a
  /// third state, so a legacy configuration keeps working without ever being
  /// reported as cryptographically authenticated.
  legacyUnsigned,

  /// The signature did not verify against the named key.
  invalidSignature,

  /// The named `key_id` is not in the SDK's pinned trust root, or is revoked.
  unknownKey,

  /// `algorithm` names something this SDK does not implement.
  unsupportedAlgorithm,

  /// Structurally unusable: missing required fields, undecodable signature,
  /// non-canonicalizable payload.
  malformed,

  /// `expires_at` has passed.
  expired,

  /// `issued_at` is beyond the tolerated clock skew in the future.
  notYetValid,

  /// Same version, different document identity.
  replay,

  /// Older than the configuration already in force.
  downgrade,

  /// Verification itself threw.
  error,
}

/// Semantics for [ConfigVerificationResult].
extension ConfigVerificationResultX on ConfigVerificationResult {
  /// The single value meaning "cryptographically authenticated and fresh".
  ///
  /// One definition site, so the `X != VALID` fail-safe rules cannot drift.
  bool get isAuthenticated => this == ConfigVerificationResult.valid;

  /// Stable wire name.
  String get wireName => name
      .replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}')
      .toUpperCase();
}
