import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'config_canonical.dart';
import 'config_signing_keys.dart';

/// A configuration document plus the metadata a signature must cover.
///
/// Every field here is inside the signed bytes. Signing only the payload
/// while leaving `expires_at` and `config_version` editable would defeat both
/// expiry and downgrade protection — an attacker could take a genuine signed
/// document and simply extend its life or renumber it.
class SignedConfigEnvelope {
  final int configVersion;
  final String? configId;
  final DateTime? issuedAt;
  final DateTime? expiresAt;

  /// Identifies which pinned public key signed this document.
  final String? keyId;

  /// Signature algorithm name. Only [signatureAlgorithm] is implemented.
  final String? algorithm;

  /// The configuration itself.
  final Map<String, dynamic> payload;

  /// Base64 detached signature over [signingBytes].
  final String? signature;

  const SignedConfigEnvelope({
    required this.configVersion,
    this.configId,
    this.issuedAt,
    this.expiresAt,
    this.keyId,
    this.algorithm,
    this.payload = const {},
    this.signature,
  });

  /// The only algorithm this SDK verifies. See
  /// `docs/SIGNED_SECURITY_CONFIGURATION.md` §2 for why Ed25519.
  static const String signatureAlgorithm = 'ed25519';

  /// `true` when the document claims to be signed at all. A document with no
  /// signature is legacy, not invalid.
  bool get isSigned => signature != null && signature!.isNotEmpty;

  /// Names carried as named, top-level signed fields rather than left inside
  /// [payload].
  ///
  /// **The signing contract**: `payload` is *only* the configuration values
  /// themselves (`block_on_threat`, `protection_policy`, …) — every one of
  /// these six names, plus `signature`/`integrity`, is excluded from it. A
  /// signer computes [signingBytes] over the actual config values under
  /// `payload` and the metadata under its own named fields; it must **not**
  /// duplicate the metadata inside `payload` too, and this SDK's own parsing
  /// does not either — see [fromConfig]. Getting the two sides of this
  /// contract to disagree is exactly the defect a security review must catch:
  /// it would make every legitimately-signed configuration fail verification.
  static const Set<String> _metadataFields = {
    'config_version',
    'config_id',
    'issued_at',
    'expires_at',
    'key_id',
    'algorithm',
  };

  /// `signature`/`integrity` additionally excluded from [payload] — a
  /// signature cannot cover itself.
  static const Set<String> _signatureFields = {'signature', 'integrity'};

  /// Parses an envelope out of a remote-config bundle.
  ///
  /// Additive and backward compatible: a bundle carrying none of the signing
  /// fields parses into an unsigned envelope, exactly as before.
  ///
  /// [configVersionOverride] exists because the backend sends `config_version`
  /// as a **sibling** of `remote_config`, not a member of it — reading it from
  /// the config map alone yields 0 on every real device. See
  /// `docs/SIGNED_SECURITY_CONFIGURATION_AUDIT.md` §4.
  static SignedConfigEnvelope fromConfig(
    Map<String, dynamic> config, {
    int? configVersionOverride,
  }) {
    DateTime? parseUtc(Object? value) {
      if (value is! String || value.isEmpty) return null;
      return DateTime.tryParse(value)?.toUtc();
    }

    String? str(Object? value) {
      if (value is! String) return null;
      final trimmed = value.trim();
      return trimmed.isEmpty ? null : trimmed;
    }

    final rawVersion = config['config_version'];
    // The signing contract (see `_metadataFields`) keeps metadata out of
    // `payload`. Stripped here so a real backend response — where
    // `config_version`/`key_id`/etc. sit as siblings of the actual config
    // values in the same JSON object — parses into exactly the payload a
    // signer would have signed, not a superset of it.
    final payloadOnly = <String, dynamic>{
      for (final entry in config.entries)
        if (!_metadataFields.contains(entry.key) &&
            !_signatureFields.contains(entry.key))
          entry.key: entry.value,
    };
    return SignedConfigEnvelope(
      configVersion:
          configVersionOverride ?? (rawVersion is num ? rawVersion.toInt() : 0),
      configId: str(config['config_id']),
      issuedAt: parseUtc(config['issued_at']),
      expiresAt: parseUtc(config['expires_at']),
      keyId: str(config['key_id']),
      algorithm: str(config['algorithm']),
      payload: payloadOnly,
      // `integrity` is accepted as a deprecated alias for `signature` so a
      // producer that already emits the previous milestone's field name keeps
      // working. New producers should emit `signature`.
      signature: str(config['signature']) ?? str(config['integrity']),
    );
  }

  /// The exact bytes that are signed and verified.
  ///
  /// [payload] is signed as-is — [fromConfig] is responsible for handing this
  /// class a payload that already excludes metadata, per the signing
  /// contract documented on [_metadataFields]. Re-stripping here as well
  /// would silently mask a caller that got the contract wrong (e.g. a test
  /// or a future producer passing a raw, un-stripped map) instead of
  /// producing bytes that visibly disagree with what a correct signer
  /// computed — which is the behaviour that makes the mismatch discoverable
  /// in testing rather than only in a production signature failure.
  Uint8List signingBytes() {
    return ConfigCanonicalizer.canonicalBytes(<String, Object?>{
      'algorithm': algorithm,
      'config_id': configId,
      'config_version': configVersion,
      'expires_at': expiresAt?.toUtc().toIso8601String(),
      'issued_at': issuedAt?.toUtc().toIso8601String(),
      'key_id': keyId,
      'payload': payload,
    });
  }
}

/// What a verification concluded, and why.
class SignedConfigVerification {
  final ConfigVerificationResult result;

  /// The key that verified the signature, when one did.
  final ConfigSigningKey? key;

  /// Human-readable category. Never contains key material or a signature.
  final String? detail;

  const SignedConfigVerification(this.result, {this.key, this.detail});

  bool get isAuthenticated => result.isAuthenticated;
}

/// Verifies signed security configuration.
///
/// ## Order of operations, and why it is this order
///
/// ```
///   structure → algorithm → key lookup → SIGNATURE → freshness → version
/// ```
///
/// Authenticity is checked **before** freshness, because a document that is
/// not authentic should never have its timestamps believed in the first place.
/// Freshness and version policy are checked **after**, because a valid
/// signature over an old document is precisely the attack a signature alone
/// does not stop — the brief's own requirement: *"Signature authenticity AND
/// freshness AND version policy must all pass."*
///
/// Everything except the Ed25519 primitive itself is pure; the primitive comes
/// from the `cryptography` package rather than being hand-rolled.
class SignedConfigVerifier {
  final ConfigTrustRoot trustRoot;

  /// Tolerance for a clock that runs behind the server's. A device whose clock
  /// is a few minutes slow must not reject a freshly-issued document.
  final Duration clockSkewTolerance;

  const SignedConfigVerifier({
    required this.trustRoot,
    this.clockSkewTolerance = const Duration(minutes: 5),
  });

  static final Ed25519 _ed25519 = Ed25519();

  /// Verifies [envelope] against the pinned trust root and freshness rules.
  ///
  /// [authenticationCache], when supplied, skips the expensive Ed25519
  /// primitive for an envelope whose signature was already checked — see
  /// [SignedConfigAuthenticationCache]'s doc comment for the exact,
  /// deterministic invalidation rule. Freshness and version policy are
  /// **never** cached: they depend on [now]/[heldVersion]/[heldConfigId] and
  /// are cheap pure comparisons, so they run fresh on every call regardless
  /// of a cache hit.
  ///
  /// Never throws: a thrown primitive becomes
  /// [ConfigVerificationResult.error], which is never treated as valid.
  Future<SignedConfigVerification> verify(
    SignedConfigEnvelope envelope, {
    required DateTime now,
    int? heldVersion,
    String? heldConfigId,
    SignedConfigAuthenticationCache? authenticationCache,
  }) async {
    try {
      return await _verify(
        envelope,
        now: now.toUtc(),
        heldVersion: heldVersion,
        heldConfigId: heldConfigId,
        authenticationCache: authenticationCache,
      );
    } catch (_) {
      return const SignedConfigVerification(
        ConfigVerificationResult.error,
        detail: 'verification raised',
      );
    }
  }

  Future<SignedConfigVerification> _verify(
    SignedConfigEnvelope envelope, {
    required DateTime now,
    int? heldVersion,
    String? heldConfigId,
    SignedConfigAuthenticationCache? authenticationCache,
  }) async {
    // ── Unsigned: a distinct state, never valid and never a hard failure ──
    if (!envelope.isSigned) {
      return const SignedConfigVerification(
        ConfigVerificationResult.legacyUnsigned,
        detail: 'configuration carries no signature',
      );
    }

    final authentication = await _authenticate(envelope, authenticationCache);
    if (!authentication.authentic) {
      return SignedConfigVerification(
        authentication.result,
        key: authentication.key,
        detail: authentication.detail,
      );
    }
    final key = authentication.key!;

    // ── Freshness. Authentic, but is it current? ─────────────────────────
    final expiresAt = envelope.expiresAt;
    if (expiresAt != null && !now.isBefore(expiresAt)) {
      return SignedConfigVerification(
        ConfigVerificationResult.expired,
        key: key,
        detail: 'signed configuration has expired',
      );
    }

    final issuedAt = envelope.issuedAt;
    if (issuedAt != null && issuedAt.isAfter(now.add(clockSkewTolerance))) {
      return SignedConfigVerification(
        ConfigVerificationResult.notYetValid,
        key: key,
        detail: 'signed configuration is issued beyond tolerated clock skew',
      );
    }

    // ── Version policy. Authentic and fresh, but is it the newest? ───────
    // A genuine, correctly-signed, unexpired document from last month is still
    // a downgrade if the device has already moved past it.
    if (envelope.configVersion <= 0) {
      return SignedConfigVerification(
        ConfigVerificationResult.malformed,
        key: key,
        detail: 'configuration carries no orderable version',
      );
    }
    if (heldVersion != null) {
      if (envelope.configVersion < heldVersion) {
        return SignedConfigVerification(
          ConfigVerificationResult.downgrade,
          key: key,
          detail: 'offered configuration is older than the one in force',
        );
      }
      if (envelope.configVersion == heldVersion &&
          heldConfigId != null &&
          heldConfigId.isNotEmpty &&
          envelope.configId != null &&
          envelope.configId != heldConfigId) {
        return SignedConfigVerification(
          ConfigVerificationResult.replay,
          key: key,
          detail: 'a different configuration reuses the version in force',
        );
      }
    }

    return SignedConfigVerification(
      ConfigVerificationResult.valid,
      key: key,
      detail: key.status == ConfigKeyStatus.next
          ? 'verified with the incoming rotation key'
          : null,
    );
  }

  /// The algorithm/key/signature portion only — everything up to but
  /// excluding freshness and version policy. This is the expensive, and the
  /// cacheable, part: the Ed25519 primitive measured at roughly 3-4ms per
  /// call (see `docs/SIGNED_SECURITY_CONFIGURATION.md` §10), against a scan
  /// budget of 8 **seconds** per detector — not urgent, but also not free to
  /// redo on every scan for a configuration that has not changed since the
  /// last one.
  Future<_Authentication> _authenticate(
    SignedConfigEnvelope envelope,
    SignedConfigAuthenticationCache? cache,
  ) async {
    final cacheKey = cache == null
        ? null
        : SignedConfigAuthenticationCache.keyFor(envelope, trustRoot);
    if (cacheKey != null) {
      final cached = cache!._get(cacheKey);
      if (cached != null) return cached;
    }
    final computed = await _authenticateUncached(envelope);
    if (cacheKey != null) cache!._put(cacheKey, computed);
    return computed;
  }

  Future<_Authentication> _authenticateUncached(
    SignedConfigEnvelope envelope,
  ) async {
    // ── Algorithm ────────────────────────────────────────────────────────
    // Checked before anything is decoded. Accepting a document that names an
    // algorithm we do not implement — or, worse, treating a missing/"none"
    // algorithm as permission to skip verification — is the classic
    // algorithm-confusion bug. A signed document must name its algorithm and
    // it must be the one we implement.
    final algorithm = envelope.algorithm?.toLowerCase();
    if (algorithm == null) {
      return const _Authentication.failed(
        ConfigVerificationResult.malformed,
        'signed configuration does not name an algorithm',
      );
    }
    if (algorithm != SignedConfigEnvelope.signatureAlgorithm) {
      return const _Authentication.failed(
        ConfigVerificationResult.unsupportedAlgorithm,
        'algorithm is not supported by this SDK build',
      );
    }

    // ── Key lookup, before any cryptography ──────────────────────────────
    // A signature is only meaningful against a key we already trust. Looking
    // the key up first also means an unknown key can never be reported as an
    // invalid signature, which would send an operator debugging the wrong
    // thing.
    final key = trustRoot.keyFor(envelope.keyId);
    if (key == null) {
      return const _Authentication.failed(
        ConfigVerificationResult.unknownKey,
        'signing key is not pinned in this SDK build',
      );
    }
    if (key.status == ConfigKeyStatus.revoked) {
      return _Authentication.failed(
        ConfigVerificationResult.unknownKey,
        'signing key has been revoked',
        key: key,
      );
    }

    // ── Signature ────────────────────────────────────────────────────────
    final Uint8List signatureBytes;
    try {
      signatureBytes = Uint8List.fromList(base64.decode(envelope.signature!));
    } catch (_) {
      return const _Authentication.failed(
        ConfigVerificationResult.malformed,
        'signature is not valid base64',
      );
    }
    // Ed25519 signatures are exactly 64 bytes. Rejecting other lengths up
    // front turns a truncated signature into `malformed` rather than relying
    // on the primitive to reject it.
    if (signatureBytes.length != 64) {
      return const _Authentication.failed(
        ConfigVerificationResult.malformed,
        'signature is not the expected length',
      );
    }

    final Uint8List message;
    try {
      message = envelope.signingBytes();
    } catch (_) {
      // A payload that cannot be canonicalized deterministically must fail,
      // not be verified over bytes the signer might have computed differently.
      return const _Authentication.failed(
        ConfigVerificationResult.malformed,
        'configuration has no canonical representation',
      );
    }

    final verified = await _ed25519.verify(
      message,
      signature: Signature(
        signatureBytes,
        publicKey: SimplePublicKey(key.publicKey, type: KeyPairType.ed25519),
      ),
    );
    if (!verified) {
      return _Authentication.failed(
        ConfigVerificationResult.invalidSignature,
        'signature does not match the signed configuration',
        key: key,
      );
    }

    return _Authentication.success(key);
  }
}

/// Internal outcome of the cacheable authentication step.
class _Authentication {
  final bool authentic;
  final ConfigSigningKey? key;
  final ConfigVerificationResult result;
  final String? detail;

  const _Authentication.success(ConfigSigningKey this.key)
      : authentic = true,
        result = ConfigVerificationResult.valid,
        detail = null;

  const _Authentication.failed(this.result, this.detail, {this.key})
      : authentic = false;
}

/// A small, deterministic cache for [SignedConfigVerifier]'s expensive
/// Ed25519 authentication step.
///
/// ## Invalidation rule — the only one that is safe here
///
/// The cache key is the signature itself, plus every field the signature
/// covers that isn't already baked into computing it (`key_id`, `algorithm`).
/// An Ed25519 signature cryptographically commits to the exact bytes it was
/// computed over — see [SignedConfigEnvelope.signingBytes] — so two envelopes
/// that produce the **same signature string** are, for any practical
/// adversary, the same signed document. Changing a single field (payload,
/// version, timestamps, key id) changes the signed bytes and therefore
/// changes the signature, which changes the cache key automatically. There is
/// no separate "is this still fresh" question for the *authentication*
/// result — only for freshness/version, which this cache never stores (see
/// [SignedConfigVerifier.verify]'s doc comment).
///
/// Bounded to a small number of entries — this SDK holds at most one
/// configuration in force at a time, plus perhaps one mid-rotation, so a
/// handful of entries is generous, not a real memory concern, and an eviction
/// under normal use should never happen.
class SignedConfigAuthenticationCache {
  static const int _maxEntries = 4;

  final Map<String, _Authentication> _entries = {};
  final List<String> _order = [];

  /// The cache key for [envelope] under [trustRoot].
  ///
  /// Includes an identity of the trust root (its key ids and statuses, not
  /// the key bytes — those are implied by key id) so a caller that swaps
  /// trust roots between calls — a test, or a host app reconfiguring keys —
  /// cannot get a stale hit from a different root.
  static String keyFor(SignedConfigEnvelope envelope, ConfigTrustRoot trustRoot) {
    final rootFingerprint = trustRoot.keys
        .map((k) => '${k.keyId}:${k.status.name}')
        .join(',');
    return '${envelope.signature}|${envelope.keyId}|${envelope.algorithm}|'
        '$rootFingerprint';
  }

  _Authentication? _get(String key) => _entries[key];

  void _put(String key, _Authentication value) {
    if (!_entries.containsKey(key)) {
      _order.add(key);
      if (_order.length > _maxEntries) {
        final evicted = _order.removeAt(0);
        _entries.remove(evicted);
      }
    }
    _entries[key] = value;
  }
}
