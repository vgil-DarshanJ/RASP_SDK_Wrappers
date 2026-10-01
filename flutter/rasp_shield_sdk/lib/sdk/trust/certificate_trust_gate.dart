import 'config_signing_keys.dart';
import 'signed_config_verifier.dart';

/// Whether a delivered configuration's certificate expectations are
/// authoritative — the state Phase 6/7 of the Backend Signed Configuration
/// milestone requires be represented explicitly, not inferred.
///
/// Deliberately reuses [ConfigVerificationResult]'s vocabulary rather than
/// inventing a parallel one — see [certificateTrustSourceStateFor]'s doc
/// comment for why a second trust/confidence model was avoided here, per the
/// project's standing rule against exactly that.
enum CertificateTrustSourceState {
  /// Signature valid, fresh, and in-order. Certificate expectations from this
  /// configuration may become authoritative.
  authentic,

  /// No signature, an invalid one, an unrecognised key, or an unsupported
  /// algorithm. The configuration was **not proven to come from the
  /// operator** — its certificate expectations must not be trusted.
  unauthenticated,

  /// Authentic once, but its validity window has passed.
  expired,

  /// Authentic, but this exact version/document pairing was already seen —
  /// a replay of an old, otherwise-genuine response.
  replayed,

  /// Authentic, but older than the version already in force.
  downgraded,

  /// Structurally unusable, or issued outside tolerated clock skew — neither
  /// provably authentic nor provably forged.
  unknown,

  /// No configuration, or no verification was ever attempted (e.g. the
  /// config carried no signature and there is nothing to gate on).
  unavailable,

  /// Verification itself failed to complete.
  error,
}

/// Semantics for [CertificateTrustSourceState].
extension CertificateTrustSourceStateX on CertificateTrustSourceState {
  /// The single state in which certificate expectations from this
  /// configuration may be used. **The only `true`** — every other value,
  /// including `unauthenticated`, must leave the certificate trust store
  /// exactly as it was (empty, if nothing else has populated it), never
  /// "trusted because we could not prove otherwise."
  bool get maysPopulateCertificateTrust =>
      this == CertificateTrustSourceState.authentic;

  String get wireName => name.toUpperCase();
}

/// Maps a [SignedConfigVerification] (or its absence) onto
/// [CertificateTrustSourceState].
///
/// ## Why this is a mapping, not a new trust model
///
/// `ConfigVerificationResult` already distinguishes every failure mode this
/// gate needs (`invalidSignature`, `unknownKey`, `expired`, `replay`,
/// `downgrade`, …) — see `signed_config_verifier.dart`. Introducing a second,
/// independent enum with its own verification logic would be exactly the
/// "second trust/confidence model" this project's standing convention
/// forbids (`TRUST_ANCHOR_MODEL.md`, `SIGNED_SECURITY_CONFIGURATION.md`).
/// This function is a pure, total, one-way projection from the existing
/// result vocabulary onto the coarser 8-state vocabulary Phase 7 of this
/// milestone asks be represented explicitly — nothing here re-derives a
/// verdict.
CertificateTrustSourceState certificateTrustSourceStateFor(
  SignedConfigVerification? verification,
) {
  if (verification == null) return CertificateTrustSourceState.unavailable;

  switch (verification.result) {
    case ConfigVerificationResult.valid:
      return CertificateTrustSourceState.authentic;

    case ConfigVerificationResult.legacyUnsigned:
    case ConfigVerificationResult.invalidSignature:
    case ConfigVerificationResult.unknownKey:
    case ConfigVerificationResult.unsupportedAlgorithm:
      // Never a signature failure becoming a trusted certificate — each of
      // these is a distinct reason the configuration was not proven
      // authentic, folded into one state because the consequence (do not
      // gate) is identical for all four. The distinguishing evidence code
      // (CONFIG_SIGNATURE_INVALID / CONFIG_UNKNOWN_KEY / …) is still
      // available on the securityConfiguration trust anchor for anyone who
      // needs to tell them apart.
      return CertificateTrustSourceState.unauthenticated;

    case ConfigVerificationResult.expired:
      return CertificateTrustSourceState.expired;

    case ConfigVerificationResult.replay:
      return CertificateTrustSourceState.replayed;

    case ConfigVerificationResult.downgrade:
      return CertificateTrustSourceState.downgraded;

    case ConfigVerificationResult.malformed:
    case ConfigVerificationResult.notYetValid:
      return CertificateTrustSourceState.unknown;

    case ConfigVerificationResult.error:
      return CertificateTrustSourceState.error;
  }
}
