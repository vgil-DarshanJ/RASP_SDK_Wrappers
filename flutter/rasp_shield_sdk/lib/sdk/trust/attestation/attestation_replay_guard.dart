import 'attestation_challenge.dart';
import 'attestation_result.dart';

/// Independently checks binding and freshness against an already-parsed
/// [AttestationResult] — the "do not trust a raw client-provided verdict"
/// layer, applied to the *normalized* result rather than the raw provider
/// payload (normalization/cryptographic authenticity is the parser's job;
/// this guard's job is binding and freshness, and it runs regardless of
/// which parser produced the result).
///
/// ## Why this exists even though the parser already normalizes
///
/// A provider can report `VALID` truthfully — the token really was genuine —
/// while still being wrong for *this* request: reused against an old
/// challenge, bound to a different package, or presented after its window
/// closed. Those are request-context failures, not authenticity failures,
/// and conflating them with the parser's job would make one class harder to
/// reason about than two. Mirrors `SignedConfigVerifier`'s own two-phase
/// split (authenticate, then freshness/version) for exactly the same reason.
class AttestationReplayGuard {
  const AttestationReplayGuard();

  /// Re-validates [result] against the [challenge] it should be bound to and
  /// the identity this device/app is expected to present.
  ///
  /// Returns a possibly-*downgraded* result: a provider-reported `valid` can
  /// come back `replayed`/`invalid`/`unknown` here, but a non-`valid` result
  /// is never upgraded — this guard only takes trust away, consistent with
  /// every other self-referential/binding check in this SDK
  /// (`TRUST_ANCHOR_MODEL.md` §2.3).
  ///
  /// [consumedNonces] models the server-side single-use ledger — passed in
  /// rather than owned here so this stays pure and testable; the real
  /// consumer (the backend's `attestation_challenges` table) is the
  /// authoritative ledger. See `attestation_router.py`.
  AttestationResult validate(
    AttestationResult result, {
    required AttestationChallenge challenge,
    required String expectedBundleId,
    required String expectedDeviceId,
    String? expectedCertificateFingerprint,
    Set<String> consumedNonces = const {},
    DateTime? now,
  }) {
    if (!result.status.isTrusted) {
      // Already not valid — nothing to take away, and never upgraded.
      return result;
    }

    final at = (now ?? DateTime.now()).toUtc();

    // ── Challenge binding ──────────────────────────────────────────────
    if (result.nonce == null || result.nonce != challenge.nonce) {
      return _downgrade(result, AttestationStatus.invalid,
          'attestation nonce does not match the issued challenge');
    }
    if (challenge.deviceId != expectedDeviceId) {
      // The challenge itself was not issued to this device — a caller error
      // or an attempted device-substitution, either way not valid here.
      return _downgrade(result, AttestationStatus.invalid,
          'challenge was not issued to this device');
    }
    if (challenge.bundleId != expectedBundleId) {
      return _downgrade(result, AttestationStatus.invalid,
          'challenge was not issued to this application');
    }

    // ── Replay ──────────────────────────────────────────────────────────
    if (consumedNonces.contains(challenge.nonce)) {
      return _downgrade(
          result, AttestationStatus.replayed, 'challenge nonce already consumed');
    }

    // ── Freshness ───────────────────────────────────────────────────────
    if (challenge.isExpired(now: at)) {
      return _downgrade(
          result, AttestationStatus.expired, 'challenge validity window has passed');
    }
    final timestamp = result.timestamp;
    if (timestamp != null && timestamp.toUtc().isAfter(challenge.expiresAt.toUtc())) {
      return _downgrade(result, AttestationStatus.expired,
          'attestation was produced after its challenge expired');
    }
    if (timestamp != null && timestamp.toUtc().isBefore(challenge.issuedAt.toUtc())) {
      // An attestation claiming to predate the challenge it is bound to has
      // no legitimate explanation — treated as unknown, not silently
      // accepted, per the same "never assume a benign clock skew" caution
      // the signed-config verifier applies to `notYetValid`.
      return _downgrade(result, AttestationStatus.unknown,
          'attestation timestamp predates its own challenge');
    }

    // ── Package / bundle identity ──────────────────────────────────────
    final observedPackage = result.packageIdentity;
    if (observedPackage != null && observedPackage != expectedBundleId) {
      return _downgrade(
          result, AttestationStatus.invalid, 'attested package identity does not match');
    }

    // ── Signing certificate ─────────────────────────────────────────────
    final expectedCert = expectedCertificateFingerprint;
    final observedCert = result.signingIdentity;
    if (expectedCert != null &&
        expectedCert.isNotEmpty &&
        observedCert != null &&
        observedCert.isNotEmpty &&
        _normalize(observedCert) != _normalize(expectedCert)) {
      return _downgrade(result, AttestationStatus.invalid,
          'attested signing certificate does not match');
    }

    // ── App / device integrity verdicts ─────────────────────────────────
    // The parser already turned a bad verdict into a non-valid status in the
    // common case; this is the belt-and-braces check for a provider-reported
    // valid whose integrity flags are explicitly false — never trusted just
    // because the envelope parsed.
    if (result.appIntegrity == false || result.deviceIntegrity == false) {
      return _downgrade(
          result, AttestationStatus.invalid, 'reported integrity verdict is negative');
    }

    return result;
  }

  static AttestationResult _downgrade(
    AttestationResult result,
    AttestationStatus status,
    String reason,
  ) =>
      AttestationResult(
        platform: result.platform,
        provider: result.provider,
        status: status,
        appIntegrity: result.appIntegrity,
        deviceIntegrity: result.deviceIntegrity,
        signingIdentity: result.signingIdentity,
        packageIdentity: result.packageIdentity,
        nonce: result.nonce,
        timestamp: result.timestamp,
        keyId: result.keyId,
        evidence: result.evidence,
        error: reason,
        providerConfidence: result.providerConfidence,
      );

  static String _normalize(String value) =>
      value.replaceAll(RegExp('[:\\s-]'), '').toUpperCase();
}
