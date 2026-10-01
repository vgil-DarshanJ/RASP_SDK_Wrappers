import '../trust_anchor.dart';
import '../trust_evidence.dart';
import 'attestation_result.dart';

/// Outcome of judging an [AttestationResult] as a trust anchor.
class AttestationTrustVerdict {
  final TrustAnchorState state;
  final List<TrustEvidence> evidence;

  const AttestationTrustVerdict({required this.state, this.evidence = const []});
}

/// Maps [AttestationResult] onto the shared [TrustAnchorState] vocabulary.
///
/// A pure, total, one-way projection — the same pattern
/// `certificateTrustSourceStateFor` already uses to avoid a second trust
/// model. `AttestationStatus` is richer (7 states, provider-shaped);
/// `TrustAnchorState` is the coarser 6-state vocabulary every anchor reports
/// through. Nothing here re-derives a verdict — [AttestationReplayGuard] and
/// the provider parsers already decided the [AttestationResult]; this only
/// translates it.
class AttestationTrustEvaluator {
  const AttestationTrustEvaluator();

  AttestationTrustVerdict evaluate(AttestationResult? result) {
    if (result == null) {
      return const AttestationTrustVerdict(
        state: TrustAnchorState.unavailable,
        evidence: [TrustEvidence(TrustEvidenceCode.attestationUnavailable)],
      );
    }

    switch (result.status) {
      case AttestationStatus.valid:
        return const AttestationTrustVerdict(state: TrustAnchorState.valid);

      case AttestationStatus.invalid:
        return AttestationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [_evidenceFor(result)],
        );

      case AttestationStatus.expired:
        return const AttestationTrustVerdict(
          state: TrustAnchorState.expired,
          evidence: [TrustEvidence(TrustEvidenceCode.attestationExpired)],
        );

      case AttestationStatus.replayed:
        return const AttestationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [TrustEvidence(TrustEvidenceCode.attestationReplayed)],
        );

      case AttestationStatus.unknown:
        return const AttestationTrustVerdict(
          state: TrustAnchorState.unknown,
          evidence: [TrustEvidence(TrustEvidenceCode.attestationUnknown)],
        );

      case AttestationStatus.unavailable:
        return const AttestationTrustVerdict(
          state: TrustAnchorState.unavailable,
          evidence: [TrustEvidence(TrustEvidenceCode.attestationUnavailable)],
        );

      case AttestationStatus.error:
        return const AttestationTrustVerdict(
          state: TrustAnchorState.error,
          evidence: [TrustEvidence(TrustEvidenceCode.attestationError)],
        );
    }
  }

  /// Picks the most specific evidence code for an `invalid` result — the
  /// error string set by `AttestationReplayGuard` names *why*, and this
  /// reads it back into a stable code rather than free text, without the
  /// replay guard needing to know about `TrustEvidenceCode` at all (keeping
  /// the attestation package free of a `trust/` dependency except this one
  /// integration file).
  TrustEvidence _evidenceFor(AttestationResult result) {
    final reason = result.error ?? '';
    if (reason.contains('package')) {
      return const TrustEvidence(TrustEvidenceCode.attestationPackageMismatch);
    }
    if (reason.contains('certificate')) {
      return const TrustEvidence(TrustEvidenceCode.attestationCertificateMismatch);
    }
    if (reason.contains('challenge') || reason.contains('nonce')) {
      return const TrustEvidence(TrustEvidenceCode.attestationChallengeMismatch);
    }
    return const TrustEvidence(TrustEvidenceCode.attestationInvalid);
  }
}
