import '../risk/risk_posture.dart';
import '../trust/trust_assessment.dart';
import 'compatibility_decision.dart';
import 'pipeline_mode.dart';
import 'protection_action.dart';
import 'protection_result.dart';

/// Deterministic classification of how the two pipelines related for one
/// scan — Phase 9 of the Backend Rollout milestone.
///
/// Every observation carries exactly one of these. Nothing is silently
/// discarded: an error, an unavailable pipeline, and a genuine disagreement
/// are each their own category rather than being collapsed into "other".
enum RolloutDisagreement {
  /// Both pipelines recommended the same action.
  legacyEquivalent,

  /// The risk pipeline recommended a stricter action than legacy.
  riskStricter,

  /// The legacy pipeline recommended a stricter action than risk.
  legacyStricter,

  /// The risk pipeline could not be evaluated (threw, or was disabled).
  riskError,

  /// The legacy pipeline could not be evaluated. Not reachable from
  /// `SecurityCenterController` today — legacy always runs first — but a
  /// category exists so the case is never silently miscounted as something
  /// else if it ever becomes reachable.
  legacyError,

  /// A trust anchor was contradicted (`TrustLevel.compromised`/`suspicious`).
  /// Takes precedence over the action comparison, because *why* the
  /// pipelines diverged matters more to an operator than *that* they did.
  trustFailure,

  /// The trust assessment could not be produced at all, or reported
  /// `TrustLevel.unknown` — configuration/collection did not complete.
  configFailure,

  /// Neither pipeline produced a usable result, or the state could not be
  /// classified.
  unknownState,
}

extension RolloutDisagreementX on RolloutDisagreement {
  /// Stable `SCREAMING_SNAKE_CASE` wire name, matching the categories the
  /// backend's `risk_pipeline_observations.disagreement` column stores and
  /// `GET /licensing/risk-pipeline/metrics` aggregates by.
  ///
  /// Derived from the enum name rather than hand-written per case, so a new
  /// category cannot ship with a typo'd or duplicated wire name — the same
  /// approach `TrustEvidenceCode.wireName` already uses.
  String get wireName =>
      name.replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}').toUpperCase();
}

/// One rollout decision, reduced to exactly what the backend records.
///
/// ## What this deliberately does not carry
///
/// No licence key, activation token, attestation token, device fingerprint,
/// GPS fix, or any other personal information — see
/// `docs/RISK_PIPELINE_MONITORING.md`. The authentication fields the
/// transport needs (`license_key_hash`, `activation_token`) are added by the
/// reporter at send time and are never stored on this object.
class RolloutObservation {
  final PipelineMode mode;
  final ProtectionAction legacyAction;
  final ProtectionAction? riskAction;
  final ProtectionAction finalAction;
  final RolloutDisagreement disagreement;
  final String? riskPosture;
  final int detectorCount;
  final String sdkVersion;
  final String? trustLevel;

  const RolloutObservation({
    required this.mode,
    required this.legacyAction,
    required this.riskAction,
    required this.finalAction,
    required this.disagreement,
    required this.riskPosture,
    required this.detectorCount,
    required this.sdkVersion,
    required this.trustLevel,
  });

  /// Classifies one scan.
  ///
  /// Precedence is deliberate and documented rather than emergent:
  ///
  /// 1. A missing/unknown trust assessment → [configFailure] — the
  ///    collection step did not complete, so any action comparison is
  ///    being made on incomplete inputs and saying "they agreed" would
  ///    overstate what was actually verified.
  /// 2. A contradicted trust anchor → [trustFailure] — *why* they diverged.
  /// 3. Only then, the action comparison itself.
  ///
  /// Never throws and always returns a category — [unknownState] is the
  /// total fallback, not an omission.
  static RolloutDisagreement classify({
    required ProtectionResult? legacy,
    required ProtectionResult? risk,
    required TrustAssessment? trust,
  }) {
    if (legacy == null && risk == null) return RolloutDisagreement.unknownState;
    if (legacy == null) return RolloutDisagreement.legacyError;

    if (trust == null || trust.level == TrustLevel.unknown) {
      return RolloutDisagreement.configFailure;
    }
    if (trust.level == TrustLevel.compromised ||
        trust.level == TrustLevel.suspicious) {
      return RolloutDisagreement.trustFailure;
    }

    if (risk == null) return RolloutDisagreement.riskError;

    final delta =
        risk.recommendedAction.index - legacy.recommendedAction.index;
    if (delta == 0) return RolloutDisagreement.legacyEquivalent;
    return delta > 0
        ? RolloutDisagreement.riskStricter
        : RolloutDisagreement.legacyStricter;
  }

  /// Builds an observation from one completed scan, or `null` when there is
  /// nothing to report.
  ///
  /// Returns `null` for [PipelineMode.legacy]: a device with no risk
  /// comparison has no observation to make, and the backend rejects a
  /// `legacy` observation outright (`RiskPipelineObservation`'s pattern).
  static RolloutObservation? from({
    required PipelineMode mode,
    required ProtectionResult? legacy,
    required ProtectionResult? risk,
    required CompatibilityDecision? compatibility,
    required TrustAssessment? trust,
    required String sdkVersion,
    required int detectorCount,
  }) {
    if (mode == PipelineMode.legacy) return null;
    if (legacy == null) return null;

    return RolloutObservation(
      mode: mode,
      legacyAction: legacy.recommendedAction,
      riskAction: risk?.recommendedAction,
      // In SHADOW the final action IS legacy's, by definition. In
      // COMPATIBILITY it is the reconciled decision — falling back to
      // legacy's if the decision is somehow absent, which matches what
      // `SecurityCenterController` actually leaves `protection` as.
      finalAction: mode == PipelineMode.compatibility
          ? (compatibility?.action ?? legacy.recommendedAction)
          : legacy.recommendedAction,
      disagreement: classify(legacy: legacy, risk: risk, trust: trust),
      riskPosture: risk?.posture.wireName,
      detectorCount: detectorCount,
      sdkVersion: sdkVersion,
      trustLevel: trust?.level.wireName,
    );
  }

  /// The request body for `POST /api/v1/sdk/risk-pipeline/observation`,
  /// minus the authentication fields the reporter adds.
  Map<String, Object?> toMap() => {
        'rollout_mode': mode.wireName,
        'legacy_action': legacyAction.wireName,
        'risk_action': riskAction?.wireName,
        'final_action': finalAction.wireName,
        'disagreement': disagreement.wireName,
        'risk_posture': riskPosture,
        'detector_count': detectorCount,
        'sdk_version': sdkVersion,
        'trust_level': trustLevel,
      };

  @override
  String toString() =>
      'RolloutObservation(${mode.wireName}, ${disagreement.wireName}, '
      'legacy=${legacyAction.name}, final=${finalAction.name})';
}
