import '../core/core.dart';
import '../risk/risk_assessment.dart';
import '../risk/risk_posture.dart';
import 'protection_action.dart';

/// The outcome of one Protection Engine evaluation.
///
/// Carries both the **verdict** and the **evidence it was reached from**:
/// the recommended action, the score behind it, the highest severity seen,
/// and the full list of detections considered. A host app that only wants to
/// act reads [recommendedAction]; a SOC surface that has to justify the
/// decision to an analyst reads [detections] and [riskScore] alongside it.
/// Nothing is discarded, so a decision is never unexplainable after the
/// fact.
///
/// Plain data, like everything else in `sdk/core/` — no UI types, no
/// behavior. Producing a `ProtectionResult` changes nothing on its own; the
/// host application decides what to do with it.
class ProtectionResult {
  /// Overall risk for this evaluation, `0`–`100`. See
  /// `ProtectionEngine.riskScore` for the intended scale.
  final int riskScore;

  /// What the engine recommends the host application do. Always an action
  /// the evaluating `ProtectionPolicy` permits.
  final ProtectionAction recommendedAction;

  /// The highest [DetectionSeverity] among [detections], or `null` when
  /// nothing was detected.
  final DetectionSeverity? highestSeverity;

  /// Every detection this evaluation considered — including ones the policy
  /// suppressed from the decision, so the record stays complete.
  final List<DetectionResult> detections;

  /// When this evaluation ran, in UTC.
  final DateTime evaluatedAt;

  /// The `ProtectionPolicy.version` this decision was made under.
  ///
  /// Carried so a SOC analyst reviewing an action months later can tell
  /// *which* rules produced it. Without this, a policy change silently
  /// rewrites the meaning of every historical decision.
  final int policyVersion;

  /// The risk band [riskScore] falls into.
  ///
  /// Carried alongside the number so every surface — device UI, portal, SOC
  /// console — describes the same device with the same word instead of each
  /// inventing its own cut-offs.
  final RiskPosture posture;

  /// Ordered, human-readable reasons this decision was reached.
  ///
  /// A security action a user cannot have explained to them is a support
  /// ticket. This is what turns "blocked" into "blocked because Frida and
  /// hooking were detected together".
  final List<String> reasons;

  /// The full risk breakdown, when the evaluation used the risk engine.
  ///
  /// `null` for evaluations made through the legacy path, which is preserved
  /// unchanged for backward compatibility.
  final RiskAssessment? assessment;

  /// Creates an evaluation outcome.
  const ProtectionResult({
    required this.riskScore,
    required this.recommendedAction,
    this.highestSeverity,
    this.detections = const [],
    required this.evaluatedAt,
    this.policyVersion = 0,
    this.posture = RiskPosture.trusted,
    this.reasons = const [],
    this.assessment,
  });

  /// `true` when the evidence behind [recommendedAction] is too incomplete
  /// to trust, and a fresh scan — not a stronger verdict — is the right
  /// response.
  ///
  /// Deliberately **not** a value on [ProtectionAction]. Every existing
  /// action describes how much the app is restricted, in a single
  /// escalating ladder that a dozen call sites compare with `.index`
  /// (offline fallback floors, remote-policy ceilings, per-detector floors —
  /// see `ProtectionEngine`, `ProtectionPolicy`, `SecurityPolicyProfile`).
  /// "Ask for better evidence" is not a rung on that ladder — it can be the
  /// right response at `allow` (nothing conclusive yet) just as easily as at
  /// `monitor`, and splicing a new value into an enum every one of those
  /// sites treats as strictly ordered would silently change what every
  /// existing floor/ceiling/offline comparison means. Modelled instead as an
  /// orthogonal signal a caller reads *alongside* [recommendedAction] — see
  /// `RaspShield._runProtectionScan`'s bounded, non-recursive rescan.
  ///
  /// `true` only when the engine actually ran (there is a real
  /// [assessment]), evidence was genuinely incomplete
  /// (`assessment.indeterminateCount > 0`), and nothing already earned a
  /// stronger verdict than [ProtectionAction.monitor] — an evaluation severe
  /// enough to warn/block/lock already has enough signal to act on; asking
  /// for a rescan on top of that would only delay a decision the evidence
  /// already supports.
  bool get recommendRescan {
    final a = assessment;
    if (a == null) return false;
    if (a.indeterminateCount <= 0) return false;
    return recommendedAction.index <= ProtectionAction.monitor.index;
  }

  /// Detections that could not run — neither threats nor clean results.
  /// Surfaced so an integrator can see coverage gaps rather than mistaking
  /// them for passing checks.
  List<DetectionResult> get unavailable =>
      detections.where((d) => !d.isConclusive).toList();

  /// An evaluation that found nothing actionable. Distinct from "no
  /// evaluation happened" — a caller holding this knows the engine ran and
  /// came back clean.
  factory ProtectionResult.clean({DateTime? evaluatedAt}) => ProtectionResult(
        riskScore: 0,
        recommendedAction: ProtectionAction.allow,
        evaluatedAt: evaluatedAt ?? DateTime.now().toUtc(),
      );

  /// The subset of [detections] that actually reported a threat.
  List<DetectionResult> get threats =>
      detections.where((d) => d.threatDetected && d.isConclusive).toList();

  /// `true` when at least one detection reported a threat.
  bool get hasThreat =>
      detections.any((d) => d.threatDetected && d.isConclusive);

  /// Plain-map form for logging, diagnostics, or JSON encoding.
  Map<String, Object?> toMap() => {
        'risk_score': riskScore,
        'recommended_action': recommendedAction.name,
        'highest_severity': highestSeverity?.name,
        'detections': detections.map((d) => d.toMap()).toList(),
        'evaluated_at': evaluatedAt.toIso8601String(),
        'policy_version': policyVersion,
        'posture': posture.wireName,
        'reasons': reasons,
        if (assessment != null) 'assessment': assessment!.toMap(),
      };

  @override
  String toString() => 'ProtectionResult(score=$riskScore, '
      'posture=${posture.name}, action=${recommendedAction.name}, '
      'threats=${threats.length})';
}
