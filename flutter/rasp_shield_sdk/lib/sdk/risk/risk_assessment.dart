import '../core/core.dart';
import 'correlation_rule.dart';
import 'risk_posture.dart';

/// One detector's contribution to the final score, kept for explainability.
///
/// The engine records *why* each detection mattered, so a decision can be
/// reconstructed rather than trusted. Without this a score is an unfalsifiable
/// number, and "why was I blocked?" has no answer.
class RiskContribution {
  final String detectorId;
  final DetectionSeverity severity;
  final DetectionConfidence confidence;

  /// Weight before confidence is applied.
  final int baseWeight;

  /// Weight after confidence, rounded — what actually entered the sum.
  final int effectiveWeight;

  /// How many separate results collapsed into this one contribution.
  ///
  /// Greater than 1 means duplicates were merged rather than summed — see
  /// [RiskAssessment] for why that distinction is load-bearing.
  final int mergedResults;

  const RiskContribution({
    required this.detectorId,
    required this.severity,
    required this.confidence,
    required this.baseWeight,
    required this.effectiveWeight,
    this.mergedResults = 1,
  });

  Map<String, Object?> toMap() => {
        'detector_id': detectorId,
        'severity': severity.name,
        'confidence': confidence.wireName,
        'base_weight': baseWeight,
        'effective_weight': effectiveWeight,
        if (mergedResults > 1) 'merged_results': mergedResults,
      };

  @override
  String toString() =>
      'RiskContribution($detectorId, $effectiveWeight/$baseWeight)';
}

/// The complete, explainable output of the risk engine.
///
/// Deliberately more than a number: [score] drives the policy decision, while
/// [contributions], [chains] and [reasons] are what make that decision
/// defensible to a customer, an auditor, or an engineer three months later.
class RiskAssessment {
  /// Overall risk, guaranteed to be within 0–100 inclusive.
  final int score;

  /// The band [score] falls into.
  final RiskPosture posture;

  /// Per-detector breakdown, strongest first.
  final List<RiskContribution> contributions;

  /// Attack chains that fired.
  final List<AttackChain> chains;

  /// Highest severity among conclusive threats, or `null` when none.
  final DetectionSeverity? highestSeverity;

  /// Overall confidence, from the strongest contributing detection.
  final DetectionConfidence? confidence;

  /// How many detectors could not reach a verdict.
  ///
  /// Reported separately from findings because a scan where half the detectors
  /// were `unknown` is not the same posture as one where they all reported
  /// clean, even though both yield zero threats. A caller that ignores this is
  /// treating absent coverage as safety.
  final int indeterminateCount;

  /// Total detectors considered.
  final int evaluatedCount;

  /// Short human-readable reasons, ordered by impact.
  final List<String> reasons;

  const RiskAssessment({
    required this.score,
    required this.posture,
    required this.contributions,
    required this.chains,
    required this.highestSeverity,
    required this.confidence,
    required this.indeterminateCount,
    required this.evaluatedCount,
    required this.reasons,
  });

  /// An assessment for a scan that produced nothing to act on.
  static const RiskAssessment none = RiskAssessment(
    score: 0,
    posture: RiskPosture.trusted,
    contributions: [],
    chains: [],
    highestSeverity: null,
    confidence: null,
    indeterminateCount: 0,
    evaluatedCount: 0,
    reasons: [],
  );

  /// `true` when at least one conclusive threat contributed.
  bool get hasFindings => contributions.isNotEmpty;

  /// Fraction of detectors that reached a verdict, 0.0–1.0.
  ///
  /// `1.0` means full coverage. A policy may reasonably refuse to trust a
  /// `trusted` posture that came with 30% coverage.
  double get coverage {
    if (evaluatedCount <= 0) return 0;
    final conclusive = evaluatedCount - indeterminateCount;
    return (conclusive / evaluatedCount).clamp(0.0, 1.0);
  }

  Map<String, Object?> toMap() => {
        'score': score,
        'posture': posture.wireName,
        'highest_severity': highestSeverity?.name,
        'confidence': confidence?.wireName,
        'evaluated_count': evaluatedCount,
        'indeterminate_count': indeterminateCount,
        'coverage': coverage,
        'contributions': contributions.map((c) => c.toMap()).toList(),
        'chains': chains.map((c) => c.toMap()).toList(),
        'reasons': reasons,
      };

  @override
  String toString() =>
      'RiskAssessment($score, ${posture.name}, ${chains.length} chains)';
}
