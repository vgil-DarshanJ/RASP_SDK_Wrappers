import '../risk/risk_posture.dart';
import 'protection_result.dart';

/// Compares the legacy [ProtectionEngine.evaluate] decision against the newer
/// [ProtectionEngine.evaluateWithRisk] decision for the **same** detections.
///
/// ## Why this exists
///
/// The brief requires proving the new pipeline "does not unexpectedly change
/// legitimate security decisions" before it becomes the default. A model
/// change that silently makes a customer's fleet stricter or looser overnight
/// is exactly the kind of regression a compiled-and-green test suite does not
/// catch on its own — the code can be correct in isolation and still change
/// production behaviour in a way nobody signed off on.
///
/// This is a pure comparison: it holds no state, calls nothing, and is safe to
/// run in a hot path (used for shadow evaluation in
/// `SecurityCenterController`) or in a test (used for the regression suite).
class ProtectionDecisionComparison {
  final ProtectionResult legacy;
  final ProtectionResult risk;

  const ProtectionDecisionComparison({required this.legacy, required this.risk});

  /// `true` when both pipelines recommend the same action.
  bool get actionsMatch => legacy.recommendedAction == risk.recommendedAction;

  /// Positive when the risk pipeline is **stricter** (a higher-numbered
  /// action) than the legacy one for this scan; negative when it is more
  /// lenient; zero when they agree.
  int get actionDelta =>
      risk.recommendedAction.index - legacy.recommendedAction.index;

  /// `true` when the risk pipeline recommends a *softer* action than the
  /// legacy pipeline for the same evidence.
  ///
  /// This is the comparison that actually matters for safety: a stricter
  /// disagreement is defensible (the risk pipeline sees corroboration and
  /// correlation the legacy scorer never modelled), but a device the legacy
  /// engine would have blocked and the risk engine now allows is a real
  /// regression and must be reviewed before any default switch.
  bool get riskPipelineIsMoreLenient => actionDelta < 0;

  /// Absolute difference between the two raw scores, 0–100 scale on both
  /// sides.
  int get scoreDelta => (risk.riskScore - legacy.riskScore).abs();

  /// A short, human-readable summary — what a reviewer reads when scanning a
  /// batch of comparisons for anything worth a closer look.
  String get summary {
    if (actionsMatch) {
      return 'MATCH action=${legacy.recommendedAction.name} '
          'scoreDelta=$scoreDelta';
    }
    final direction = riskPipelineIsMoreLenient ? 'LENIENT' : 'STRICTER';
    return 'DIFFER($direction) legacy=${legacy.recommendedAction.name}'
        '(${legacy.riskScore}) risk=${risk.recommendedAction.name}'
        '(${risk.riskScore})'
        '${risk.reasons.isNotEmpty ? ' reasons=${risk.reasons.take(2).join('; ')}' : ''}';
  }

  Map<String, Object?> toMap() => {
        'actions_match': actionsMatch,
        'action_delta': actionDelta,
        'more_lenient': riskPipelineIsMoreLenient,
        'score_delta': scoreDelta,
        'legacy_action': legacy.recommendedAction.name,
        'legacy_score': legacy.riskScore,
        'risk_action': risk.recommendedAction.name,
        'risk_score': risk.riskScore,
        'risk_posture': risk.posture.wireName,
      };

  @override
  String toString() => 'ProtectionDecisionComparison($summary)';
}

/// Aggregate statistics over many comparisons — what a migration reviewer
/// looks at before flipping a default, and what a shadow-evaluation run
/// accumulates over a session without ever affecting the live decision.
class ProtectionDecisionComparisonSummary {
  final int total;
  final int matching;
  final int stricter;
  final int lenient;
  final int maxScoreDelta;

  const ProtectionDecisionComparisonSummary({
    required this.total,
    required this.matching,
    required this.stricter,
    required this.lenient,
    required this.maxScoreDelta,
  });

  static const ProtectionDecisionComparisonSummary empty =
      ProtectionDecisionComparisonSummary(
    total: 0,
    matching: 0,
    stricter: 0,
    lenient: 0,
    maxScoreDelta: 0,
  );

  /// Fraction of comparisons where both pipelines agreed, 0.0–1.0.
  double get agreementRate => total == 0 ? 1.0 : matching / total;

  /// Builds a summary from a batch of comparisons.
  factory ProtectionDecisionComparisonSummary.of(
    Iterable<ProtectionDecisionComparison> comparisons,
  ) {
    var matching = 0, stricter = 0, lenient = 0, maxDelta = 0, total = 0;
    for (final c in comparisons) {
      total++;
      if (c.actionsMatch) {
        matching++;
      } else if (c.riskPipelineIsMoreLenient) {
        lenient++;
      } else {
        stricter++;
      }
      if (c.scoreDelta > maxDelta) maxDelta = c.scoreDelta;
    }
    return ProtectionDecisionComparisonSummary(
      total: total,
      matching: matching,
      stricter: stricter,
      lenient: lenient,
      maxScoreDelta: maxDelta,
    );
  }

  Map<String, Object?> toMap() => {
        'total': total,
        'matching': matching,
        'stricter': stricter,
        'lenient': lenient,
        'agreement_rate': agreementRate,
        'max_score_delta': maxScoreDelta,
      };
}
