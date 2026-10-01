import '../core/core.dart';
import 'correlation_engine.dart';
import 'correlation_rule.dart';
import 'risk_assessment.dart';
import 'risk_posture.dart';

/// Turns detections into an explainable 0–100 risk score.
///
/// ```
///   detections ─→ dedup ─→ severity × confidence ─→ correlate ─→ normalize
///                                                                    ↓
///                                                            RiskAssessment
/// ```
///
/// Pure and deterministic. No clock, no I/O, no shared mutable state — safe to
/// call concurrently, and reproducible from stored telemetry. The full model is
/// specified in `docs/RISK_SCORING_MODEL.md`.
///
/// ## Deduplication is the load-bearing property
///
/// Frida can be found by a file, a memory map, a thread name, a `LD_PRELOAD`
/// entry and a socket handshake. Those are five pieces of evidence for **one**
/// attack. Summing them would let a single compromise reach a critical score on
/// its own, and would mean adding a sixth Frida probe silently made every
/// instrumented device look worse without any change in reality.
///
/// So findings are folded by `detectorId`: multiple results for the same
/// detector **raise confidence, never the weight count**. That is the
/// difference between "we are more sure it is Frida" and "there are five
/// attacks".
class RiskEngine {
  /// Correlation used to detect attack chains.
  final CorrelationEngine correlationEngine;

  const RiskEngine({
    this.correlationEngine = const CorrelationEngine(),
  });

  /// Per-detector base weights, keyed by `detectorId`.
  ///
  /// Mirrors `ProtectionEngine.detectorWeights`, which in turn mirrors the
  /// backend scorer, so a device and the SOC console rank the same threats the
  /// same way. Detectors absent here fall back to their severity — see
  /// [_baseWeightFor].
  static const Map<String, int> detectorWeights = {
    'clone': 90,
    'frida': 80,
    're_tools': 70,
    'tamper': 60,
    'repackage': 60,
    'root_jailbreak': 50,
    'debugger': 40,
    'emulator': 30,
    'overlay': 25,
    'accessibility': 25,
    'mitm': 20,
    'vpn': 15,
    'screenshot_protection': 10,
    'untrusted_install_source': 35,
    'adb_enabled': 20,
    'device_lock_missing': 20,
    'developer_mode': 10,
    'secure_hardware_unavailable': 10,
    'hook_detection': 70,

    // Risk + Response Engine milestone: explicit entry, not left to the
    // severity fallback. `ExternalDisplayDetector`'s own doc states it
    // reports a non-default display's *presence*, never confirmation that
    // this app's content is actually being mirrored there — the same
    // weaker-confidence character as `screenshot_protection` (10), not the
    // stronger evidence a `medium`-severity fallback (25) would imply.
    // `risky_app` is deliberately left on the severity fallback: its own
    // detector already assigns `medium`/`low`-confidence for capability-only
    // evidence vs. `high` for a named risky package, and a flat weight here
    // would flatten a distinction the detector went out of its way to make.
    'external_display': 10,
  };

  /// Fallback weight when a detector has no explicit entry.
  static const Map<DetectionSeverity, int> severityWeights = {
    DetectionSeverity.low: 10,
    DetectionSeverity.medium: 25,
    DetectionSeverity.high: 50,
    DetectionSeverity.critical: 80,
  };

  /// Raw score that maps to 100. Matches the backend scorer's CRITICAL floor,
  /// so the device's normalized score and the console's raw score agree about
  /// what "critical" means.
  static const int criticalFloor = 150;

  static int _baseWeightFor(DetectionResult detection) =>
      detectorWeights[detection.detectorId] ??
      severityWeights[detection.severity] ??
      10;

  /// Evaluates [detections] into a complete [RiskAssessment].
  ///
  /// Only conclusive threats contribute. `unavailable`, `unknown` and `error`
  /// are counted toward [RiskAssessment.indeterminateCount] and contribute
  /// **zero** score — a check that did not run is neither a threat nor
  /// reassurance.
  RiskAssessment evaluate(List<DetectionResult> detections) {
    if (detections.isEmpty) return RiskAssessment.none;

    var indeterminate = 0;
    final threatsById = <String, List<DetectionResult>>{};

    for (final detection in detections) {
      if (detection.status.isIndeterminate) {
        indeterminate++;
        continue;
      }
      if (!detection.threatDetected) continue;
      threatsById.putIfAbsent(detection.detectorId, () => []).add(detection);
    }

    final contributions = <RiskContribution>[];
    var rawScore = 0;

    threatsById.forEach((detectorId, results) {
      final merged = _merge(results);
      final baseWeight = _baseWeightFor(merged);
      final effective = (baseWeight * merged.confidence.multiplier).round();
      rawScore += effective;
      contributions.add(RiskContribution(
        detectorId: detectorId,
        severity: merged.severity,
        confidence: merged.confidence,
        baseWeight: baseWeight,
        effectiveWeight: effective,
        mergedResults: results.length,
      ));
    });

    final chains = correlationEngine.correlate(detections);
    for (final chain in chains) {
      rawScore += chain.riskContribution;
    }

    contributions.sort((a, b) {
      final byWeight = b.effectiveWeight.compareTo(a.effectiveWeight);
      if (byWeight != 0) return byWeight;
      return a.detectorId.compareTo(b.detectorId);
    });

    final score = _normalize(rawScore);
    return RiskAssessment(
      score: score,
      posture: postureForScore(score),
      contributions: List.unmodifiable(contributions),
      chains: chains,
      highestSeverity: _highestSeverity(contributions),
      confidence: _overallConfidence(contributions),
      indeterminateCount: indeterminate,
      evaluatedCount: detections.length,
      reasons: _reasons(contributions, chains, indeterminate),
    );
  }

  /// Folds several results for one detector into a single finding.
  ///
  /// Takes the worst severity seen, and raises confidence by one step for each
  /// additional independent result — capped at [DetectionConfidence.veryHigh].
  /// Evidence accumulates so nothing is lost from the report.
  static DetectionResult _merge(List<DetectionResult> results) {
    var worst = results.first;
    for (final result in results.skip(1)) {
      if (result.severity.index > worst.severity.index) worst = result;
    }
    final boosted =
        (worst.confidence.rank + (results.length - 1)).clamp(0, DetectionConfidence.values.length - 1);
    final evidence = [for (final r in results) ...r.evidence];
    return worst.copyWith(
      confidence: DetectionConfidence.values[boosted],
      evidence: evidence,
    );
  }

  /// Maps a raw weight sum onto 0–100.
  ///
  /// Linear against [criticalFloor], then clamped. The clamp is what makes the
  /// range a guarantee rather than an expectation: no number of detectors or
  /// chains can push the score past 100, and no negative weight can drive it
  /// below 0.
  static int _normalize(int rawScore) {
    if (rawScore <= 0) return 0;
    final normalized = (rawScore * 100 / criticalFloor).round();
    return normalized.clamp(0, 100);
  }

  static DetectionSeverity? _highestSeverity(List<RiskContribution> items) {
    DetectionSeverity? worst;
    for (final item in items) {
      if (worst == null || item.severity.index > worst.index) {
        worst = item.severity;
      }
    }
    return worst;
  }

  static DetectionConfidence? _overallConfidence(List<RiskContribution> items) {
    DetectionConfidence? best;
    for (final item in items) {
      if (best == null || item.confidence.rank > best.rank) {
        best = item.confidence;
      }
    }
    return best;
  }

  /// Human-readable reasons, chains first because a named attack explains more
  /// than the individual findings that compose it.
  static List<String> _reasons(
    List<RiskContribution> contributions,
    List<AttackChain> chains,
    int indeterminate,
  ) {
    final reasons = <String>[
      for (final chain in chains) '${chain.rule.name} (${chain.rule.id})',
      for (final c in contributions.take(5))
        '${c.detectorId} detected (${c.severity.name}, ${c.confidence.name} confidence)',
    ];
    if (indeterminate > 0) {
      reasons.add(
          '$indeterminate check(s) could not reach a verdict — coverage is incomplete');
    }
    return List.unmodifiable(reasons);
  }
}
