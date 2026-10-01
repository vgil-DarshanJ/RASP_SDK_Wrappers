import '../core/core.dart';

/// A named combination of detections that means more together than apart.
///
/// ## Why a rule object and not an `if` ladder
///
/// The previous model expressed correlation as a fixed chain of `if`s over
/// five hardcoded detector ids inside the scoring function. That could not be
/// enumerated, could not be unit-tested in isolation, could not be extended
/// without editing the scorer, and could not explain itself to an analyst.
///
/// A rule is data. It can be listed on a settings screen, tested one at a
/// time, added by a future detector without touching the engine, and — most
/// importantly — **named** in the explanation the user or SOC sees. "Frida +
/// hook detected" is a finding; `INSTRUMENTATION_ATTACK` is a diagnosis.
///
/// ## Determinism
///
/// Matching is a pure function of the detector ids present, their confidence,
/// and nothing else. No clock, no I/O, no randomness — the same detections
/// always produce the same chains, which is what makes a security decision
/// reproducible from stored telemetry.
class CorrelationRule {
  /// Stable machine identifier, e.g. `INSTRUMENTATION_ATTACK`.
  final String id;

  /// Human-readable name for the SOC console.
  final String name;

  /// Detector ids that must **all** be present for this rule to fire.
  final Set<String> requiredSignals;

  /// Detector ids that strengthen the finding when present, but are not
  /// needed for it to fire. Each one raises the chain's confidence.
  final Set<String> optionalSignals;

  /// The lowest confidence a required detection may carry and still count.
  ///
  /// Stops a chain from being assembled out of guesses: `ROOT + FRIDA` is only
  /// `CRITICAL_RUNTIME_COMPROMISE` if both were actually established.
  final DetectionConfidence minimumConfidence;

  /// Severity of the *combination*, which is normally worse than any member.
  final DetectionSeverity severity;

  /// Points this chain adds to the risk score when it fires.
  ///
  /// Additive rather than multiplicative: a multiplier compounds with the
  /// number of members and makes the ceiling hard to reason about, whereas a
  /// bounded addition keeps the contribution of any single chain explicit and
  /// auditable.
  final int riskContribution;

  /// One sentence an analyst can act on.
  final String description;

  const CorrelationRule({
    required this.id,
    required this.name,
    required this.requiredSignals,
    required this.severity,
    required this.riskContribution,
    required this.description,
    this.optionalSignals = const {},
    this.minimumConfidence = DetectionConfidence.medium,
  });

  /// Whether this rule fires against [byDetectorId].
  ///
  /// Only *conclusive threat* detections are eligible. An `unavailable`,
  /// `unknown` or `error` result must never help assemble an attack chain —
  /// building a compromise narrative out of checks that did not run is how a
  /// RASP SDK produces a confident, entirely fabricated verdict.
  bool matches(Map<String, DetectionResult> byDetectorId) {
    for (final required in requiredSignals) {
      final detection = byDetectorId[required];
      if (detection == null) return false;
      if (!detection.threatDetected) return false;
      if (detection.confidence.rank < minimumConfidence.rank) return false;
    }
    return requiredSignals.isNotEmpty;
  }

  /// The optional signals that are also present as confirmed threats.
  Set<String> supportingSignalsIn(Map<String, DetectionResult> byDetectorId) =>
      optionalSignals
          .where((id) => byDetectorId[id]?.threatDetected == true)
          .toSet();
}

/// A rule that fired, with the evidence that made it fire.
class AttackChain {
  /// The rule that matched.
  final CorrelationRule rule;

  /// Required detector ids that were present.
  final Set<String> matchedSignals;

  /// Optional detector ids that were also present.
  final Set<String> supportingSignals;

  /// Confidence in the chain as a whole.
  ///
  /// Derived from the weakest required member — a chain is only as certain as
  /// its least certain link — then raised when optional signals corroborate.
  final DetectionConfidence confidence;

  const AttackChain({
    required this.rule,
    required this.matchedSignals,
    required this.supportingSignals,
    required this.confidence,
  });

  String get id => rule.id;
  DetectionSeverity get severity => rule.severity;
  int get riskContribution => rule.riskContribution;

  /// All detector ids involved, required and supporting.
  Set<String> get allSignals => {...matchedSignals, ...supportingSignals};

  Map<String, Object?> toMap() => {
        'chain_id': rule.id,
        'name': rule.name,
        'severity': rule.severity.name,
        'confidence': confidence.wireName,
        'risk_contribution': riskContribution,
        'matched_signals': matchedSignals.toList()..sort(),
        'supporting_signals': supportingSignals.toList()..sort(),
        'description': rule.description,
      };

  @override
  String toString() => 'AttackChain(${rule.id}, ${confidence.name})';
}
