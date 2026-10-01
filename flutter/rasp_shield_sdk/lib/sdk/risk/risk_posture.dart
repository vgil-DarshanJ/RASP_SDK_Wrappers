/// Where a device sits on the 0–100 risk scale.
///
/// Bands exist so that a policy, a dashboard and an analyst all describe the
/// same device the same way. A raw score alone invites every caller to invent
/// its own cut-offs, and two surfaces disagreeing about whether 74 is
/// "elevated" is exactly the kind of inconsistency that erodes trust in a SOC
/// console.
///
/// The boundaries are **inclusive lower, exclusive upper**, except
/// [critical] which is closed at 100.
enum RiskPosture {
  /// 0–24. Nothing actionable found.
  trusted,

  /// 25–49. Something was found, but nothing that warrants friction.
  lowRisk,

  /// 50–74. Real findings; step-up or restriction is reasonable.
  elevated,

  /// 75–89. Strong evidence of compromise.
  highRisk,

  /// 90–100. Multiple corroborating signals, or a confirmed active attack.
  critical,
}

extension RiskPostureX on RiskPosture {
  /// Inclusive lower bound of this band.
  int get lowerBound {
    switch (this) {
      case RiskPosture.trusted:
        return 0;
      case RiskPosture.lowRisk:
        return 25;
      case RiskPosture.elevated:
        return 50;
      case RiskPosture.highRisk:
        return 75;
      case RiskPosture.critical:
        return 90;
    }
  }

  /// Inclusive upper bound of this band.
  int get upperBound {
    switch (this) {
      case RiskPosture.trusted:
        return 24;
      case RiskPosture.lowRisk:
        return 49;
      case RiskPosture.elevated:
        return 74;
      case RiskPosture.highRisk:
        return 89;
      case RiskPosture.critical:
        return 100;
    }
  }

  String get wireName => name;

  /// Ordering helper — higher means worse.
  int get rank => index;
}

/// The band a score falls into.
///
/// Scores outside 0–100 are clamped rather than rejected: this is the last
/// step before a security decision, and throwing here would turn a scoring bug
/// into an app crash. The risk engine already guarantees the range; this is
/// defence in depth.
RiskPosture postureForScore(int score) {
  final clamped = score.clamp(0, 100);
  if (clamped >= RiskPosture.critical.lowerBound) return RiskPosture.critical;
  if (clamped >= RiskPosture.highRisk.lowerBound) return RiskPosture.highRisk;
  if (clamped >= RiskPosture.elevated.lowerBound) return RiskPosture.elevated;
  if (clamped >= RiskPosture.lowRisk.lowerBound) return RiskPosture.lowRisk;
  return RiskPosture.trusted;
}
