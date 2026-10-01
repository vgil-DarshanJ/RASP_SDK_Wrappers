/// How much a detector's verdict should be trusted.
///
/// ## Why confidence is separate from severity
///
/// Severity answers *"how bad is this if true?"*; confidence answers *"how
/// sure are we that it is true?"*. Collapsing them loses the distinction
/// between a definite low-severity finding and a doubtful critical one — and
/// those deserve opposite responses. A `medium`-severity emulator verdict from
/// three independent native signals is more actionable than a `critical`
/// Frida verdict resting on one filename.
///
/// Before this existed, a detection contributed the same weight regardless of
/// how it was reached, so a single spoofable `Build` field counted exactly as
/// much as a D-Bus handshake with a live Frida server.
///
/// ## The scale is ordinal, not probabilistic
///
/// [multiplier] is a **policy weight**, not a likelihood. The SDK has no
/// calibration data from real attacks, so no claim of statistical accuracy is
/// made — see `docs/RISK_SCORING_MODEL.md`. The numbers exist so that "more
/// independent evidence outranks less" is expressed consistently rather than
/// re-invented per detector.
enum DetectionConfidence {
  /// One weak or individually-explainable signal. A `Build` field, a merely
  /// open port, a thread name that a legitimate library also uses.
  low,

  /// One signal that is hard to forge, or two weak ones agreeing.
  medium,

  /// Two or more independent signal families agreeing.
  high,

  /// Several independent families, or one signal that observes the attack's
  /// own mechanism (a live protocol handshake, a hooked method entry point).
  veryHigh,
}

/// Weighting and derivation helpers.
extension DetectionConfidenceX on DetectionConfidence {
  /// Multiplier applied to a finding's severity weight.
  ///
  /// Deliberately never `0` — a low-confidence detection is still a detection
  /// and must not be silently discarded — and never `> 1.0`, so confidence can
  /// only ever *discount* a finding, never manufacture risk that the severity
  /// model did not already allow. That one-sidedness is what keeps the score
  /// bounded without a second clamp.
  double get multiplier {
    switch (this) {
      case DetectionConfidence.low:
        return 0.4;
      case DetectionConfidence.medium:
        return 0.7;
      case DetectionConfidence.high:
        return 0.9;
      case DetectionConfidence.veryHigh:
        return 1.0;
    }
  }

  /// Stable wire/display name.
  String get wireName => name;

  /// Ordering helper — higher means more trustworthy.
  int get rank => index;
}

/// Derives a confidence level from how many **independent** evidence sources
/// agree.
///
/// "Independent" means different signal families — filesystem, memory map,
/// thread table, network. Three filesystem paths are one family, not three
/// sources; counting them separately is exactly the duplicate-inflation
/// mistake the risk engine exists to prevent.
///
/// The mapping is intentionally conservative: a single source never exceeds
/// [DetectionConfidence.medium], no matter how convincing it looks in
/// isolation, because a single mechanism is also a single point of bypass.
DetectionConfidence confidenceFromSources(
  int independentSources, {
  bool hasHardSignal = false,
}) {
  if (independentSources <= 0) return DetectionConfidence.low;
  if (independentSources == 1) {
    return hasHardSignal ? DetectionConfidence.medium : DetectionConfidence.low;
  }
  if (independentSources == 2) {
    return hasHardSignal ? DetectionConfidence.high : DetectionConfidence.medium;
  }
  return hasHardSignal
      ? DetectionConfidence.veryHigh
      : DetectionConfidence.high;
}
