/// The four distinguishable outcomes of running a detector.
///
/// ## Why four and not two
///
/// A boolean "did it fire?" cannot express the difference between *the check
/// ran and found nothing* and *the check never ran*. Collapsing those two
/// reports a clean bill of health for coverage that does not exist — which is
/// how a security SDK ends up lying to a bank about what it is protecting.
///
/// Three separate defects in this codebase came from exactly that collapse:
/// the repackaging check reported SECURE on every device because no expected
/// certificate was ever configured; `DeviceFingerprintService` catches every
/// exception and returns `isRisk: false`; `ScreenshotRestriction` returns
/// `false` both when the secure-window flag is off and when the platform call
/// threw. All three looked green while verifying nothing.
///
/// [unavailable] and [error] are kept apart because they need different
/// responses: unavailable is a *coverage* fact an operator should see and
/// usually accept (wrong platform, feature not licensed, nothing configured),
/// while error is a *fault* someone should investigate.
enum DetectionStatus {
  /// The check ran and found nothing wrong. The only status that means "safe".
  secure,

  /// The check ran and found a threat.
  detected,

  /// The check could not run, and that is expected: wrong platform, no native
  /// implementation, disabled by policy or licence, or a required value was
  /// never configured.
  unavailable,

  /// The check **ran** but could not reach a verdict.
  ///
  /// Distinct from [unavailable], which means the check never ran at all. This
  /// is the state for "I looked and could not tell" — the platform allowed the
  /// attempt but withheld the answer.
  ///
  /// The Android root detector is the worked example: `/system/xbin` is not
  /// listable by an app, so `File("/system/xbin/su").exists()` returns `false`
  /// for a binary `adb shell` can see plainly. Reporting that as [secure]
  /// converts missing visibility into a clean bill of health. Measured on
  /// Android 14: **all 13** `su` paths are unknown, not absent.
  unknown,

  /// The check tried to run and failed: the platform threw, a timeout
  /// elapsed, a reply was malformed. Never a passing result.
  error,
}

/// Grouping helpers so callers do not re-derive the same predicates.
extension DetectionStatusX on DetectionStatus {
  /// `true` only for [DetectionStatus.detected].
  bool get isThreat => this == DetectionStatus.detected;

  /// `true` when the detector produced a real verdict — [secure] or
  /// [detected]. [unavailable], [unknown] and [error] are all false here, so
  /// none of them can be mistaken for coverage.
  bool get isConclusive =>
      this == DetectionStatus.secure || this == DetectionStatus.detected;

  /// `true` when the detector could not establish the answer, for any reason
  /// other than finding nothing.
  ///
  /// Useful for reporting *coverage* separately from *findings*: a scan where
  /// half the detectors are unknown is not the same security posture as one
  /// where they all reported clean, even though both produce zero threats.
  bool get isIndeterminate =>
      this == DetectionStatus.unavailable ||
      this == DetectionStatus.unknown ||
      this == DetectionStatus.error;

  /// `true` when the detector produced no verdict, for any reason.
  bool get isInconclusive => !isConclusive;

  /// Stable wire/display name.
  String get wireName => name;
}
