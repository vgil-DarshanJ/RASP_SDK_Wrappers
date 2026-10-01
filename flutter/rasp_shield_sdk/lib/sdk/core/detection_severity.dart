/// How dangerous a single detection is, independent of how it is displayed.
///
/// This mirrors the meaning of `rasp/security_feature.dart`'s `Severity` and
/// the backend's `risk_level` vocabulary, but carries no color or icon —
/// presentation is a concern for whatever layer renders a `DetectionResult`,
/// not for the SDK Core model itself.
///
/// Ordered low → critical so callers can compare severities with `.index`.
enum DetectionSeverity {
  /// Informational or low-risk; rarely worth interrupting the user.
  low,

  /// Worth surfacing to an analyst, not urgent on its own.
  medium,

  /// A real threat signal; typically combined with others to decide policy.
  high,

  /// Immediate risk to the session or device; the strongest single signal.
  critical,
}
