import 'security_detector.dart';

/// Holds the set of known [SecurityDetector]s.
///
/// ## Membership only — execution lives in ScanRunner
///
/// The registry answers "what detectors exist?" and nothing else. Running
/// them is `ScanRunner`'s job (`sdk/detectors/scan_runner.dart`), which
/// applies concurrency, per-detector timeouts, and the entitlement/policy
/// gate. Keeping the two apart means a caller can enumerate the detector set
/// — to render a settings screen, to report coverage — without that
/// enumeration being able to trigger a scan as a side effect.
///
/// ## What it holds
///
/// `defaultRegistry()` in `builtin_detectors.dart` preloads every detector
/// the SDK ships. A host app can [register] its own detector under a new id,
/// or replace a shipped one by registering a different implementation under
/// the same id — [register] swaps by `detectorId`, so no separate remove
/// step is needed.
class SecurityDetectorRegistry {
  final List<SecurityDetector> _detectors = [];

  /// Adds [detector]. Registering a `detectorId` that already exists
  /// replaces the previous entry, so a later migration can swap a
  /// placeholder for its real implementation without a separate "remove"
  /// step.
  void register(SecurityDetector detector) {
    _detectors.removeWhere((d) => d.detectorId == detector.detectorId);
    _detectors.add(detector);
  }

  /// Removes the detector with [detectorId], if present.
  void unregister(String detectorId) {
    _detectors.removeWhere((d) => d.detectorId == detectorId);
  }

  /// The detector registered under [detectorId], or `null`.
  SecurityDetector? byId(String detectorId) {
    for (final detector in _detectors) {
      if (detector.detectorId == detectorId) return detector;
    }
    return null;
  }

  /// Every registered detector. Read-only — use [register]/[unregister] to
  /// change membership.
  List<SecurityDetector> get detectors => List.unmodifiable(_detectors);

  /// How many detectors are currently registered.
  int get length => _detectors.length;
}
