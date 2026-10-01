import '../core/core.dart';
import 'security_detector.dart';
import 'security_detector_registry.dart';

/// Why a detector did not run in a given scan.
typedef SkipReason = String Function(String detectorId);

/// Decides whether a detector is allowed to run in this scan.
///
/// Returning `null` means "run it"; returning a string means "skip it, and
/// here is why" — the reason lands on the resulting
/// [DetectionResult.unavailableReason], so a skipped detector is still
/// represented in the output rather than silently missing.
typedef DetectorGate = String? Function(SecurityDetector detector);

/// Executes the registered detectors and returns their findings.
///
/// This is the single execution path for detection in the SDK:
///
/// ```
///   SecurityDetectorRegistry → ScanRunner → List<DetectionResult>
/// ```
///
/// ## Behaviour preserved from the previous scan loop
///
/// `SecurityCenterController.runScan()` established three properties that a
/// production RASP scan needs, and this runner keeps all three:
///
/// * **Concurrent.** Every detector starts at once. A serial loop made the
///   scan as slow as the sum of its network checks.
/// * **Individually timed out.** One hung check can never stall the scan —
///   the previous single-blob behaviour was the cause of the endless
///   "running security analysis" spinner. Default is 8 seconds, matching
///   what shipped.
/// * **Individually fault-isolated.** A detector that throws yields an
///   unavailable result, not a failed scan.
///
/// ## A timed-out or thrown detector is never "secure"
///
/// Both produce a [DetectionResult] with `unavailableReason` set and
/// `threatDetected: false`. The Protection Engine ignores unavailable
/// results entirely rather than counting them as clean — see
/// [DetectionResult.unavailableReason].
class ScanRunner {
  /// Per-detector safety timeout. Network-backed checks (MITM, IP
  /// reputation) are the slowest; anything beyond this is reported as
  /// unavailable rather than blocking the scan.
  static const Duration defaultTimeout = Duration(seconds: 8);

  final SecurityDetectorRegistry registry;
  final Duration timeout;

  /// Optional gate applied before each detector runs — used to enforce
  /// licence entitlements and policy-level detector toggles without the
  /// runner needing to know what either of those are.
  final DetectorGate? gate;

  const ScanRunner({
    required this.registry,
    this.timeout = defaultTimeout,
    this.gate,
  });

  /// Runs every registered detector and returns one [DetectionResult] each,
  /// in registry order.
  ///
  /// The output always has exactly one entry per registered detector, so a
  /// caller can index by `detectorId` without checking for gaps — a gated,
  /// timed-out, or thrown detector is present and marked unavailable.
  Future<List<DetectionResult>> scanAll() async {
    final detectors = registry.detectors;
    final results = await Future.wait(detectors.map(_runOne));
    return List.unmodifiable(results);
  }

  /// Runs a single detector by id, or returns `null` when nothing is
  /// registered under that id.
  Future<DetectionResult?> scanOne(String detectorId) async {
    final detector = registry.byId(detectorId);
    if (detector == null) return null;
    return _runOne(detector);
  }

  Future<DetectionResult> _runOne(SecurityDetector detector) async {
    // A gated detector is UNAVAILABLE: not running it is the intended
    // outcome of a licence or policy decision, not a fault.
    final blocked = gate?.call(detector);
    if (blocked != null) {
      return _inconclusive(detector, DetectionStatus.unavailable, blocked);
    }

    try {
      return await detector.scan().timeout(
            timeout,
            // A timeout is a fault, not an expected absence — the detector
            // was supposed to run and did not finish.
            onTimeout: () => _inconclusive(
              detector,
              DetectionStatus.error,
              'Check timed out after ${timeout.inSeconds}s',
            ),
          );
    } catch (e) {
      return _inconclusive(
        detector,
        DetectionStatus.error,
        'Check failed to run: $e',
      );
    }
  }

  /// A placeholder result for a detector that produced no verdict.
  ///
  /// Severity is [DetectionSeverity.low] and category [ThreatCategory.other]
  /// because neither is known without running the detector — and neither is
  /// ever read, since an inconclusive status excludes the result from scoring.
  static DetectionResult _inconclusive(
    SecurityDetector detector,
    DetectionStatus status,
    String reason,
  ) {
    assert(status.isInconclusive);
    return DetectionResult(
      detectorId: detector.detectorId,
      detectorType: detector.detectorType,
      category: ThreatCategory.other,
      status: status,
      severity: DetectionSeverity.low,
      title: detector.detectorId,
      description: reason,
      observedAt: DateTime.now().toUtc(),
      unavailableReason: reason,
    );
  }
}
