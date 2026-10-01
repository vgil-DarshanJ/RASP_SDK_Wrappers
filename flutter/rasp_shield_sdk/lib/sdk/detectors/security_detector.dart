import '../core/core.dart';

/// Common contract every RASP detector will eventually implement.
///
/// ## Why this exists
///
/// Today's detection logic (`rasp/security_catalog.dart`'s
/// `SecurityFeature.runner`, `rasp/rasp_service.dart`'s
/// `RaspService.runChecks()`) is defined per-caller, with no shared shape: a
/// detector is "whatever function some controller decided to call", and its
/// result is a UI-oriented `FeatureOutcome`/`RaspCheckResult`, not a portable
/// data type. That makes the set of detectors impossible to enumerate,
/// register, or run generically — the SDK cannot ask "what detectors exist?"
/// or "run all of them, whatever they are" without hardcoding every case.
///
/// `SecurityDetector` gives every detector one method with one return type —
/// [scan] returning a plain [DetectionResult] from `sdk/core/` — so a future
/// engine can hold a list of `SecurityDetector`s and treat them uniformly,
/// regardless of what any individual detector actually inspects.
///
/// ## Zero UI dependency
///
/// This file imports only `sdk/core/core.dart` (plain Dart data). No
/// `material.dart`, no `widgets.dart`, no `Color`/`IconData`. A detector
/// implementing this interface can be unit-tested with no widget tree, no
/// device, and — for a detector that does its own work in pure Dart — no
/// platform channel either.
///
/// ## Every shipped detector implements this
///
/// All 21 checks the SDK ships are `SecurityDetector`s in
/// `sdk/detectors/builtin_detectors.dart`. `SecurityCatalog` no longer
/// implements any check itself — it holds presentation metadata and
/// delegates to these classes, so a check has exactly one implementation.
///
/// A host app can add its own detector by implementing this interface and
/// registering it; `ScanRunner` will run it alongside the built-ins with the
/// same timeout and fault isolation.
abstract class SecurityDetector {
  /// Stable identifier for this detector, e.g. `'root_jailbreak'`. Matches
  /// the `detectorId` field on the `DetectionResult` this detector produces.
  String get detectorId;

  /// Which mechanism this detector represents.
  DetectorType get detectorType;

  /// Runs the check and returns its finding.
  ///
  /// Must not throw for an ordinary "no threat found" outcome — that is a
  /// `DetectionResult` with `threatDetected: false`, not an exception. An
  /// exception means the check itself could not run.
  Future<DetectionResult> scan();
}
