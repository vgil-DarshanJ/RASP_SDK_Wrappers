import 'package:flutter/foundation.dart';

import '../core/core.dart';
import 'security_event_center.dart';
import 'security_event_type.dart';

/// Phase 16 — debug-only synthetic event generation for integration testing.
///
/// Mirrors `TransactionOperationGuard.debugForceInfrastructureError`'s
/// established pattern in this codebase exactly: a plain (non-const, non-
/// `@visibleForTesting`) method gated by [kDebugMode], so a widget's "Simulate
/// CRITICAL event" debug button can call it from non-test code, while the
/// [kDebugMode] compile-time constant guarantees the entire body — including
/// the string literals — is tree-shaken out of a release/AOT build, exactly
/// like `ActivationManager._trace`'s `[RASP-TRACE]` logging.
///
/// ## Why this exists rather than reusing a real detector
///
/// The milestone is explicit: *do not generate fake detections just to
/// populate telemetry* on the live path (Phase 15). This class is the
/// opposite of that — it exists so a QA engineer or an integration test can
/// deliberately push a LOW/HIGH/CRITICAL event through the real pipeline
/// (real dedup, real chain, real queue, real priority eviction) without
/// needing to fabricate a rooted device or a tampered APK to prove the
/// *pipeline* works. It is never wired into `RaspSdk.initialize`, never
/// called from `SecurityCenterController.runScan`, and produces an event
/// whose `evidence_summary` explicitly says `synthetic: true` so it can
/// never be mistaken for a real finding by anything reading the wire form.
///
/// ## Why it cannot be reached from a production public API
///
/// - Every method is a no-op (`kDebugMode` check first, `return`
///   immediately) when `kDebugMode` is `false`, which the Dart compiler
///   resolves at compile time for a release/AOT build — a release binary
///   contains no path that ever executes the injection code, not merely a
///   flag that happens to be off.
/// - Nothing in `main.dart`, `RaspSdk`, or any detector calls this class.
///   It is reached only by test code (`test/` directory) or by a debug-only
///   UI affordance a host app author deliberately wires up, exactly the same
///   trust boundary `debugForceInfrastructureError` already relies on.
class SecurityEventTestInjector {
  const SecurityEventTestInjector._();

  /// Injects one synthetic detection-shaped event at [priority]. No-op in
  /// release builds.
  static Future<void> injectDetection({
    required SecurityEventPriority priority,
    String detectorId = 'test_injector',
    String evidenceLabel = 'synthetic_finding',
  }) async {
    if (!kDebugMode) return;
    final severity = switch (priority) {
      SecurityEventPriority.critical => DetectionSeverity.critical,
      SecurityEventPriority.high => DetectionSeverity.high,
      SecurityEventPriority.medium => DetectionSeverity.medium,
      SecurityEventPriority.low => DetectionSeverity.low,
      SecurityEventPriority.info => DetectionSeverity.low,
    };
    final result = DetectionResult(
      detectorId: detectorId,
      detectorType: DetectorType.custom,
      category: ThreatCategory.appIntegrity,
      status: DetectionStatus.detected,
      severity: severity,
      title: 'Synthetic test event',
      description: 'Injected by SecurityEventTestInjector for integration '
          'testing — never a real finding.',
      evidence: [
        DetectionEvidence(key: 'synthetic', value: true),
        DetectionEvidence(key: 'label', value: evidenceLabel),
      ],
      observedAt: DateTime.now().toUtc(),
    );
    await SecurityEventCenter.recordDetections([result]);
  }

  /// Injects one synthetic self-integrity event of [type]. No-op in release
  /// builds. Restricted to the eight Phase 13 types by
  /// [SecurityEventType.isSelfIntegrity], matching
  /// `SecurityEventFactory.selfIntegrity`'s own assertion.
  static Future<void> injectSelfIntegrity(SecurityEventType type) async {
    if (!kDebugMode) return;
    assert(type.isSelfIntegrity,
        'injectSelfIntegrity only accepts a Phase 13 self-integrity type');
    try {
      // Route through a real record* call so the pipeline is initialised
      // exactly as it would be on a real device — no shortcut construction.
      // An empty detection batch is a legitimate no-op call that still
      // forces initialization.
      await SecurityEventCenter.recordDetections(const []);
      await SecurityEventCenter.pipelineOrNull?.recordSelfIntegrity(
        type: type,
        severity: DetectionSeverity.critical,
        evidence: {'synthetic': 'true'},
      );
    } catch (_) {
      // Debug-only convenience; never allowed to crash a debug build either.
    }
  }
}
