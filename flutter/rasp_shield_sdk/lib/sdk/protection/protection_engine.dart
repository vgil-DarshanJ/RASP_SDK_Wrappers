import '../core/core.dart';
import '../risk/risk.dart';
import 'protection_action.dart';
import 'protection_context.dart';
import 'protection_policy.dart';
import 'protection_result.dart';

/// Turns a set of detections into a protection decision.
///
/// ```
///   detections (List<DetectionResult>)  ─┐
///   context    (ProtectionContext)      ─┼─→  evaluate()  ─→  ProtectionResult
///   policy     (ProtectionPolicy)       ─┘
/// ```
///
/// ## The engine never runs a detector
///
/// It consumes results something else already produced (`ScanRunner`), which
/// keeps one scan loop in the app and makes an evaluation reproducible from
/// data alone — the same three inputs always produce the same
/// `ProtectionResult`, in a test or on a device, with no I/O in between.
///
/// ## Scoring: one opinion, two places it is used
///
/// [riskScore] deliberately mirrors the backend scorer
/// (`app/threat_engine/scorer.py`): the same per-detector weights and the
/// same combination multipliers. This is **not** a second scoring engine —
/// the backend stays authoritative for what lands in `threat_history` and
/// the SOC console. The device needs a local score because a RASP SDK must
/// be able to act while offline, and a device that scored threats
/// differently from the console would produce decisions an analyst could not
/// explain.
///
/// The one difference is the scale. The backend score is unbounded (root +
/// frida + tamper = 285); [riskScore] is clamped to 0–100 so a policy's
/// `minimumRiskScore` means the same thing across SDK versions. The mapping
/// is linear against the backend's own CRITICAL floor of 150 — see
/// [_criticalFloor].
class ProtectionEngine {
  const ProtectionEngine();

  /// Per-detector weights, mirroring `Settings.THREAT_SCORE_*` on the
  /// backend. Keyed by `detectorId` as used in `SecurityCatalog` and
  /// `builtin_detectors.dart`.
  ///
  /// Detectors with no backend weight (`device_binding`,
  /// `device_fingerprint`, `high_risk_ip`) are scored here from their
  /// severity instead — see [_weightFor]. That is a known asymmetry, already
  /// documented for telemetry in `ScanTelemetryMapper`: those three have no
  /// column in the backend schema, so the backend cannot weight them at all.
  static const Map<String, int> detectorWeights = {
    // Active-attack signals
    'clone': 90, // maps to malware_detected
    'frida': 80,
    're_tools': 70, // maps to hook_detected
    'tamper': 60,
    'repackage': 60, // folds onto tamper_detected on the wire
    'root_jailbreak': 50,
    'debugger': 40,
    'emulator': 30,
    'overlay': 25,
    'accessibility': 25,
    'mitm': 20, // maps to proxy_detected
    'vpn': 15,
    'screenshot_protection': 10,
    // Device posture — deliberately lower: how exposed the device is, not
    // that an attack is under way.
    'untrusted_install_source': 35,
    'adb_enabled': 20,
    'device_lock_missing': 20,
    'developer_mode': 10,
    'secure_hardware_unavailable': 10,
  };

  /// Fallback weight by severity for detectors absent from
  /// [detectorWeights], chosen to sit inside the same band as their
  /// backend-weighted peers.
  static const Map<DetectionSeverity, int> _severityWeights = {
    DetectionSeverity.low: 10,
    DetectionSeverity.medium: 25,
    DetectionSeverity.high: 50,
    DetectionSeverity.critical: 80,
  };

  /// The backend's CRITICAL threshold (`ThreatScorer.RISK_THRESHOLDS`). A
  /// raw score at or above this maps to 100 here.
  static const int _criticalFloor = 150;

  static int _weightFor(DetectionResult detection) =>
      detectorWeights[detection.detectorId] ??
      _severityWeights[detection.severity] ??
      10;

  /// Detections that actually ran, fired, and clear the policy's severity
  /// bar. Unavailable results are excluded outright — a check that could not
  /// run is neither a threat nor a clean bill of health.
  static List<DetectionResult> _actionable(
    List<DetectionResult> detections,
    ProtectionPolicy policy,
  ) {
    return detections
        .where((d) =>
            d.isConclusive &&
            d.threatDetected &&
            d.severity.index >= policy.minimumSeverity.index)
        .toList(growable: false);
  }

  /// Evaluates [detections] against [policy], in light of [context].
  ///
  /// Fails safe: any unexpected state resolves toward *more* protection, not
  /// less. An expired policy escalates to [ProtectionPolicy.strict] before
  /// anything else is decided.
  ProtectionResult evaluate(
    List<DetectionResult> detections, {
    required ProtectionContext context,
    required ProtectionPolicy policy,
  }) {
    final effective = policy.effective();
    final score = riskScore(detections, context: context, policy: effective);
    final severity = highestSeverity(detections, policy: effective);

    var action = recommendedAction(
      riskScore: score,
      highestSeverity: severity,
      policy: effective,
    );

    // Authoritative Protection Engine V1 — per-detector policy floor. Most
    // severe wins, exactly like the severity/score ladders above: a
    // detector named in `policy.detectorActions` can only ever raise this
    // decision, never lower what severity/score already required.
    final detectorFloor = _detectorActionFloor(detections, effective);
    if (detectorFloor.index > action.index) {
      action = effective.clamp(detectorFloor);
    }

    // Offline handling is applied last so it can only ever *change* the
    // decision the evidence produced, never hide the evidence itself.
    if (context.isOffline) {
      switch (effective.offlineBehavior) {
        case OfflinePolicy.enforce:
          break;
        case OfflinePolicy.monitorOnly:
          if (action.index > ProtectionAction.monitor.index) {
            action = effective.clamp(ProtectionAction.monitor);
          }
          break;
        case OfflinePolicy.fail:
          if (effective.offlineFallbackAction.index > action.index) {
            action = effective.clamp(effective.offlineFallbackAction);
          }
          break;
      }
    }

    return ProtectionResult(
      riskScore: score,
      recommendedAction: action,
      highestSeverity: severity,
      detections: detections,
      evaluatedAt: DateTime.now().toUtc(),
      policyVersion: effective.version,
      posture: postureForScore(score),
    );
  }

  /// Evaluates using the **risk engine** pipeline: deduplication, confidence
  /// weighting, correlation, posture banding and explainable reasons.
  ///
  /// ```
  ///   detections → RiskEngine → RiskAssessment → profile → ProtectionResult
  /// ```
  ///
  /// Separate from [evaluate] rather than replacing it. [evaluate] mirrors the
  /// backend scorer exactly and is pinned by existing tests; changing it would
  /// silently rewrite what every historical score meant. This is the path new
  /// callers opt into.
  ///
  /// Fails safe throughout: an expired policy escalates to
  /// [ProtectionPolicy.strict] before anything is decided, an inconclusive
  /// scan contributes zero rather than reassurance, and offline handling is
  /// applied last so it can only change the decision the evidence produced —
  /// never hide the evidence itself.
  ProtectionResult evaluateWithRisk(
    List<DetectionResult> detections, {
    required ProtectionContext context,
    required ProtectionPolicy policy,
    SecurityProfile profile = SecurityProfile.standard,
    RiskEngine riskEngine = const RiskEngine(),
  }) {
    final effective = policy.effective();
    final assessment = riskEngine.evaluate(detections);
    final definition = SecurityProfileDefinition.of(profile);

    // Reconciled decision: the stricter of the posture ladder and the
    // severity floor — see docs/ACTION_LADDER_MIGRATION.md. This is what
    // brings evaluateWithRisk into structural parity with the legacy
    // evaluate()'s own two-ladder-max design.
    var action = definition.decisionFor(
      posture: assessment.posture,
      highestSeverity: assessment.highestSeverity,
    );

    // Authoritative Protection Engine V1 — same per-detector floor the
    // legacy pipeline applies in `evaluate()`, consulted here too so a
    // customer policy's detector-specific rule has identical effect
    // regardless of which pipeline is driving the live decision.
    final detectorFloor = _detectorActionFloor(detections, effective);
    if (detectorFloor.index > action.index) action = detectorFloor;

    // Coverage gate. A device that scored 0 because nothing could be measured
    // has not demonstrated safety, and a profile that demands corroboration
    // must not accept an empty measurement as a pass.
    final reasons = <String>[...assessment.reasons];
    if (assessment.evaluatedCount > 0 &&
        assessment.coverage < definition.minimumCoverage) {
      final escalated = effective.clamp(ProtectionAction.warn);
      if (escalated.index > action.index) action = escalated;
      reasons.add(
          'Coverage ${(assessment.coverage * 100).round()}% is below the '
          '${(definition.minimumCoverage * 100).round()}% required by '
          '${profile.name} — treated as reduced assurance, not as safety');
    }

    // Required detectors that produced no verdict are a coverage gap the
    // profile explicitly said it cannot tolerate.
    final missing = _missingRequiredDetectors(detections, definition);
    if (missing.isNotEmpty) {
      final escalated = effective.clamp(ProtectionAction.warn);
      if (escalated.index > action.index) action = escalated;
      reasons.add(
          'Required detector(s) unavailable: ${(missing.toList()..sort()).join(', ')}');
    }

    if (context.isOffline) {
      switch (effective.offlineBehavior) {
        case OfflinePolicy.enforce:
          break;
        case OfflinePolicy.monitorOnly:
          if (action.index > ProtectionAction.monitor.index) {
            action = effective.clamp(ProtectionAction.monitor);
            reasons.add('Offline: enforcement reduced to monitoring by policy');
          }
          break;
        case OfflinePolicy.fail:
          if (definition.offlineFallbackAction.index > action.index) {
            action = effective.clamp(definition.offlineFallbackAction);
            reasons.add('Offline: profile fallback action applied');
          }
          break;
      }
    }

    return ProtectionResult(
      riskScore: assessment.score,
      recommendedAction: effective.clamp(action),
      highestSeverity: assessment.highestSeverity,
      detections: detections,
      evaluatedAt: DateTime.now().toUtc(),
      policyVersion: effective.version,
      posture: assessment.posture,
      reasons: List.unmodifiable(reasons),
      assessment: assessment,
    );
  }

  /// Required detectors that did not reach a verdict.
  ///
  /// A detector missing from the scan entirely counts as unavailable — absence
  /// of a required check is a gap whether it was skipped, disabled or never
  /// registered.
  static Set<String> _missingRequiredDetectors(
    List<DetectionResult> detections,
    SecurityProfileDefinition definition,
  ) {
    if (definition.requiredDetectors.isEmpty) return const {};
    final conclusive = <String>{
      for (final d in detections)
        if (d.isConclusive) d.detectorId,
    };
    return definition.requiredDetectors.difference(conclusive);
  }

  /// The highest `policy.detectorActions` floor among detections that ran,
  /// fired, and clear the severity bar — [ProtectionAction.allow] when none
  /// of the actionable detectors are named in the policy. Mirrors
  /// [_actionable]'s own gating so a detector suppressed by
  /// `minimumSeverity` cannot be escalated back in through this side door.
  static ProtectionAction _detectorActionFloor(
    List<DetectionResult> detections,
    ProtectionPolicy policy,
  ) {
    if (policy.detectorActions.isEmpty) return ProtectionAction.allow;
    var best = ProtectionAction.allow;
    for (final detection in _actionable(detections, policy)) {
      final floor = policy.detectorActions[detection.detectorId];
      if (floor != null && floor.index > best.index) best = floor;
    }
    return best;
  }

  /// The highest severity among detections that ran, fired, and clear the
  /// policy bar — or `null` when none did.
  DetectionSeverity? highestSeverity(
    List<DetectionResult> detections, {
    ProtectionPolicy policy = ProtectionPolicy.monitorOnly,
  }) {
    DetectionSeverity? worst;
    for (final detection in _actionable(detections, policy)) {
      if (worst == null || detection.severity.index > worst.index) {
        worst = detection.severity;
      }
    }
    return worst;
  }

  /// Overall risk, `0`–`100`.
  ///
  /// Raw score and multipliers mirror `app/threat_engine/scorer.py` exactly;
  /// the result is then mapped onto 0–100 against [_criticalFloor].
  int riskScore(
    List<DetectionResult> detections, {
    required ProtectionContext context,
    ProtectionPolicy policy = ProtectionPolicy.monitorOnly,
  }) {
    final actionable = _actionable(detections, policy);
    if (actionable.isEmpty) return 0;

    var raw = 0;
    for (final detection in actionable) {
      raw += _weightFor(detection);
    }

    final fired = actionable.map((d) => d.detectorId).toSet();
    final scaled = (raw * _combinationMultiplier(fired)).round();

    final normalized = (scaled * 100 / _criticalFloor).round();
    return normalized.clamp(0, 100);
  }

  /// Highest applicable combination multiplier, mirroring
  /// `ThreatScorer._get_combination_multiplier`.
  ///
  /// Detector ids are translated to the backend's flag vocabulary first, so
  /// the two implementations agree on what "root + frida" means even though
  /// they name the detectors differently.
  static double _combinationMultiplier(Set<String> firedDetectorIds) {
    final root = firedDetectorIds.contains('root_jailbreak');
    final frida = firedDetectorIds.contains('frida');
    final hook = firedDetectorIds.contains('re_tools');
    final tamper = firedDetectorIds.contains('tamper') ||
        firedDetectorIds.contains('repackage');
    final malware = firedDetectorIds.contains('clone');

    var multiplier = 1.0;
    if (root && frida && tamper) multiplier = _max(multiplier, 1.5);
    if (frida && hook) multiplier = _max(multiplier, 1.4);
    if (root && frida) multiplier = _max(multiplier, 1.3);
    if (malware && firedDetectorIds.length > 1) multiplier = _max(multiplier, 1.3);
    if (root && tamper) multiplier = _max(multiplier, 1.2);
    return multiplier;
  }

  static double _max(double a, double b) => a > b ? a : b;

  /// The action for a given score and severity, clamped to what [policy]
  /// permits.
  ///
  /// Two independent ladders, and the **more severe** result wins: a single
  /// critical finding must act even when the aggregate score is low, and a
  /// pile of medium findings must act even when none of them is individually
  /// alarming. Using only one ladder loses one of those cases.
  ProtectionAction recommendedAction({
    required int riskScore,
    required DetectionSeverity? highestSeverity,
    required ProtectionPolicy policy,
  }) {
    if (highestSeverity == null) return policy.clamp(ProtectionAction.allow);
    if (riskScore < policy.minimumRiskScore) {
      return policy.clamp(ProtectionAction.monitor);
    }

    final bySeverity = policy.severityActions[highestSeverity] ??
        _defaultSeverityAction(highestSeverity);
    final byScore = _scoreAction(riskScore);

    final chosen = bySeverity.index >= byScore.index ? bySeverity : byScore;
    return policy.clamp(chosen);
  }

  /// Default escalation ladder when a policy does not override it.
  ///
  /// Delegates to [defaultSeverityActionFloor] — the same table
  /// [SecurityProfileDefinition.severityFloor] now defaults to — so the
  /// legacy and risk-engine pipelines share one authoritative severity floor
  /// rather than two tables that could silently drift apart. Output is
  /// unchanged from before the action-ladder reconciliation; this is a
  /// refactor of the *source*, not the *values*.
  static ProtectionAction _defaultSeverityAction(DetectionSeverity severity) =>
      defaultSeverityActionFloor[severity]!;

  /// Score ladder, aligned to the backend's own level boundaries once
  /// normalized: MEDIUM ≥ 50/150, HIGH ≥ 100/150, CRITICAL ≥ 150/150.
  static ProtectionAction _scoreAction(int score) {
    if (score >= 100) return ProtectionAction.lockApp;
    if (score >= 67) return ProtectionAction.block;
    if (score >= 33) return ProtectionAction.warn;
    if (score > 0) return ProtectionAction.monitor;
    return ProtectionAction.allow;
  }
}
