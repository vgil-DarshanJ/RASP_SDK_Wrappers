import '../core/core.dart';
import 'correlation_rule.dart';

/// Turns a set of independent detections into named attack chains.
///
/// ```
///   List<DetectionResult>  ──→  correlate()  ──→  List<AttackChain>
/// ```
///
/// Pure and deterministic: no clock, no I/O, no shared state. The same
/// detections always produce the same chains, in the same order, which is what
/// lets a stored `threat_history` row be re-explained months later.
///
/// ## Why correlation is separate from scoring
///
/// The risk engine answers *"how bad is this device?"*; correlation answers
/// *"what is happening to it?"*. Those have different audiences — a number
/// drives a policy decision, a named chain drives an investigation — and
/// fusing them produced a scorer that could not explain itself.
class CorrelationEngine {
  /// The rules this engine evaluates.
  final List<CorrelationRule> rules;

  const CorrelationEngine({this.rules = defaultRules});

  /// Chains that fire against [detections], strongest first.
  ///
  /// Sorted by severity then risk contribution so the first entry is the one
  /// worth showing when there is only room for one.
  List<AttackChain> correlate(List<DetectionResult> detections) {
    // Index by detector id, keeping the *worst* result per id. Two results for
    // the same detector must not both feed a rule — see RiskEngine's
    // deduplication note; the same reasoning applies here.
    final byId = <String, DetectionResult>{};
    for (final detection in detections) {
      final existing = byId[detection.detectorId];
      if (existing == null || _isWorse(detection, existing)) {
        byId[detection.detectorId] = detection;
      }
    }

    final fired = <AttackChain>[];
    for (final rule in rules) {
      if (!rule.matches(byId)) continue;
      final supporting = rule.supportingSignalsIn(byId);
      fired.add(AttackChain(
        rule: rule,
        matchedSignals: Set<String>.from(rule.requiredSignals),
        supportingSignals: supporting,
        confidence: _chainConfidence(rule, byId, supporting.length),
      ));
    }

    fired.sort((a, b) {
      final bySeverity = b.severity.index.compareTo(a.severity.index);
      if (bySeverity != 0) return bySeverity;
      final byContribution =
          b.riskContribution.compareTo(a.riskContribution);
      if (byContribution != 0) return byContribution;
      // Stable final tiebreak so ordering is fully deterministic.
      return a.rule.id.compareTo(b.rule.id);
    });
    return List.unmodifiable(fired);
  }

  static bool _isWorse(DetectionResult a, DetectionResult b) {
    if (a.threatDetected != b.threatDetected) return a.threatDetected;
    if (a.severity.index != b.severity.index) {
      return a.severity.index > b.severity.index;
    }
    return a.confidence.rank > b.confidence.rank;
  }

  /// A chain is only as certain as its weakest required link, raised one step
  /// for every two corroborating optional signals.
  static DetectionConfidence _chainConfidence(
    CorrelationRule rule,
    Map<String, DetectionResult> byId,
    int supportingCount,
  ) {
    var weakest = DetectionConfidence.veryHigh;
    for (final id in rule.requiredSignals) {
      final confidence = byId[id]?.confidence;
      if (confidence != null && confidence.rank < weakest.rank) {
        weakest = confidence;
      }
    }
    final boosted = weakest.rank + (supportingCount ~/ 2);
    final capped = boosted.clamp(0, DetectionConfidence.values.length - 1);
    return DetectionConfidence.values[capped];
  }

  /// The chains RASP Shield ships.
  ///
  /// Detector ids match `builtin_detectors.dart`. Adding a rule here is the
  /// only change needed to teach the engine a new attack pattern — no scorer
  /// edit, no engine edit.
  static const List<CorrelationRule> defaultRules = [
    CorrelationRule(
      id: 'CRITICAL_RUNTIME_COMPROMISE',
      name: 'Root + instrumentation',
      requiredSignals: {'root_jailbreak', 'frida'},
      optionalSignals: {'re_tools', 'debugger', 'tamper'},
      severity: DetectionSeverity.critical,
      riskContribution: 40,
      description:
          'The device is rooted and a live instrumentation framework is '
          'attached. Every client-side check should be assumed observable and '
          'modifiable.',
    ),
    CorrelationRule(
      id: 'INSTRUMENTATION_ATTACK',
      name: 'Instrumentation with hooking',
      requiredSignals: {'frida', 're_tools'},
      // `hook_detection` added here — see
      // docs/INSTRUMENTATION_CORRELATION_AUDIT.md and
      // docs/INSTRUMENTATION_ATTACK_CHAIN.md for the full analysis. Kept
      // optional rather than required: `frida` (a live instrumentation
      // engine attached right now) and `re_tools` (hooking-capable packages
      // installed on the device) already define when this rule fires, and
      // that firing condition is deliberately left unchanged — `re_tools`
      // remains valid device-posture evidence on its own. `hook_detection`
      // (a live, in-process hooking observation — mapped hook-framework
      // libraries, suspicious RWX memory, or this SDK's own security-critical
      // methods reporting themselves as `native`) corroborates rather than
      // gates: when it also fires, the chain's confidence rises exactly like
      // `debugger`/`root_jailbreak` already do. `frida` and `hook_detection`
      // both read `/proc/self/maps`, but for disjoint marker sets (Frida's
      // own library names vs. Xposed/Substrate/Dobby-family names) plus one
      // mechanism — ART method-integrity reflection — that touches no file
      // at all, so this is genuine (if not provably statistical)
      // corroboration, not the same fact restated.
      optionalSignals: {'debugger', 'root_jailbreak', 'hook_detection'},
      severity: DetectionSeverity.critical,
      riskContribution: 35,
      description:
          'An instrumentation framework is present alongside hooking tools. '
          'Method interception of security-critical code is likely under way.',
    ),
    CorrelationRule(
      id: 'APPLICATION_COMPROMISE',
      name: 'Tampered and repackaged application',
      requiredSignals: {'tamper', 'repackage'},
      optionalSignals: {'untrusted_install_source', 'clone'},
      severity: DetectionSeverity.critical,
      riskContribution: 35,
      description:
          'The application binary differs from the signed original and was '
          'resigned. This build is not the one the customer published.',
    ),
    CorrelationRule(
      id: 'ACTIVE_RUNTIME_ATTACK',
      name: 'Debugger with hooking and tampering',
      requiredSignals: {'debugger', 're_tools', 'tamper'},
      optionalSignals: {'frida', 'root_jailbreak'},
      severity: DetectionSeverity.critical,
      riskContribution: 40,
      description:
          'A debugger is attached to a modified binary with hooking tools '
          'present — the signature of interactive reverse engineering against '
          'a live session.',
    ),
    CorrelationRule(
      id: 'UNTRUSTED_DISTRIBUTION',
      name: 'Sideloaded clone',
      requiredSignals: {'clone', 'untrusted_install_source'},
      optionalSignals: {'repackage', 'tamper'},
      severity: DetectionSeverity.high,
      riskContribution: 25,
      description:
          'A cloned instance installed from an untrusted source. Commonly '
          'used to run multiple accounts or to host a modified build.',
    ),
    CorrelationRule(
      id: 'NETWORK_INTERCEPTION',
      name: 'Proxy with interception capability',
      requiredSignals: {'mitm', 'vpn'},
      optionalSignals: {'root_jailbreak', 'frida'},
      severity: DetectionSeverity.high,
      riskContribution: 20,
      description:
          'Traffic is routed through a VPN while interception indicators are '
          'present. Request and response inspection is plausible.',
    ),
    CorrelationRule(
      id: 'UI_OVERLAY_ATTACK',
      name: 'Overlay with accessibility abuse',
      requiredSignals: {'overlay', 'accessibility'},
      optionalSignals: {'screenshot_protection'},
      severity: DetectionSeverity.high,
      riskContribution: 20,
      description:
          'A screen overlay is combined with accessibility-service abuse — '
          'the standard construction for credential-harvesting on Android.',
    ),
    // ── SDK Self-Integrity milestone additions ──────────────────────────
    //
    // Both new. Audited first (docs/SDK_SELF_INTEGRITY_AUDIT.md §8, Phase 8
    // of that milestone) against every existing rule: `APPLICATION_COMPROMISE`
    // already covers "tamper + repackage + untrusted installer" via its own
    // `optionalSignals`, and "certificate mismatch + package mismatch"
    // is already forced to `TrustLevel.compromised` by `TrustEngine`'s own
    // identity-anchor precedence rule *before* `CorrelationEngine` ever runs
    // (see `trust_anchor_engine_test.dart`, "certificate mismatch + package
    // mismatch → COMPROMISED, two anchors") — neither needed a new rule.
    // `sdk_integrity` (detector id `trust_sdkIntegrity`, from
    // `TrustAssessment._detectorIdFor`) is genuinely new: no existing rule
    // references it, because the anchor itself did not exist before this
    // milestone.
    CorrelationRule(
      id: 'RUNTIME_TAMPERING',
      name: 'SDK integrity failure with a debugger attached',
      requiredSignals: {'trust_sdkIntegrity', 'debugger'},
      optionalSignals: {'frida', 're_tools', 'root_jailbreak'},
      severity: DetectionSeverity.critical,
      riskContribution: 40,
      description:
          'This SDK\'s own decision logic disagrees with the signed '
          'behavioral manifest while a debugger is attached — consistent '
          'with live, interactive tampering of the protection engine '
          'itself, not merely the host application.',
    ),
    CorrelationRule(
      id: 'SECURITY_ENGINE_TAMPER',
      name: 'SDK integrity failure with hooking',
      requiredSignals: {'trust_sdkIntegrity', 'hook_detection'},
      optionalSignals: {'frida', 're_tools'},
      severity: DetectionSeverity.critical,
      riskContribution: 40,
      description:
          'This SDK\'s own decision logic disagrees with the signed '
          'behavioral manifest while an in-process method hook is '
          'observed — the specific combination a Frida script patching '
          'TrustEngine/RiskEngine/ProtectionEngine at runtime would '
          'produce.',
    ),
    CorrelationRule(
      id: 'ANALYSIS_ENVIRONMENT',
      name: 'Emulated analysis environment',
      requiredSignals: {'emulator', 'debugger'},
      optionalSignals: {'re_tools', 'adb_enabled', 'developer_mode'},
      severity: DetectionSeverity.medium,
      riskContribution: 15,
      description:
          'The application is running under a debugger inside an emulator. '
          'Typical of static/dynamic analysis rather than a live customer.',
    ),
  ];
}
