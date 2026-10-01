import '../core/core.dart';
import '../protection/protection_action.dart';
import '../protection/protection_policy.dart';
import 'risk_posture.dart';
import 'severity_action_ladder.dart';

/// Named security postures a customer can select.
///
/// These are **presets over the existing [ProtectionPolicy]**, not a second
/// policy system. Each profile is a documented set of thresholds that produces
/// an ordinary `ProtectionPolicy`, so remote delivery, versioning, expiry and
/// the fail-closed behaviour already built into that class apply unchanged.
///
/// A bank does not want to reason about `minimumRiskScore: 34`; it wants
/// "BANKING". The mapping between the two lives here, in one auditable place,
/// rather than being re-derived by each customer.
enum SecurityProfile {
  /// Observe and report. No user-visible friction.
  standard,

  /// Act on high-confidence findings.
  strict,

  /// Tuned for retail banking: step up on elevated risk, lock on critical.
  banking,

  /// Payment flows — the least tolerant of ambiguity, because the operation
  /// being protected is irreversible.
  payment,

  /// Maximum enforcement, for internal or high-value deployments.
  highSecurity,

  /// A policy supplied by the customer. Validated, never trusted blindly.
  custom,
}

/// Attestation strength a profile requires.
///
/// ⚠️ **Interface only in this milestone.** No attestation is implemented —
/// Play Integrity and App Attest are separate milestones. This exists so those
/// can be added later without changing the policy shape, and so a profile can
/// already *declare* its intent.
enum AttestationRequirement {
  /// No attestation required.
  none,

  /// Use attestation when available; proceed without it.
  preferred,

  /// Attestation must succeed. **Not enforceable yet** — a policy selecting
  /// this today behaves as [preferred] and reports the gap.
  required,
}

/// Network conditions a profile expects.
enum NetworkRequirement {
  /// Any network state is acceptable.
  any,

  /// Refuse to operate over a connection with interception indicators.
  noInterception,

  /// Require a validated, non-proxied connection.
  trustedOnly,
}

/// The full definition behind a [SecurityProfile].
class SecurityProfileDefinition {
  final SecurityProfile profile;

  /// Risk posture at or above which the profile begins to act.
  final RiskPosture actionThreshold;

  /// Action taken at each posture. Absent postures fall back to [ProtectionAction.allow].
  final Map<RiskPosture, ProtectionAction> postureActions;

  /// Detector ids this profile considers mandatory.
  ///
  /// If one is `unavailable`/`unknown`, the profile is running with reduced
  /// coverage — surfaced via [ProtectionPolicy] rather than silently ignored.
  final Set<String> requiredDetectors;

  /// Minimum fraction of detectors that must reach a verdict, 0.0–1.0.
  ///
  /// Guards the failure mode where every check is inconclusive and the device
  /// scores 0 — a perfect score achieved by measuring nothing.
  final double minimumCoverage;

  final AttestationRequirement attestation;
  final NetworkRequirement network;
  final OfflinePolicy offlineBehavior;
  final ProtectionAction offlineFallbackAction;

  /// Whether telemetry is required for this profile to be considered healthy.
  final bool telemetryRequired;

  /// Minimum action for a given [DetectionSeverity], independent of the
  /// aggregate posture — the risk-pipeline half of the action-ladder
  /// reconciliation. See `severity_action_ladder.dart` for why this exists:
  /// without it, a single high/critical-severity finding with a lower-scoring
  /// (e.g. uncorroborated) confidence could recommend a softer action than
  /// the legacy pipeline's severity floor would have. Defaults to
  /// [defaultSeverityActionFloor] — the same table the legacy pipeline uses —
  /// so a profile that does not override it behaves identically to the
  /// pre-reconciliation legacy floor.
  final Map<DetectionSeverity, ProtectionAction> severityFloor;

  const SecurityProfileDefinition({
    required this.profile,
    required this.actionThreshold,
    required this.postureActions,
    this.requiredDetectors = const {},
    this.minimumCoverage = 0.0,
    this.attestation = AttestationRequirement.none,
    this.network = NetworkRequirement.any,
    this.offlineBehavior = OfflinePolicy.enforce,
    this.offlineFallbackAction = ProtectionAction.monitor,
    this.telemetryRequired = false,
    this.severityFloor = defaultSeverityActionFloor,
  });

  /// The action this profile prescribes for [posture] **alone**, ignoring
  /// severity. Kept for callers that specifically want the posture-only
  /// answer (tests, diagnostics); [ProtectionEngine.evaluateWithRisk] uses
  /// [decisionFor] instead, which is the reconciled model.
  ProtectionAction actionFor(RiskPosture posture) {
    if (posture.rank < actionThreshold.rank) return ProtectionAction.allow;
    return postureActions[posture] ?? ProtectionAction.allow;
  }

  /// The reconciled decision: the stricter of the posture ladder and the
  /// severity floor, exactly mirroring how the legacy pipeline already
  /// combines its own two ladders (`ProtectionEngine.recommendedAction`).
  ///
  /// This is **the** authoritative action-selection rule for the risk
  /// pipeline — see `docs/ACTION_LADDER_MIGRATION.md` § One authoritative
  /// decision model.
  ProtectionAction decisionFor({
    required RiskPosture posture,
    required DetectionSeverity? highestSeverity,
  }) {
    final byPosture = actionFor(posture);
    final bySeverity = severityActionFloor(highestSeverity, severityFloor);
    return byPosture.index >= bySeverity.index ? byPosture : bySeverity;
  }

  /// Converts this profile into an ordinary [ProtectionPolicy].
  ///
  /// Everything downstream keeps working on the existing type — profiles add
  /// vocabulary, not a parallel enforcement path.
  ProtectionPolicy toPolicy({int version = 1}) => ProtectionPolicy(
        version: version,
        minimumRiskScore: actionThreshold.lowerBound,
        enabledActions: postureActions.values.toSet()
          ..add(ProtectionAction.allow)
          ..add(ProtectionAction.monitor),
        offlineBehavior: offlineBehavior,
        offlineFallbackAction: offlineFallbackAction,
      );

  static const Map<SecurityProfile, SecurityProfileDefinition> definitions = {
    SecurityProfile.standard: SecurityProfileDefinition(
      profile: SecurityProfile.standard,
      actionThreshold: RiskPosture.elevated,
      postureActions: {
        RiskPosture.elevated: ProtectionAction.warn,
        RiskPosture.highRisk: ProtectionAction.warn,
        RiskPosture.critical: ProtectionAction.block,
      },
      offlineBehavior: OfflinePolicy.monitorOnly,
    ),
    SecurityProfile.strict: SecurityProfileDefinition(
      profile: SecurityProfile.strict,
      actionThreshold: RiskPosture.lowRisk,
      postureActions: {
        RiskPosture.lowRisk: ProtectionAction.monitor,
        RiskPosture.elevated: ProtectionAction.warn,
        RiskPosture.highRisk: ProtectionAction.block,
        RiskPosture.critical: ProtectionAction.lockApp,
      },
      minimumCoverage: 0.5,
    ),
    SecurityProfile.banking: SecurityProfileDefinition(
      profile: SecurityProfile.banking,
      actionThreshold: RiskPosture.lowRisk,
      postureActions: {
        RiskPosture.lowRisk: ProtectionAction.monitor,
        RiskPosture.elevated: ProtectionAction.stepUp,
        RiskPosture.highRisk: ProtectionAction.block,
        RiskPosture.critical: ProtectionAction.lockApp,
      },
      requiredDetectors: {'root_jailbreak', 'frida', 'tamper', 'debugger'},
      minimumCoverage: 0.6,
      attestation: AttestationRequirement.preferred,
      network: NetworkRequirement.noInterception,
      offlineFallbackAction: ProtectionAction.warn,
      telemetryRequired: true,
    ),
    SecurityProfile.payment: SecurityProfileDefinition(
      profile: SecurityProfile.payment,
      actionThreshold: RiskPosture.lowRisk,
      postureActions: {
        RiskPosture.lowRisk: ProtectionAction.warn,
        RiskPosture.elevated: ProtectionAction.block,
        RiskPosture.highRisk: ProtectionAction.lockSession,
        RiskPosture.critical: ProtectionAction.lockApp,
      },
      requiredDetectors: {
        'root_jailbreak', 'frida', 'tamper', 'debugger', 're_tools', 'mitm',
      },
      minimumCoverage: 0.7,
      attestation: AttestationRequirement.preferred,
      network: NetworkRequirement.trustedOnly,
      offlineBehavior: OfflinePolicy.fail,
      offlineFallbackAction: ProtectionAction.block,
      telemetryRequired: true,
    ),
    SecurityProfile.highSecurity: SecurityProfileDefinition(
      profile: SecurityProfile.highSecurity,
      actionThreshold: RiskPosture.trusted,
      postureActions: {
        RiskPosture.trusted: ProtectionAction.monitor,
        RiskPosture.lowRisk: ProtectionAction.warn,
        RiskPosture.elevated: ProtectionAction.lockSession,
        RiskPosture.highRisk: ProtectionAction.lockApp,
        RiskPosture.critical: ProtectionAction.lockApp,
      },
      requiredDetectors: {
        'root_jailbreak', 'frida', 'tamper', 'debugger', 're_tools',
        'emulator', 'hook_detection',
      },
      minimumCoverage: 0.8,
      attestation: AttestationRequirement.required,
      network: NetworkRequirement.trustedOnly,
      offlineBehavior: OfflinePolicy.fail,
      offlineFallbackAction: ProtectionAction.lockSession,
      telemetryRequired: true,
    ),
    SecurityProfile.custom: SecurityProfileDefinition(
      profile: SecurityProfile.custom,
      actionThreshold: RiskPosture.elevated,
      postureActions: {
        RiskPosture.elevated: ProtectionAction.warn,
        RiskPosture.highRisk: ProtectionAction.block,
        RiskPosture.critical: ProtectionAction.lockApp,
      },
    ),
  };

  /// The definition for [profile]. Never null — [SecurityProfile.custom] is
  /// the fallback, so an unknown profile degrades to a defined posture rather
  /// than to no protection.
  static SecurityProfileDefinition of(SecurityProfile profile) =>
      definitions[profile] ?? definitions[SecurityProfile.custom]!;
}

/// Outcome of validating a profile or policy.
///
/// Validation **reports**; it does not throw. A malformed policy arriving from
/// a server must degrade to a safe default, not crash the host application —
/// a crash is a denial of service triggered by whoever controls the policy.
class PolicyValidation {
  /// `false` only for defects that make the policy unsafe or incoherent.
  final bool isValid;

  /// Defects that invalidate the policy.
  final List<String> problems;

  /// Notes that do not invalidate the policy but that an operator should see.
  ///
  /// Kept separate from [problems] because they answer different questions.
  /// "This profile requests attestation that is not implemented yet" is a
  /// capability gap worth surfacing; treating it as invalid would reject the
  /// shipped `highSecurity` profile and leave the customer with no policy at
  /// all — strictly worse than running it with the gap reported.
  final List<String> warnings;

  const PolicyValidation({
    required this.isValid,
    required this.problems,
    this.warnings = const [],
  });

  static const PolicyValidation valid =
      PolicyValidation(isValid: true, problems: []);

  static PolicyValidation invalid(List<String> problems,
          {List<String> warnings = const []}) =>
      PolicyValidation(
        isValid: false,
        problems: List.unmodifiable(problems),
        warnings: List.unmodifiable(warnings),
      );

  static PolicyValidation validWith(List<String> warnings) => PolicyValidation(
        isValid: true,
        problems: const [],
        warnings: List.unmodifiable(warnings),
      );
}

/// Validates a [SecurityProfileDefinition] against structural rules.
///
/// Checks ranges and coherence — not authenticity. Verifying that a policy
/// came from the customer requires signing, which is a documented future
/// integration point (`docs/RUNTIME_SECURITY_ENGINE.md` § Policy integrity),
/// not part of this milestone.
PolicyValidation validateProfile(SecurityProfileDefinition definition) {
  final problems = <String>[];
  final warnings = <String>[];

  final coverage = definition.minimumCoverage;
  if (coverage.isNaN || coverage.isInfinite) {
    problems.add('minimumCoverage must be a finite number');
  } else if (coverage < 0.0 || coverage > 1.0) {
    problems.add('minimumCoverage must be within 0.0–1.0, got $coverage');
  }

  if (definition.postureActions.isEmpty) {
    problems.add('postureActions must define at least one posture');
  }

  // A profile that acts at a posture it never defines an action for is
  // silently inert — the most dangerous kind of misconfiguration, because it
  // looks configured.
  for (final posture in RiskPosture.values) {
    if (posture.rank < definition.actionThreshold.rank) continue;
    if (!definition.postureActions.containsKey(posture)) {
      problems.add(
          'posture ${posture.name} is at or above the action threshold but has no action');
    }
  }

  // Escalation must be monotonic: a worse posture may not carry a softer
  // action, or an attacker gains by making the device look *more* compromised.
  ProtectionAction? previous;
  for (final posture in RiskPosture.values) {
    final action = definition.postureActions[posture];
    if (action == null) continue;
    if (previous != null && action.index < previous.index) {
      problems.add(
          'posture ${posture.name} weakens the action relative to a lower posture');
    }
    previous = action;
  }

  // The severity floor must itself escalate monotonically — the same
  // reasoning as the posture ladder above, applied to the other half of the
  // reconciled decision model.
  ProtectionAction? previousFloor;
  for (final severity in DetectionSeverity.values) {
    final action = definition.severityFloor[severity];
    if (action == null) continue;
    if (previousFloor != null && action.index < previousFloor.index) {
      problems.add(
          'severityFloor for ${severity.name} weakens the action relative '
          'to a lower severity');
    }
    previousFloor = action;
  }

  if (definition.attestation == AttestationRequirement.required) {
    warnings.add(
        'attestation "required" is not enforceable yet — no attestation '
        'provider is implemented; the profile behaves as "preferred"');
  }

  if (problems.isNotEmpty) {
    return PolicyValidation.invalid(problems, warnings: warnings);
  }
  return warnings.isEmpty
      ? PolicyValidation.valid
      : PolicyValidation.validWith(warnings);
}
