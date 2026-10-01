import '../../device/device_binding_state.dart';
import '../../offline/offline_compliance.dart';
import '../../risk/risk_posture.dart';
import '../../trust/attestation/attestation_result.dart';
import '../../trust/trust_assessment.dart';
import 'operation_action.dart';
import 'operation_context.dart';
import 'operation_sensitivity.dart';

/// Phase 3/9/10/17 — the generic decision engine.
///
/// ## Composition, not a single formula
///
/// A [SensitiveOperationPolicy] is a set of independent floors, one per
/// input dimension (sensitivity baseline, risk, trust, device binding,
/// attestation, offline). Each floor maps its dimension's states to a
/// minimum [SensitiveOperationAction]; the final decision is the **most
/// restrictive** floor that applies. This is what makes Phase 15's property
/// — "risk can only maintain or strengthen a restriction" — true by
/// construction rather than by careful formula-balancing: adding a stricter
/// floor for one dimension can only raise the max, never lower it, and no
/// dimension's floor can be bypassed by another dimension looking good.
///
/// ## No banking rules
///
/// Every floor below is keyed on **generic** states this SDK already
/// produces (`RiskPosture`, `TrustLevel`, `DeviceBindingVerdict`,
/// `AttestationStatus`, `OfflineComplianceState`) — never on `operationType`,
/// `amount`, or any host-app business concept. A host app wanting
/// `operationType`-specific behaviour supplies a different
/// [OperationSensitivity] for different operation types before calling the
/// policy; the policy itself stays generic.
class SensitiveOperationPolicy {
  /// Monotonic version, mirroring `ProtectionPolicy.version` — a policy is
  /// meaningful to compare only against itself over time, and callers that
  /// log a decision should log which version produced it.
  final int version;

  /// The floor every operation gets from its own declared sensitivity alone,
  /// with everything else at its best case. `NORMAL` defaults to `allow`;
  /// `CRITICAL` defaults to `stepUp`, per Phase 5's "ordinarily requires
  /// step-up... unless policy says otherwise."
  final Map<OperationSensitivity, SensitiveOperationAction> sensitivityFloor;

  /// Risk-posture floor. Phase 9's examples ("elevated risk → STEP_UP",
  /// "compromised device → BLOCK") land here and in [trustFloor]
  /// respectively.
  final Map<RiskPosture, SensitiveOperationAction> riskFloor;

  final Map<TrustLevel, SensitiveOperationAction> trustFloor;

  final Map<DeviceBindingVerdict, SensitiveOperationAction> deviceBindingFloor;

  /// Phase 10. `AttestationStatus.valid` is intentionally absent from a
  /// default policy's map (a valid attestation should never be able to
  /// *weaken* what risk/trust already require — it can only fail to raise
  /// the floor further, never lower one). `invalid` and `error` default to
  /// `block`; `unknown`/`unavailable`/`expired`/`replayed` default to
  /// `stepUp` — attestation absence is treated as reduced assurance, never
  /// as a pass, matching Phase 17's "UNAVAILABLE never improves security."
  final Map<AttestationStatus, SensitiveOperationAction> attestationFloor;

  /// Phase 9. Applied only when the context is offline (the caller decides
  /// offline-ness; this map only says what to do once it is true).
  final Map<OperationSensitivity, SensitiveOperationAction> offlineFloor;

  /// Applied when [OfflineComplianceState] resolves to something other than
  /// `valid`/`withinGrace` while the operation is being evaluated —
  /// independent of [offlineFloor], which is keyed on sensitivity for the
  /// "we are currently offline" case. This one is keyed on the compliance
  /// state itself, so `expired`/`unknown`/`error` can be floored regardless
  /// of whether the device *currently* has connectivity (a device that is
  /// online right now but has not proven itself in the compliance window is
  /// a different risk than one that is offline right now but proved itself
  /// five minutes ago).
  final Map<OfflineComplianceState, SensitiveOperationAction>
      offlineComplianceFloor;

  /// Phase 6 (end-to-end backend verification milestone) — which
  /// sensitivities may not execute on local `evaluate()`/`issue()` alone
  /// and additionally require a confirmed
  /// [BackendVerificationOutcome.authorized] from
  /// `/api/v1/sdk/protected-operations/verify` before
  /// `SensitiveOperationAuthorizer.verify`'s AUTHORIZED result may be acted
  /// on. Additive — every existing caller that never checks this field
  /// (every prior milestone's code) is unaffected; only a caller that
  /// explicitly consults it (the new backend-authorization flow) changes
  /// behaviour. Defaults to `{high, critical}`: `normal`/`elevated` stay
  /// fully local, matching the existing [offlineFloor] treating only
  /// `critical` specially — see
  /// `docs/PROTECTED_OPERATION_END_TO_END_AUDIT.md` §5.
  final Set<OperationSensitivity> backendVerificationRequired;

  const SensitiveOperationPolicy({
    this.version = 1,
    this.sensitivityFloor = const {
      OperationSensitivity.normal: SensitiveOperationAction.allow,
      OperationSensitivity.elevated: SensitiveOperationAction.allow,
      OperationSensitivity.high: SensitiveOperationAction.stepUp,
      OperationSensitivity.critical: SensitiveOperationAction.stepUp,
    },
    this.riskFloor = const {
      RiskPosture.trusted: SensitiveOperationAction.allow,
      RiskPosture.lowRisk: SensitiveOperationAction.allow,
      RiskPosture.elevated: SensitiveOperationAction.stepUp,
      RiskPosture.highRisk: SensitiveOperationAction.restrict,
      RiskPosture.critical: SensitiveOperationAction.block,
    },
    this.trustFloor = const {
      TrustLevel.trusted: SensitiveOperationAction.allow,
      TrustLevel.degraded: SensitiveOperationAction.stepUp,
      TrustLevel.unknown: SensitiveOperationAction.stepUp,
      TrustLevel.suspicious: SensitiveOperationAction.restrict,
      TrustLevel.compromised: SensitiveOperationAction.block,
    },
    this.deviceBindingFloor = const {
      DeviceBindingVerdict.valid: SensitiveOperationAction.allow,
      DeviceBindingVerdict.notBound: SensitiveOperationAction.allow,
      DeviceBindingVerdict.keyUnavailable: SensitiveOperationAction.stepUp,
      DeviceBindingVerdict.keyMissing: SensitiveOperationAction.restrict,
      DeviceBindingVerdict.keyMismatch: SensitiveOperationAction.block,
      DeviceBindingVerdict.keyRevoked: SensitiveOperationAction.block,
      DeviceBindingVerdict.proofInvalid: SensitiveOperationAction.block,
      DeviceBindingVerdict.keyError: SensitiveOperationAction.restrict,
    },
    this.attestationFloor = const {
      AttestationStatus.expired: SensitiveOperationAction.stepUp,
      AttestationStatus.replayed: SensitiveOperationAction.block,
      AttestationStatus.unknown: SensitiveOperationAction.stepUp,
      AttestationStatus.unavailable: SensitiveOperationAction.stepUp,
      AttestationStatus.invalid: SensitiveOperationAction.block,
      AttestationStatus.error: SensitiveOperationAction.stepUp,
    },
    this.offlineFloor = const {
      OperationSensitivity.normal: SensitiveOperationAction.allow,
      OperationSensitivity.elevated: SensitiveOperationAction.allow,
      OperationSensitivity.high: SensitiveOperationAction.stepUp,
      OperationSensitivity.critical: SensitiveOperationAction.restrict,
    },
    this.offlineComplianceFloor = const {
      OfflineComplianceState.valid: SensitiveOperationAction.allow,
      OfflineComplianceState.withinGrace: SensitiveOperationAction.allow,
      OfflineComplianceState.expired: SensitiveOperationAction.restrict,
      OfflineComplianceState.unknown: SensitiveOperationAction.stepUp,
      OfflineComplianceState.unavailable: SensitiveOperationAction.allow,
      OfflineComplianceState.error: SensitiveOperationAction.stepUp,
    },
    this.backendVerificationRequired = const {
      OperationSensitivity.high,
      OperationSensitivity.critical,
    },
  });

  /// Fail-safe default when a policy has no entry for a state it should
  /// still handle — Phase 17's "UNKNOWN/UNAVAILABLE/ERROR never improves
  /// security" applied at the policy-lookup level, not just the state-value
  /// level: a *missing* map entry must floor the same way an explicit
  /// `unknown` entry would, never fall through to `allow`.
  static const SensitiveOperationAction _missingEntryFloor =
      SensitiveOperationAction.stepUp;

  /// Decides an action for [context], **not accounting for step-up**. See
  /// [SensitiveOperationAuthorizer.evaluate] for the version that also
  /// folds in [SensitiveOperationContext.authenticationState] — kept
  /// separate so this method stays a pure function of the risk/trust/device
  /// dimensions alone, independently testable (Phase 19's property tests
  /// exercise this method directly).
  ///
  /// ## `null` vs. an explicit "unknown" state (Phase 17)
  ///
  /// A `null` field means the caller did not include that dimension in this
  /// decision — it contributes **no floor at all**, exactly as if the
  /// dimension did not exist for this call. This is different from, and
  /// must not be confused with, an explicit "unknown"-shaped *value*
  /// (`TrustLevel.unknown`, `AttestationStatus.unknown`,
  /// `OfflineComplianceState.unknown`) — those are real verdicts the SDK
  /// reached ("we tried to establish this and could not"), and every one of
  /// them has an explicit, non-`allow` entry in the floor maps above. Only a
  /// **present** value with **no map entry at all** (a genuinely
  /// unanticipated future enum member) falls through to
  /// [_missingEntryFloor] — the fail-safe behaviour applies to "we don't
  /// know what this new state means," not to "this dimension was not
  /// evaluated for this call."
  SensitiveOperationAction floorFor(SensitiveOperationContext context,
      {required bool isOffline}) {
    var action = sensitivityFloor[context.sensitivity] ?? _missingEntryFloor;

    if (context.riskPosture != null) {
      action = _raise(
          action, riskFloor[context.riskPosture] ?? _missingEntryFloor);
    }

    if (context.trustLevel != null) {
      action = _raise(
          action, trustFloor[context.trustLevel] ?? _missingEntryFloor);
    }

    if (context.deviceBindingState != null) {
      action = _raise(
          action,
          deviceBindingFloor[context.deviceBindingState] ??
              _missingEntryFloor);
    }

    // AttestationStatus.valid deliberately has no entry above — a valid
    // attestation applies no floor of its own (it may only fail to raise
    // the ceiling further; it can never justify lowering what risk/trust
    // already required). Every other *present* status floors explicitly.
    if (context.attestationState != null &&
        context.attestationState != AttestationStatus.valid) {
      action = _raise(action,
          attestationFloor[context.attestationState] ?? _missingEntryFloor);
    }

    if (isOffline) {
      action = _raise(action, offlineFloor[context.sensitivity] ??
          _missingEntryFloor);
    }

    if (context.offlineState != null) {
      action = _raise(action,
          offlineComplianceFloor[context.offlineState] ?? _missingEntryFloor);
    }

    return action;
  }

  static SensitiveOperationAction _raise(
    SensitiveOperationAction current,
    SensitiveOperationAction candidate,
  ) =>
      candidate.rank > current.rank ? candidate : current;
}
