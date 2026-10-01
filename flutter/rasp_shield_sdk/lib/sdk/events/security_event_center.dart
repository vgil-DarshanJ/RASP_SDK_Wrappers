import 'dart:async';
import 'dart:io' show Platform;

import '../activation_manager.dart';
import '../core/core.dart';
import '../device/device_key_manager.dart';
import '../protection/compatibility_decision.dart';
import '../protection/pipeline_mode.dart';
import '../risk/risk_assessment.dart';
import '../risk/risk_posture.dart';
import '../sdk_config.dart';
import '../protection/enforcement_state.dart';
import '../protection/protection_action.dart';
import '../security/sensitive_operation/backend_verification_outcome.dart';
import '../security/sensitive_operation/operation_action.dart';
import '../security/sensitive_operation/operation_authorization.dart';
import '../security/sensitive_operation/operation_authorizer.dart';
import '../security/sensitive_operation/operation_context.dart';
import '../security/sensitive_operation/operation_sensitivity.dart';
import '../security/transaction_integrity.dart';
import '../trust/trust_anchor.dart';
import '../trust/trust_assessment.dart';
import '../trust/trust_evidence.dart';
import 'secure_security_event_queue_store.dart';
import 'security_event_factory.dart';
import 'security_event_pipeline.dart';
import 'security_event_queue.dart';
import 'security_event_type.dart';

/// The live wiring point for `sdk/events/`.
///
/// Before this class existed, the entire `sdk/events/` subsystem was built,
/// tested, and never instantiated by any live code path. This is the fix:
/// one static holder around a single
/// [SecurityEventPipeline], with typed `record*` methods that the SDK's
/// actual scan orchestration (`SecurityCenterController.runScan`) and
/// activation handshake (`RaspSdk`, `ActivationManager`) call.
///
/// It does not run detectors, evaluate risk, or make protection decisions —
/// it only converts results those existing subsystems already computed into
/// [SecurityEvent]s and queues them. The same "an observer must never be
/// able to break the thing it observes" rule
/// `SecurityCenterController._updateTrustAssessment` already documents for
/// the trust engine applies here: every `record*` method below swallows its
/// own failures rather than letting a bug in event recording surface as a
/// scan failure.
class SecurityEventCenter {
  SecurityEventCenter._();

  static SecurityEventPipeline? _pipeline;
  static SecurityEventContext? _context;
  static final DeviceKeyManager _deviceKeys = const DeviceKeyManager();

  /// Guards [_ensurePipeline] against the classic unsynchronized-lazy-
  /// singleton race: `RaspShield._runProtectionScan()` fires
  /// `recordDetections`/`recordTrustAssessment`/`recordRiskAssessment` as
  /// independent fire-and-forget macrotasks (`_recordAsync`), and
  /// `LicenseManager.initialize()` separately fires `recordActivationOutcome`
  /// the same way — all of them able to call [_ensurePipeline] concurrently
  /// at cold start. Without this guard, several callers can each observe
  /// `_pipeline == null` before any of them finishes the `await`-laden
  /// construction below, each build its **own** [SecurityEventPipeline] (its
  /// own genesis-anchored chain, its own queue, all racing to persist to the
  /// same secure-storage key), and whichever instance finishes last silently
  /// becomes the "official" one — discovered live (Continuous Telemetry
  /// milestone) as the root cause of a device whose chain had diverged from
  /// what the backend actually accepted, surfacing as permanent
  /// `409 CHAIN_DISCONTINUITY` / `422 CHAIN_INVALID` rejections. `null`
  /// means no construction is currently in flight.
  static Completer<SecurityEventPipeline>? _pipelineInit;

  /// Test-only override of application-id resolution, so a test can drive
  /// this class without a real platform channel.
  static Future<String> Function() applicationIdGetterForTests =
      _defaultApplicationId;

  static Future<String> _defaultApplicationId() async {
    try {
      return await ActivationManager.bundleId();
    } catch (_) {
      return 'unknown';
    }
  }

  /// The shared pipeline, built lazily on first use so construction never
  /// runs before [SdkConfig.configure] has been called by the host app.
  ///
  /// **Exactly one [SecurityEventPipeline] is ever constructed per process.**
  /// The first caller to find both [_pipeline] and [_pipelineInit] empty
  /// starts construction and publishes a [Completer] for it; every
  /// concurrent caller that arrives before construction finishes finds that
  /// completer and awaits its `future` instead of starting a second,
  /// independent construction — so `recordDetections`, `recordTrustAssessment`,
  /// `recordRiskAssessment` and `recordActivationOutcome`, even when all
  /// fired as separate macrotasks at cold start, always converge on the
  /// same instance. See [_pipelineInit]'s doc for why this matters.
  static Future<SecurityEventPipeline> _ensurePipeline() async {
    final existing = _pipeline;
    if (existing != null) return existing;

    // Someone else is already building it — await THEIR result rather than
    // starting a second, independent construction. This is the fix: no
    // caller may observe `_pipeline == null` and `_pipelineInit == null`
    // simultaneously without immediately claiming the guard itself (the
    // two lines above and the two below run with no `await` between them,
    // so nothing can interleave in that window).
    final inFlight = _pipelineInit;
    if (inFlight != null) return inFlight.future;

    final completer = Completer<SecurityEventPipeline>();
    _pipelineInit = completer;
    try {
      final context = await _buildContext();
      _context = context;
      final pipeline = SecurityEventPipeline(
        factory: SecurityEventFactory(context),
        queue:
            SecurityEventQueue(store: const SecureSecurityEventQueueStore()),
      );
      await pipeline.initialize();
      // Continuous Security Telemetry milestone: replays whatever survived a
      // prior process's death — see `SecureSecurityEventQueueStore`'s doc for
      // the exact guarantee. A no-op on first launch (nothing persisted yet)
      // and in any test that never populated the store.
      await pipeline.queue.restore();
      // Published only once construction is fully done — every waiter sees
      // either nothing yet (still awaiting the completer) or a fully
      // initialized pipeline, never a half-built one.
      _pipeline = pipeline;
      completer.complete(pipeline);
      return pipeline;
    } catch (error, stackTrace) {
      // A failed construction must not poison every future call: clear the
      // guard so the *next* caller starts a fresh attempt rather than
      // awaiting a completer that can only ever error.
      completer.completeError(error, stackTrace);
      // `Completer.completeError` demands its `future` eventually be
      // "handled" — when this is the only caller (no concurrent racer ever
      // awaited `completer.future`), leaving it unhandled makes the zone
      // report a SECOND, separate unhandled-async-error on top of this
      // method's own `rethrow` below. `.ignore()` marks it handled without
      // touching the real rethrow path any caller relies on for the actual
      // failure.
      completer.future.ignore();
      rethrow;
    } finally {
      if (identical(_pipelineInit, completer)) {
        _pipelineInit = null;
      }
    }
  }

  static Future<SecurityEventContext> _buildContext() async {
    final key = await _deviceKeys.load();
    return SecurityEventContext(
      sdkVersion: SdkConfig.sdkVersion,
      platform: _platformName(),
      applicationId: await applicationIdGetterForTests(),
      deviceBindingId: key?.keyId,
    );
  }

  static String _platformName() {
    try {
      if (Platform.isAndroid) return 'android';
      if (Platform.isIOS) return 'ios';
      return Platform.operatingSystem;
    } catch (_) {
      return 'unknown';
    }
  }

  /// The queue + chain this center is backed by, once initialized.
  static SecurityEventPipeline? get pipelineOrNull => _pipeline;

  static Future<void> recordDetections(List<DetectionResult> detections) async {
    try {
      final pipeline = await _ensurePipeline();
      for (final result in detections) {
        await pipeline.recordDetection(result);
      }
    } catch (_) {
      // Recording must never affect the scan it is observing.
    }
  }

  /// Records the aggregate "native layer never answered" signal — see
  /// `SecurityEventType.nativeLayerUnavailable`. The caller
  /// (`SecurityCenterController.runScan`) decides whether to call this at
  /// all, by checking `RaspNativeChannel.isNativeLayerUnavailable`; this
  /// method only records, matching [recordDetections] and every other
  /// `record*` method here.
  static Future<void> recordNativeLayerUnavailable(
      int nativeCallAttempts) async {
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordNativeLayerUnavailable(nativeCallAttempts);
    } catch (_) {
      // See class doc.
    }
  }

  static Future<void> recordTrustAssessment(TrustAssessment assessment) async {
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordTrustAssessment(assessment);
      await _recordSelfIntegrityFromAnchors(pipeline, assessment);
    } catch (_) {
      // See class doc.
    }
  }

  /// Phase 13/15 — derives self-integrity events from anchors that already
  /// fired inside a real [TrustAssessment], rather than creating a second,
  /// redundant detection. Only anchors in a genuinely contradicted state
  /// (mismatch, error) produce an event; expired/unavailable are coverage
  /// gaps, not integrity failures, and are left to the trust assessment
  /// event alone.
  static Future<void> _recordSelfIntegrityFromAnchors(
    SecurityEventPipeline pipeline,
    TrustAssessment assessment,
  ) async {
    for (final anchor in assessment.anchors) {
      final failed = anchor.state == TrustAnchorState.mismatch ||
          anchor.state == TrustAnchorState.error;
      SecurityEventType? type;
      if (anchor.anchor == TrustAnchor.sdkIntegrity) {
        type = failed
            ? SecurityEventType.sdkIntegrityFailed
            : (anchor.state == TrustAnchorState.valid
                ? SecurityEventType.sdkIntegrityValid
                : null);
      } else if (anchor.anchor == TrustAnchor.deviceBinding && failed) {
        type = SecurityEventType.deviceKeyMismatch;
      } else if (anchor.anchor == TrustAnchor.securityConfiguration && failed) {
        type = SecurityEventType.configSignatureFailed;
      } else if (anchor.anchor == TrustAnchor.attestation && failed) {
        type = SecurityEventType.attestationFailure;
      }
      if (type == null) continue;

      await pipeline.recordSelfIntegrity(
        type: type,
        severity: failed ? DetectionSeverity.critical : null,
        confidence: anchor.confidence,
        evidence: {
          'anchor': anchor.anchor.name,
          'root': anchor.root.name,
          'evidence_codes': anchor.evidence.map((e) => e.code.wireName).toList(),
        },
      );
    }
  }

  static Future<void> recordRiskAssessment(
    RiskAssessment assessment, {
    DateTime? evaluatedAt,
    ProtectionAction? action,
    int? policyVersion,
    bool recommendRescan = false,
    bool triggeredByRescan = false,
  }) async {
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordRiskAssessment(
        assessment,
        evaluatedAt: evaluatedAt,
        action: action,
        policyVersion: policyVersion,
        recommendRescan: recommendRescan,
        triggeredByRescan: triggeredByRescan,
      );
      if (assessment.chains.isNotEmpty) {
        await pipeline.recordAttackChains(assessment.chains,
            detectedAt: evaluatedAt);
      }
    } catch (_) {
      // See class doc.
    }
  }

  static Future<void> recordProtectionDecision({
    required CompatibilityDecision decision,
    required PipelineMode rolloutMode,
    TrustLevel? trustLevel,
  }) async {
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordProtectionDecision(
        decision: decision,
        rolloutMode: rolloutMode,
        trustLevel: trustLevel,
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Phase 15 — a server-authoritative rejection observed on the activation
  /// handshake. Distinct from the client-side trust-anchor signal above: this
  /// is what the backend itself decided, from `ActivationResult.status`
  /// (`ActivationManager._interpret`), never a value this SDK invented.
  /// [isInitialActivation] scopes [SecurityEventType.activationSucceeded]
  /// to genuine activation moments (`LicenseManager.initialize()`'s call
  /// site) — never to the periodic `refresh()`/heartbeat call site, which
  /// calls this same function on every tick and would otherwise flood the
  /// timeline with a redundant "activation succeeded" every heartbeat
  /// interval. Same noise-avoidance discipline
  /// `docs/SECURITY_EVENT_DELIVERY_ARCHITECTURE.md` already documents for
  /// `POLICY_APPLIED`.
  static Future<void> recordActivationOutcome(
    String status, {
    bool isInitialActivation = false,
  }) async {
    if (isInitialActivation && (status == 'ACTIVE' || status == 'GRACE')) {
      try {
        final pipeline = await _ensurePipeline();
        await pipeline.recordActivationSucceeded(evidence: {'status': status});
      } catch (_) {
        // See class doc.
      }
      return;
    }

    SecurityEventType? type;
    switch (status) {
      case 'DEVICE_KEY_MISMATCH':
      case 'DEVICE_PROOF_REQUIRED':
        type = SecurityEventType.deviceKeyMismatch;
        break;
      case 'REQUEST_REPLAYED':
        type = SecurityEventType.requestReplay;
        break;
      default:
        return;
    }
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordSelfIntegrity(
        type: type,
        severity: DetectionSeverity.critical,
        evidence: {'server_status': status},
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Continuous Security Telemetry milestone — see
  /// `RaspSdk._trackHeartbeatOutcome`'s doc for exactly when this fires
  /// (once per failure streak, not once per failed tick).
  static Future<void> recordHeartbeatOutcome({
    required bool recovered,
    Map<String, Object?>? evidence,
  }) async {
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordHeartbeatOutcome(recovered: recovered, evidence: evidence);
    } catch (_) {
      // See class doc.
    }
  }

  /// Phase 15 — wired from [TransactionOperationGuard]'s optional
  /// `onVerified` callback. Only ever called with a genuine verification
  /// outcome the guard itself produced; never synthesized.
  static Future<void> recordTransactionOutcome(
    TransactionRiskState state,
  ) async {
    if (state != TransactionRiskState.tampered) return;
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.recordSelfIntegrity(
        type: SecurityEventType.transactionTamper,
        severity: DetectionSeverity.critical,
        evidence: {'transaction_risk_state': state.name},
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Phase 14 (Sensitive Operation Protection Engine) — records one policy
  /// decision. Maps [SensitiveOperationAction] to the matching
  /// `sensitiveOperation*` event type; never fabricates a decision, only
  /// reports the one [SensitiveOperationAuthorizer.evaluate] already made.
  static Future<void> recordSensitiveOperationDecision({
    required SensitiveOperationContext context,
    required SensitiveOperationDecision decision,
  }) async {
    final type = switch (decision.action) {
      SensitiveOperationAction.allow =>
        SecurityEventType.sensitiveOperationAllowed,
      SensitiveOperationAction.stepUp =>
        SecurityEventType.sensitiveOperationStepUp,
      SensitiveOperationAction.restrict =>
        SecurityEventType.sensitiveOperationRestricted,
      SensitiveOperationAction.block =>
        SecurityEventType.sensitiveOperationBlocked,
    };
    final priority = switch (decision.action) {
      SensitiveOperationAction.block => SecurityEventPriority.critical,
      SensitiveOperationAction.restrict => SecurityEventPriority.high,
      SensitiveOperationAction.stepUp => SecurityEventPriority.medium,
      SensitiveOperationAction.allow => SecurityEventPriority.info,
    };
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.emit(
        (sequence) => pipeline.factory.sensitiveOperation(
          type: type,
          sequence: sequence,
          priority: priority,
          operationId: context.operationId,
          evidence: {
            'operation_type': context.operationType,
            'sensitivity': context.sensitivity.wireName,
            'baseline_floor': decision.baselineFloor.wireName,
            'final_action': decision.action.wireName,
            'policy_version': decision.policyVersion,
            'reasons': decision.reasons,
            if (context.riskPosture != null)
              'risk_posture': context.riskPosture!.wireName,
            if (context.trustLevel != null)
              'trust_level': context.trustLevel!.wireName,
          },
        ),
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Phase 14 — records a tampered or replayed authorization verification.
  /// A genuine [AuthorizationState.authorized]/`expired`/`revoked` result
  /// is not itself an incident and is not reported here — only the two
  /// states that indicate a mutated or reused authorization.
  static Future<void> recordSensitiveOperationVerification({
    required String operationId,
    required String operationType,
    required AuthorizationState state,
    AuthorizationInvalidReason? reason,
  }) async {
    if (state != AuthorizationState.invalid) return;
    final type = reason == AuthorizationInvalidReason.nonceReused
        ? SecurityEventType.sensitiveOperationReplayed
        : SecurityEventType.sensitiveOperationTampered;
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.emit(
        (sequence) => pipeline.factory.sensitiveOperation(
          type: type,
          sequence: sequence,
          priority: SecurityEventPriority.critical,
          operationId: operationId,
          evidence: {
            'operation_type': operationType,
            'authorization_state': state.wireName,
            if (reason != null) 'invalid_reason': reason.name,
          },
        ),
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// End-to-end backend verification milestone, Phase 11 — records the
  /// result of asking the backend to independently confirm a
  /// [SensitiveOperationAuthorization]. One event per backend call,
  /// deliberately not one per underlying HTTP retry — a caller retries the
  /// HTTP layer transparently (if it retries at all) and only reports the
  /// final [outcome] here, so this never duplicates events for the same
  /// local decision the way the class doc's "never fabricates" rule already
  /// requires for [recordSensitiveOperationDecision].
  static Future<void> recordSensitiveOperationBackendOutcome({
    required String operationId,
    required String operationType,
    required BackendVerificationOutcome outcome,
  }) async {
    final type = switch (outcome) {
      BackendVerificationOutcome.authorized =>
        SecurityEventType.sensitiveOperationBackendAllowed,
      BackendVerificationOutcome.replayed =>
        SecurityEventType.sensitiveOperationBackendReplayed,
      BackendVerificationOutcome.rateLimited ||
      BackendVerificationOutcome.unavailable =>
        SecurityEventType.sensitiveOperationBackendError,
      BackendVerificationOutcome.invalid ||
      BackendVerificationOutcome.expired ||
      BackendVerificationOutcome.deviceMismatch ||
      BackendVerificationOutcome.applicationMismatch =>
        SecurityEventType.sensitiveOperationBackendRejected,
    };
    final priority = outcome == BackendVerificationOutcome.authorized
        ? SecurityEventPriority.info
        : outcome.isDefinitive
            ? SecurityEventPriority.critical
            : SecurityEventPriority.medium;
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.emit(
        (sequence) => pipeline.factory.sensitiveOperation(
          type: type,
          sequence: sequence,
          priority: priority,
          operationId: operationId,
          evidence: {
            'operation_type': operationType,
            'backend_outcome': outcome.wireName,
          },
        ),
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Authoritative Protection Engine V1 — records one enforcement-state
  /// transition. Called only by `EnforcementController.evaluate` when it
  /// has actually applied a change (`applied && changed`), so this never
  /// records a SHADOW-mode observation or a repeated no-op scan — Phase
  /// 7/15's idempotency and deduplication requirements are enforced by the
  /// caller deciding not to call this at all, rather than by this method
  /// filtering duplicates itself.
  static Future<void> recordEnforcementTransition({
    required EnforcementState state,
    required ProtectionAction action,
    required int policyVersion,
  }) async {
    final type = switch (state) {
      EnforcementState.none => null,
      EnforcementState.warned => SecurityEventType.protectionWarned,
      EnforcementState.stepUpRequired => SecurityEventType.protectionStepUp,
      EnforcementState.restricted => SecurityEventType.protectionRestricted,
      EnforcementState.blocked =>
        action == ProtectionAction.lockSession
            ? SecurityEventType.protectionSessionLocked
            : SecurityEventType.protectionBlocked,
    };
    if (type == null) return; // a transition down to `none` is never logged
    final priority = state == EnforcementState.blocked
        ? SecurityEventPriority.critical
        : SecurityEventPriority.high;
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.emit(
        (sequence) => pipeline.factory.enforcementTransition(
          type: type,
          sequence: sequence,
          priority: priority,
          evidence: {
            'action': action.wireName,
            'state': state.wireName,
            'policy_version': policyVersion,
          },
        ),
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Persistent Remote Lock Enforcement milestone — records one remote-lock
  /// lifecycle event. Called from both `RemoteCommandDispatcher` (received/
  /// rejected — before any enforcement decision exists) and
  /// `EnforcementController` (applied/replayed/unlockApplied/
  /// persistenceError — after one does). One event per real occurrence;
  /// callers decide when that is, this method does not deduplicate.
  static Future<void> recordRemoteLockEvent({
    required SecurityEventType type,
    required int commandId,
  }) async {
    final priority = switch (type) {
      SecurityEventType.remoteLockApplied ||
      SecurityEventType.remoteLockRejected ||
      SecurityEventType.remoteLockPersistenceError =>
        SecurityEventPriority.critical,
      SecurityEventType.remoteUnlockApplied =>
        SecurityEventPriority.high,
      _ => SecurityEventPriority.medium,
    };
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.emit(
        (sequence) => pipeline.factory.remoteLockTransition(
          type: type,
          sequence: sequence,
          priority: priority,
          commandId: commandId,
        ),
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Cryptographic Remote Command Integrity milestone — one generic
  /// command-lifecycle event, for every command type. See
  /// [SecurityEventFactory.commandLifecycle].
  static Future<void> recordCommandEvent({
    required SecurityEventType type,
    int? commandId,
    String? commandType,
    String? reason,
  }) async {
    final priority = switch (type) {
      SecurityEventType.commandRejected => SecurityEventPriority.critical,
      SecurityEventType.commandExpired ||
      SecurityEventType.commandReplayed =>
        SecurityEventPriority.high,
      _ => SecurityEventPriority.medium,
    };
    try {
      final pipeline = await _ensurePipeline();
      await pipeline.emit(
        (sequence) => pipeline.factory.commandLifecycle(
          type: type,
          sequence: sequence,
          priority: priority,
          commandId: commandId,
          commandType: commandType,
          reason: reason,
        ),
      );
    } catch (_) {
      // See class doc.
    }
  }

  /// Drains the queue's next batch, alongside the chain metadata a transport
  /// needs to anchor it. `null` when there is nothing queued.
  static Future<SecurityEventBatch?> drainNextBatch() async {
    try {
      final pipeline = await _ensurePipeline();
      final batch = await pipeline.drain();
      if (batch.isEmpty) return null;
      return SecurityEventBatch(
        entries: batch,
        chainHead: pipeline.chainHead,
        context: _context!,
      );
    } catch (_) {
      return null;
    }
  }

  /// Called once a transport confirms the backend accepted [batch].
  static Future<void> acknowledge(SecurityEventBatch batch) async {
    try {
      final pipeline = await _ensurePipeline();
      pipeline.queue.acknowledge(batch.entries);
    } catch (_) {
      // See class doc.
    }
  }

  /// Called when a transport attempt failed — returns the batch to the
  /// queue for the next flush.
  static Future<void> markFailed(SecurityEventBatch batch) async {
    try {
      final pipeline = await _ensurePipeline();
      pipeline.queue.markFailed(batch.entries);
    } catch (_) {
      // See class doc.
    }
  }

  /// Test-only reset. Never called from production code.
  static void resetForTests() {
    _pipeline = null;
    _pipelineInit = null;
    _context = null;
    applicationIdGetterForTests = _defaultApplicationId;
  }
}

/// One drained batch plus the metadata a transport needs to send and later
/// acknowledge it.
class SecurityEventBatch {
  final List<QueuedSecurityEvent> entries;
  final String chainHead;
  final SecurityEventContext context;

  const SecurityEventBatch({
    required this.entries,
    required this.chainHead,
    required this.context,
  });
}
