import '../core/core.dart';
import '../protection/compatibility_decision.dart';
import '../protection/pipeline_mode.dart';
import '../protection/protection_action.dart';
import '../risk/correlation_rule.dart';
import '../risk/risk_assessment.dart';
import '../risk/risk_posture.dart';
import '../trust/trust_anchor.dart';
import '../trust/trust_assessment.dart';
import '../trust/trust_evidence.dart';
import 'security_event.dart';
import 'security_event_queue.dart';
import 'security_event_type.dart';

/// The device+application identity every event is stamped with.
///
/// Carried as one object rather than four parameters because the four are
/// only ever meaningful together: an event with an `applicationId` but no
/// `deviceBindingId` is not half-attributed, it is unattributed. Previously
/// these lived on the *transport*, so an event separated from its HTTP
/// request could not be attributed to anything.
class SecurityEventContext {
  final String sdkVersion;
  final String platform;
  final String applicationId;

  /// The device binding key id, or `null` on an unbound (legacy) device.
  final String? deviceBindingId;

  const SecurityEventContext({
    required this.sdkVersion,
    required this.platform,
    required this.applicationId,
    this.deviceBindingId,
  });

  SecurityEventContext copyWith({String? deviceBindingId}) =>
      SecurityEventContext(
        sdkVersion: sdkVersion,
        platform: platform,
        applicationId: applicationId,
        deviceBindingId: deviceBindingId ?? this.deviceBindingId,
      );
}

/// Builds [SecurityEvent]s from the SDK's existing producers.
///
/// ## Why a factory rather than `toSecurityEvent()` on each producer
///
/// The producers are plain data in `sdk/core`, `sdk/risk`, `sdk/trust` and
/// `sdk/protection`, and several of them (`DetectionResult`,
/// `RiskAssessment`) are deliberately dependency-free — `sdk/core` imports
/// nothing, not even Flutter. Adding an event method to each would invert
/// that: the core layer would depend on the event layer, which depends on
/// secure storage and crypto. Keeping the mapping here preserves the existing
/// layering, and it puts the whole "what becomes an event" decision in one
/// readable file.
///
/// Every method is a **pure function**: no clock beyond an injectable one, no
/// storage, no network. The sequence number is supplied by the caller
/// (`SecurityEventPipeline`), which owns the sequencer.
class SecurityEventFactory {
  final SecurityEventContext context;

  const SecurityEventFactory(this.context);

  /// Priority for a detection-shaped event. Phase 9's mapping, in one place.
  ///
  /// A non-threat verdict is `info` regardless of the detector's configured
  /// severity: "we checked and it was clean" is the least valuable thing in a
  /// full queue, and treating it by the detector's severity would let clean
  /// scans evict real findings.
  static SecurityEventPriority priorityForDetection(DetectionResult result) {
    if (!result.threatDetected || !result.isConclusive) {
      return SecurityEventPriority.info;
    }
    switch (result.severity) {
      case DetectionSeverity.critical:
        return SecurityEventPriority.critical;
      case DetectionSeverity.high:
        return SecurityEventPriority.high;
      case DetectionSeverity.medium:
        return SecurityEventPriority.medium;
      case DetectionSeverity.low:
        return SecurityEventPriority.low;
    }
  }

  /// Priority for a self-integrity event type. Phase 13.
  ///
  /// The four `critical` entries are the ones that mean *the SDK's own
  /// security assumptions have failed* — a tampered SDK, a key that is not
  /// this device's, a forged config, or a mutated transaction. None of those
  /// has a benign reading, and none may be evicted to make room for a
  /// detection.
  static SecurityEventPriority priorityForSelfIntegrity(
    SecurityEventType type,
  ) {
    switch (type) {
      case SecurityEventType.sdkIntegrityFailed:
      case SecurityEventType.deviceKeyMismatch:
      case SecurityEventType.configSignatureFailed:
      case SecurityEventType.transactionTamper:
        return SecurityEventPriority.critical;
      case SecurityEventType.requestReplay:
      case SecurityEventType.licenseTimeAnomaly:
      case SecurityEventType.attestationFailure:
        return SecurityEventPriority.high;
      case SecurityEventType.sdkIntegrityValid:
        return SecurityEventPriority.info;
      default:
        return SecurityEventPriority.medium;
    }
  }

  SecurityEvent _build({
    required SecurityEventType eventType,
    required int sequence,
    required SecurityEventPriority priority,
    DateTime? timestamp,
    String? detectorId,
    DetectionStatus? status,
    DetectionSeverity? severity,
    DetectionConfidence? confidence,
    int? riskScore,
    RiskPosture? posture,
    ProtectionAction? action,
    String? chainId,
    Map<String, Object?>? evidence,
  }) =>
      SecurityEvent.create(
        eventType: eventType,
        sequence: sequence,
        sdkVersion: context.sdkVersion,
        platform: context.platform,
        applicationId: context.applicationId,
        deviceBindingId: context.deviceBindingId,
        timestamp: timestamp,
        detectorId: detectorId,
        status: status,
        severity: severity,
        confidence: confidence,
        riskScore: riskScore,
        posture: posture,
        action: action,
        chainId: chainId,
        priority: priority,
        evidence: evidence,
      );

  /// One scan whose native layer was found unavailable → one event.
  ///
  /// Always `critical` (eviction-protected) — see
  /// `SecurityEventType.nativeLayerUnavailable`'s doc for why an individual
  /// `detection` event with `DetectionStatus.unavailable` (`info` priority,
  /// evictable) is not sufficient on its own.
  ///
  /// Takes the already-computed booleans rather than reading
  /// `RaspNativeChannel` itself — the caller decides whether to call this at
  /// all; this method only records, matching every other `record*`/`from*`
  /// method in this file.
  SecurityEvent fromNativeLayerUnavailable({
    required int sequence,
    required int nativeCallAttempts,
    DateTime? occurredAt,
  }) =>
      _build(
        eventType: SecurityEventType.nativeLayerUnavailable,
        sequence: sequence,
        priority: SecurityEventPriority.critical,
        timestamp: occurredAt,
        evidence: {'native_call_attempts': nativeCallAttempts},
      );

  /// One detection → one event.
  ///
  /// Closes gap **G5**: `ScanTelemetryMapper` flattens a `DetectionResult`
  /// into a boolean before transmission, destroying severity, confidence,
  /// evidence and time. This preserves all four.
  SecurityEvent fromDetection(DetectionResult result, {required int sequence}) {
    final evidence = <String, Object?>{
      'detector_type': result.detectorType.name,
      'category': result.category.name,
      'detector_version': result.detectorVersion,
      'observed_at': result.observedAt.toUtc().toIso8601String(),
      if (result.unavailableReason != null)
        'unavailable_reason': result.unavailableReason,
    };
    for (var i = 0; i < result.evidence.length; i++) {
      final item = result.evidence[i];
      evidence['evidence_${i}_${item.key}'] = item.value;
    }

    return _build(
      eventType: SecurityEventType.detection,
      sequence: sequence,
      priority: priorityForDetection(result),
      timestamp: result.observedAt,
      detectorId: result.detectorId,
      status: result.status,
      severity: result.severity,
      confidence: result.confidence,
      evidence: evidence,
    );
  }

  /// One trust assessment → one event.
  SecurityEvent fromTrustAssessment(
    TrustAssessment assessment, {
    required int sequence,
  }) {
    final evidence = <String, Object?>{
      'trust_level': assessment.level.wireName,
      'anchor_count': assessment.anchors.length,
      'evidence_codes':
          assessment.evidence.map((e) => e.code.wireName).toList()..sort(),
      if (assessment.reasons.isNotEmpty) 'primary_reason': assessment.reasons.first,
    };
    for (final anchor in assessment.anchors) {
      evidence['anchor_${anchor.anchor.name}'] = anchor.state.wireName;
    }

    return _build(
      eventType: SecurityEventType.trustAssessment,
      sequence: sequence,
      priority: assessment.level == TrustLevel.compromised
          ? SecurityEventPriority.critical
          : assessment.level == TrustLevel.suspicious
              ? SecurityEventPriority.high
              : SecurityEventPriority.low,
      timestamp: assessment.evaluatedAt,
      evidence: evidence,
    );
  }

  /// One risk assessment → one event.
  ///
  /// Closes part of gap **G4**: `RiskAssessment` carries no timestamp of its
  /// own, so one must be supplied. Passing it in rather than defaulting to
  /// "now" inside the model keeps the assessment itself dependency-free.
  /// [action]/[policyVersion] — Risk + Response Engine milestone: the
  /// canonical "why was this device blocked?" event now carries the actual
  /// response alongside the score that produced it, and the exact policy
  /// version in force when the decision was made. Both optional so a caller
  /// with only a bare `RiskAssessment` (no `ProtectionResult` yet) still
  /// gets a valid event — this is additive, not a breaking signature change.
  SecurityEvent fromRiskAssessment(
    RiskAssessment assessment, {
    required int sequence,
    DateTime? evaluatedAt,
    ProtectionAction? action,
    int? policyVersion,
    bool recommendRescan = false,
    bool triggeredByRescan = false,
  }) =>
      _build(
        eventType: SecurityEventType.riskAssessment,
        sequence: sequence,
        priority: assessment.posture == RiskPosture.critical
            ? SecurityEventPriority.high
            : SecurityEventPriority.low,
        timestamp: evaluatedAt,
        severity: assessment.highestSeverity,
        confidence: assessment.confidence,
        riskScore: assessment.score,
        posture: assessment.posture,
        action: action,
        evidence: {
          'evaluated_count': assessment.evaluatedCount,
          'indeterminate_count': assessment.indeterminateCount,
          'coverage': assessment.coverage.toStringAsFixed(2),
          'chain_count': assessment.chains.length,
          'contributors':
              assessment.contributions.map((c) => c.detectorId).toList(),
          if (policyVersion != null) 'policy_version': policyVersion,
          if (assessment.reasons.isNotEmpty)
            'primary_reason': assessment.reasons.first,
          // FORCE_RESCAN, in the response engine's action vocabulary — see
          // `ProtectionResult.recommendRescan`'s doc for why this is an
          // evidence flag on the event rather than a `ProtectionAction`.
          if (recommendRescan) 'response': 'FORCE_RESCAN',
          if (triggeredByRescan) 'triggered_by': 'force_rescan',
        },
      );

  /// Phase 11 — **one** structured event per attack chain.
  ///
  /// Explicitly one event, not one per member detector. The member detections
  /// already produced their own events; re-notifying per member would make a
  /// three-signal instrumentation attack look like four incidents, which is
  /// exactly the "multiple redundant notifications" the milestone rules out.
  /// The chain event's job is to say *these separate findings are one attack*,
  /// and [SecurityEvent.chainId] is what lets a console group them.
  SecurityEvent fromAttackChain(
    AttackChain chain, {
    required int sequence,
    DateTime? detectedAt,
  }) =>
      _build(
        eventType: SecurityEventType.correlationChain,
        sequence: sequence,
        priority: chain.severity == DetectionSeverity.critical
            ? SecurityEventPriority.critical
            : SecurityEventPriority.high,
        timestamp: detectedAt,
        severity: chain.severity,
        confidence: chain.confidence,
        riskScore: chain.riskContribution,
        chainId: chain.id,
        evidence: {
          'chain_name': chain.rule.name,
          'matched_signals': (chain.matchedSignals.toList()..sort()),
          'supporting_signals': (chain.supportingSignals.toList()..sort()),
          'risk_contribution': chain.riskContribution,
          'description': chain.rule.description,
        },
      );

  /// Phase 12 — one event per protection action, carrying the full
  /// legacy/risk/final tuple.
  ///
  /// This is the event that makes SHADOW and COMPATIBILITY monitoring
  /// meaningful: without `legacyAction` alongside `finalAction` there is no
  /// way to tell whether the risk pipeline would have changed anything, which
  /// is the entire question a staged rollout exists to answer. The shape
  /// mirrors `RolloutObservation` — an existing model this SDK already ships
  /// — rather than inventing a parallel one.
  ///
  /// **`AUTHORITATIVE` is not representable**: [PipelineMode] has no such
  /// value, so no event can claim it.
  SecurityEvent fromProtectionDecision({
    required int sequence,
    required CompatibilityDecision decision,
    required PipelineMode rolloutMode,
    TrustLevel? trustLevel,
    DateTime? decidedAt,
  }) {
    final chosen = decision.chosen;
    final action = decision.action;
    return _build(
      eventType: SecurityEventType.protectionDecision,
      sequence: sequence,
      priority: action.index >= ProtectionAction.block.index
          ? SecurityEventPriority.critical
          : action.index >= ProtectionAction.warn.index
              ? SecurityEventPriority.high
              : SecurityEventPriority.low,
      timestamp: decidedAt ?? chosen?.evaluatedAt,
      severity: chosen?.highestSeverity,
      riskScore: chosen?.riskScore,
      posture: chosen?.posture,
      action: action,
      evidence: {
        'legacy_action': decision.legacy?.recommendedAction.wireName ?? 'none',
        'risk_action': decision.risk?.recommendedAction.wireName ?? 'none',
        'final_action': action.wireName,
        'rollout_mode': rolloutMode.wireName,
        'reason': decision.source.name,
        'escalated_beyond_legacy': decision.escalatedBeyondLegacy,
        if (trustLevel != null) 'trust_state': trustLevel.wireName,
        if (chosen != null) 'policy_version': chosen.policyVersion,
      },
    );
  }

  /// Phase 13 — one of the eight SDK self-integrity events.
  ///
  /// These describe the SDK's own security machinery failing, which no
  /// `DetectionResult` represents today (gap **G18**) — a detector reports on
  /// the *device*, while these report on *the SDK's ability to make claims at
  /// all*. Passing a [detectorId] is therefore optional and unusual; when a
  /// detector genuinely produced the same finding, emit its detection event
  /// instead of duplicating it here.
  SecurityEvent selfIntegrity({
    required SecurityEventType type,
    required int sequence,
    String? detectorId,
    DetectionSeverity? severity,
    DetectionConfidence? confidence,
    DateTime? occurredAt,
    Map<String, Object?>? evidence,
  }) {
    assert(
      type.isSelfIntegrity,
      'selfIntegrity() accepts only the Phase 13 event types',
    );
    return _build(
      eventType: type,
      sequence: sequence,
      priority: priorityForSelfIntegrity(type),
      timestamp: occurredAt,
      detectorId: detectorId,
      severity: severity,
      confidence: confidence,
      evidence: evidence,
    );
  }

  /// Continuous Security Telemetry milestone — [SecurityEventType.
  /// activationSucceeded]. Low priority: a routine success, not an anomaly
  /// (matching the priority this SDK already gives every other "expected,
  /// working as intended" fact).
  SecurityEvent activationSucceeded({
    required int sequence,
    DateTime? occurredAt,
    Map<String, Object?>? evidence,
  }) =>
      _build(
        eventType: SecurityEventType.activationSucceeded,
        sequence: sequence,
        priority: SecurityEventPriority.low,
        timestamp: occurredAt,
        evidence: evidence,
      );

  /// [SecurityEventType.heartbeatFailed] / [heartbeatRecovered] — a single
  /// factory for both, since they differ only in [recovered] and priority.
  SecurityEvent heartbeatOutcome({
    required int sequence,
    required bool recovered,
    DateTime? occurredAt,
    Map<String, Object?>? evidence,
  }) =>
      _build(
        eventType: recovered
            ? SecurityEventType.heartbeatRecovered
            : SecurityEventType.heartbeatFailed,
        sequence: sequence,
        priority:
            recovered ? SecurityEventPriority.low : SecurityEventPriority.high,
        timestamp: occurredAt,
        evidence: evidence,
      );

  /// The queue's own overflow report.
  SecurityEvent queueOverflow({
    required int sequence,
    required SecurityEventQueueOverflow overflow,
    DateTime? occurredAt,
  }) =>
      _build(
        eventType: SecurityEventType.queueOverflow,
        sequence: sequence,
        priority: overflow.droppedCritical > 0
            ? SecurityEventPriority.critical
            : SecurityEventPriority.high,
        timestamp: occurredAt,
        evidence: overflow.evidence(),
      );

  /// Phase 14 (Sensitive Operation Protection Engine) — one of the six
  /// `sensitiveOperation*` event types. Kept generic here (no dependency on
  /// `sdk/security/sensitive_operation/`, which is a higher layer than
  /// `sdk/events/`) — `SecurityEventCenter` maps a
  /// `SensitiveOperationAction`/`AuthorizationState` to the right
  /// [SecurityEventType] and calls this.
  SecurityEvent sensitiveOperation({
    required SecurityEventType type,
    required int sequence,
    SecurityEventPriority priority = SecurityEventPriority.medium,
    String? operationId,
    DateTime? occurredAt,
    Map<String, Object?>? evidence,
  }) {
    assert(
      type == SecurityEventType.sensitiveOperationAllowed ||
          type == SecurityEventType.sensitiveOperationStepUp ||
          type == SecurityEventType.sensitiveOperationRestricted ||
          type == SecurityEventType.sensitiveOperationBlocked ||
          type == SecurityEventType.sensitiveOperationTampered ||
          type == SecurityEventType.sensitiveOperationReplayed ||
          type == SecurityEventType.sensitiveOperationBackendAllowed ||
          type == SecurityEventType.sensitiveOperationBackendRejected ||
          type == SecurityEventType.sensitiveOperationBackendReplayed ||
          type == SecurityEventType.sensitiveOperationBackendError,
      'sensitiveOperation() accepts only the sensitive-operation types',
    );
    return _build(
      eventType: type,
      sequence: sequence,
      priority: priority,
      timestamp: occurredAt,
      evidence: {
        if (operationId != null) 'operation_id': operationId,
        ...?evidence,
      },
    );
  }

  /// Authoritative Protection Engine V1 — one enforcement-state transition.
  /// Kept generic here for the same reason [sensitiveOperation] is: no
  /// dependency on `sdk/protection/`, which sits above `sdk/events/` in the
  /// layering. `SecurityEventCenter` maps an `EnforcementState` to the
  /// right [SecurityEventType] and calls this.
  SecurityEvent enforcementTransition({
    required SecurityEventType type,
    required int sequence,
    SecurityEventPriority priority = SecurityEventPriority.high,
    DateTime? occurredAt,
    Map<String, Object?>? evidence,
  }) {
    assert(
      type == SecurityEventType.protectionWarned ||
          type == SecurityEventType.protectionStepUp ||
          type == SecurityEventType.protectionRestricted ||
          type == SecurityEventType.protectionBlocked ||
          type == SecurityEventType.protectionSessionLocked,
      'enforcementTransition() accepts only the enforcement-state types',
    );
    return _build(
      eventType: type,
      sequence: sequence,
      priority: priority,
      timestamp: occurredAt,
      evidence: {...?evidence},
    );
  }

  /// Persistent Remote Lock Enforcement milestone — one remote-lock
  /// lifecycle event. Kept generic here for the same reason
  /// [enforcementTransition] is.
  SecurityEvent remoteLockTransition({
    required SecurityEventType type,
    required int sequence,
    SecurityEventPriority priority = SecurityEventPriority.high,
    int? commandId,
    DateTime? occurredAt,
    Map<String, Object?>? evidence,
  }) {
    assert(
      type == SecurityEventType.remoteLockReceived ||
          type == SecurityEventType.remoteLockApplied ||
          type == SecurityEventType.remoteLockReplayed ||
          type == SecurityEventType.remoteLockRejected ||
          type == SecurityEventType.remoteUnlockApplied ||
          type == SecurityEventType.remoteLockPersistenceError,
      'remoteLockTransition() accepts only the remote-lock event types',
    );
    return _build(
      eventType: type,
      sequence: sequence,
      priority: priority,
      timestamp: occurredAt,
      evidence: {
        if (commandId != null) 'command_id': commandId,
        ...?evidence,
      },
    );
  }

  /// Cryptographic Remote Command Integrity milestone — one generic
  /// command-lifecycle event, applicable to every command type (not only
  /// `LOCK_APP`/`UNLOCK_APP`). Kept generic here for the same reason
  /// [remoteLockTransition] is.
  SecurityEvent commandLifecycle({
    required SecurityEventType type,
    required int sequence,
    SecurityEventPriority priority = SecurityEventPriority.medium,
    int? commandId,
    String? commandType,
    String? reason,
    DateTime? occurredAt,
  }) {
    assert(
      type == SecurityEventType.commandReceived ||
          type == SecurityEventType.commandVerified ||
          type == SecurityEventType.commandRejected ||
          type == SecurityEventType.commandExpired ||
          type == SecurityEventType.commandReplayed ||
          type == SecurityEventType.commandExecuted ||
          type == SecurityEventType.commandAcknowledged,
      'commandLifecycle() accepts only the remote-command lifecycle event types',
    );
    return _build(
      eventType: type,
      sequence: sequence,
      priority: priority,
      timestamp: occurredAt,
      evidence: {
        if (commandId != null) 'command_id': commandId,
        if (commandType != null) 'command_type': commandType,
        // `reason` is a fixed category label this SDK chose (e.g.
        // "malformed", "invalid_signature", "device_mismatch") — never
        // attacker-controlled free text, matching every other evidence
        // field's "category, not value" discipline.
        if (reason != null) 'reason': reason,
      },
    );
  }

  /// The sequencer's own failure report. See `SecurityEventSequencer`.
  SecurityEvent sequenceIntegrityError({
    required int sequence,
    required String state,
    DateTime? occurredAt,
  }) =>
      _build(
        eventType: SecurityEventType.sequenceIntegrityError,
        sequence: sequence,
        priority: SecurityEventPriority.critical,
        timestamp: occurredAt,
        evidence: {'sequence_state': state},
      );
}
