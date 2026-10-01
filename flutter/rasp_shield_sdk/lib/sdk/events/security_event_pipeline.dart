import 'dart:async';

import 'package:flutter/foundation.dart';

import '../core/core.dart';
import '../protection/compatibility_decision.dart';
import '../protection/pipeline_mode.dart';
import '../protection/protection_action.dart';
import '../risk/correlation_rule.dart';
import '../risk/risk_assessment.dart';
import '../trust/trust_assessment.dart';
import 'security_event.dart';
import 'security_event_chain.dart';
import 'security_event_dedup.dart';
import 'security_event_factory.dart';
import 'security_event_queue.dart';
import 'security_event_sequence.dart';
import 'security_event_type.dart';

/// The one place the event subsystem's parts meet.
///
/// ```
///   producer ──▶ factory ──▶ dedup ──▶ sequencer ──▶ chain ──▶ queue
/// ```
///
/// ## Ordering matters, and this is the order
///
/// Deduplication runs **before** a sequence number is consumed and before the
/// event is sealed. Sealing a suppressed event would put it in the hash chain
/// and then discard it, which breaks the chain for everything after it —
/// a deleted link is precisely what `SecurityEventChainVerifier` is built to
/// detect, so the pipeline must never create one deliberately. Every sequence
/// number that is issued therefore corresponds to exactly one sealed, queued
/// event.
///
/// This does mean an event's identity (`eventId`) is minted before it may be
/// suppressed, and a suppressed event's id is simply discarded. That is
/// cheap — 16 random bytes — and it keeps the invariant that matters.
///
/// ## It owns no timer and no socket
///
/// [drain] returns the batch a caller should transmit and does not transmit
/// it. Transmission stays with the existing heartbeat-driven reporters, per
/// the milestone's "do NOT create another independent scheduler" and "do NOT
/// create a second telemetry system" constraints.
class SecurityEventPipeline {
  final SecurityEventFactory factory;
  final SecurityEventSequencer sequencer;
  final SecurityEventDeduplicator deduplicator;
  final SecurityEventChain chain;
  final SecurityEventQueue queue;

  bool _reportedSequenceProblem = false;
  Future<void> _tail = Future<void>.value();

  SecurityEventPipeline({
    required this.factory,
    SecurityEventSequencer? sequencer,
    SecurityEventDeduplicator? deduplicator,
    SecurityEventChain? chain,
    SecurityEventQueue? queue,
  })  : sequencer = sequencer ?? SecurityEventSequencer(),
        deduplicator = deduplicator ?? SecurityEventDeduplicator(),
        chain = chain ?? SecurityEventChain(),
        queue = queue ?? SecurityEventQueue();

  /// Serialises the sequence-allocate → seal → enqueue critical section.
  ///
  /// **This is load-bearing, not defensive.** Allocating a sequence number is
  /// asynchronous (it can touch secure storage), so two concurrent producers —
  /// which is the normal case, since detectors run in parallel — can otherwise
  /// interleave: producer A takes sequence 5, awaits, producer B takes 6 and
  /// seals first, and the chain now runs 6 → 5. `SecurityEventChainVerifier`
  /// correctly rejects that as `sequenceRollback`, so an unserialised pipeline
  /// produces batches the backend must refuse. Found by the concurrency test
  /// in `security_event_test.dart`, not reasoned about in advance.
  Future<T> _serialized<T>(Future<T> Function() action) {
    final result = _tail.then((_) => action());
    _tail = result.then<void>((_) {}, onError: (_) {});
    return result;
  }

  /// Loads persisted sequence state. Safe to call more than once.
  Future<void> initialize() => _serialized(() async {
        await sequencer.initialize();
        await _reportSequenceProblemIfAny();
      });

  /// Submits an already-built event through dedup → seal → queue.
  ///
  /// Returns the sealed event, or `null` when it was deduplicated. Never
  /// throws for an ordinary event: a [CanonicalFieldError] from a field
  /// containing the canonical delimiter is caught and turned into a dropped
  /// event rather than propagating into a scan, because a producer's bad
  /// field must not be able to abort the security scan that produced it.
  Future<SealedSecurityEvent?> submit(
    SecurityEvent event, {
    DateTime? now,
  }) =>
      _serialized(() => _submitLocked(event, now: now));

  Future<SealedSecurityEvent?> _submitLocked(
    SecurityEvent event, {
    DateTime? now,
  }) async {
    final decision = deduplicator.evaluate(event, now: now);
    if (!decision.emit) return null;

    try {
      final sealed = chain.seal(event);
      queue.enqueue(sealed, now: now);
      return sealed;
    } catch (error) {
      // Only a canonicalisation failure can land here. Reported, not
      // swallowed — but reported through debug logging rather than as an
      // event, because building the event is exactly what just failed.
      debugPrint(
        '[RASP-TRACE] EVENT-SEAL FAIL type=${event.eventType.wireName} '
        'error=${error.runtimeType}',
      );
      return null;
    }
  }

  /// Convenience: allocate a sequence number, build via [build], submit.
  Future<SealedSecurityEvent?> emit(
    SecurityEvent Function(int sequence) build, {
    DateTime? now,
  }) =>
      _serialized(() => _emitLocked(build, now: now));

  Future<SealedSecurityEvent?> _emitLocked(
    SecurityEvent Function(int sequence) build, {
    DateTime? now,
  }) async {
    // Reported *before* this event takes its number, so the integrity-error
    // event's sequence is lower than the event that follows it. Reporting
    // afterwards would seal a higher-numbered event first and break the very
    // ordering the report is complaining about.
    await _reportSequenceProblemIfAny(now: now);
    final sequence = await sequencer.next();
    return _submitLocked(build(sequence), now: now);
  }

  Future<SealedSecurityEvent?> recordDetection(
    DetectionResult result, {
    DateTime? now,
  }) =>
      emit((s) => factory.fromDetection(result, sequence: s), now: now);

  Future<SealedSecurityEvent?> recordNativeLayerUnavailable(
    int nativeCallAttempts, {
    DateTime? now,
  }) =>
      emit(
        (s) => factory.fromNativeLayerUnavailable(
          sequence: s,
          nativeCallAttempts: nativeCallAttempts,
        ),
        now: now,
      );

  Future<SealedSecurityEvent?> recordTrustAssessment(
    TrustAssessment assessment, {
    DateTime? now,
  }) =>
      emit((s) => factory.fromTrustAssessment(assessment, sequence: s),
          now: now);

  Future<SealedSecurityEvent?> recordRiskAssessment(
    RiskAssessment assessment, {
    DateTime? evaluatedAt,
    DateTime? now,
    ProtectionAction? action,
    int? policyVersion,
    bool recommendRescan = false,
    bool triggeredByRescan = false,
  }) =>
      emit(
        (s) => factory.fromRiskAssessment(
          assessment,
          sequence: s,
          evaluatedAt: evaluatedAt,
          action: action,
          policyVersion: policyVersion,
          recommendRescan: recommendRescan,
          triggeredByRescan: triggeredByRescan,
        ),
        now: now,
      );

  /// Phase 11 — one event per chain, no per-member re-notification.
  Future<List<SealedSecurityEvent>> recordAttackChains(
    List<AttackChain> chains, {
    DateTime? detectedAt,
    DateTime? now,
  }) async {
    final sealed = <SealedSecurityEvent>[];
    for (final attackChain in chains) {
      final result = await emit(
        (s) => factory.fromAttackChain(
          attackChain,
          sequence: s,
          detectedAt: detectedAt,
        ),
        now: now,
      );
      if (result != null) sealed.add(result);
    }
    return sealed;
  }

  /// Phase 12.
  Future<SealedSecurityEvent?> recordProtectionDecision({
    required CompatibilityDecision decision,
    required PipelineMode rolloutMode,
    TrustLevel? trustLevel,
    DateTime? decidedAt,
    DateTime? now,
  }) =>
      emit(
        (s) => factory.fromProtectionDecision(
          sequence: s,
          decision: decision,
          rolloutMode: rolloutMode,
          trustLevel: trustLevel,
          decidedAt: decidedAt,
        ),
        now: now,
      );

  /// Continuous Security Telemetry milestone.
  Future<SealedSecurityEvent?> recordActivationSucceeded({
    Map<String, Object?>? evidence,
    DateTime? occurredAt,
    DateTime? now,
  }) =>
      emit(
        (s) => factory.activationSucceeded(
          sequence: s, evidence: evidence, occurredAt: occurredAt,
        ),
        now: now,
      );

  /// Continuous Security Telemetry milestone.
  Future<SealedSecurityEvent?> recordHeartbeatOutcome({
    required bool recovered,
    Map<String, Object?>? evidence,
    DateTime? occurredAt,
    DateTime? now,
  }) =>
      emit(
        (s) => factory.heartbeatOutcome(
          sequence: s, recovered: recovered, evidence: evidence,
          occurredAt: occurredAt,
        ),
        now: now,
      );

  /// Phase 13.
  Future<SealedSecurityEvent?> recordSelfIntegrity({
    required SecurityEventType type,
    String? detectorId,
    DetectionSeverity? severity,
    DetectionConfidence? confidence,
    Map<String, Object?>? evidence,
    DateTime? occurredAt,
    DateTime? now,
  }) =>
      emit(
        (s) => factory.selfIntegrity(
          type: type,
          sequence: s,
          detectorId: detectorId,
          severity: severity,
          confidence: confidence,
          evidence: evidence,
          occurredAt: occurredAt,
        ),
        now: now,
      );

  /// Expires aged entries, reports any drops, and returns the next batch to
  /// transmit. Returns an empty list when there is nothing to send.
  ///
  /// The overflow event is emitted **before** the batch is taken, so a drop
  /// that happened while offline is reported in the same batch as the events
  /// that survived it — an operator sees "12 events, 3 dropped" together
  /// rather than learning about the loss a cycle later.
  Future<List<QueuedSecurityEvent>> drain({DateTime? now}) =>
      _serialized(() async {
        queue.expire(now: now);
        final overflow = queue.drainOverflowNotice();
        if (overflow != null && !overflow.isEmpty) {
          final sequence = await sequencer.next();
          await _submitLocked(
            factory.queueOverflow(
              sequence: sequence,
              overflow: overflow,
              occurredAt: now,
            ),
            now: now,
          );
        }
        return queue.nextBatch();
      });

  /// The chain digest a batch should be anchored to. Sent alongside a batch
  /// so a whole missing batch is detectable, not just a missing event.
  String get chainHead => chain.head;

  Future<void> _reportSequenceProblemIfAny({DateTime? now}) async {
    if (sequencer.state.isTrustworthy) return;
    if (_reportedSequenceProblem) return;
    _reportedSequenceProblem = true;

    // Deliberately uses the sequencer that just failed: a number that may be
    // untrustworthy is still better than no event, and the event's own
    // evidence says exactly which state the sequencer is in.
    final sequence = await sequencer.next();
    await _submitLocked(
      factory.sequenceIntegrityError(
        sequence: sequence,
        state: sequencer.state.wireName,
        occurredAt: now,
      ),
      now: now,
    );
  }

  @visibleForTesting
  void resetForTests() {
    deduplicator.reset();
    queue.clear();
    _reportedSequenceProblem = false;
  }
}
