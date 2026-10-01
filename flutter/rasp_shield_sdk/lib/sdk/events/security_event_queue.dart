/// Phase 6 — the offline queue, and Phase 9 — priority.
///
/// ## It reuses the existing scheduler; it does not add one
///
/// This class holds events and decides what to send. It **never starts a
/// timer, never opens a socket, and never calls Dio.** Draining is driven by
/// `SecurityEventPipeline`, which is in turn driven by the heartbeat cycle
/// that `DeviceLogReporter.flush()` already rides — the milestone's "do NOT
/// create another independent scheduler" constraint, and the same discipline
/// `RemoteCommandDispatcher` already follows.
///
/// ## Lifecycle
///
/// ```
///   enqueue ──▶ QUEUED ──nextBatch──▶ SENT ──acknowledge──▶ (removed)
///                  ▲                    │
///                  └────markFailed──────┘   (→ RETRYING, attempts++)
///                  │
///                  └── expire ──▶ DROPPED_EXPIRED (removed)
/// ```
///
/// **`SENT` is not `ACKNOWLEDGED`.** An HTTP 200 that never reached the client
/// is indistinguishable from a request that never arrived, so an event leaves
/// the queue only on an explicit acknowledgement. That mirrors the one
/// existing flow in this SDK with a real ACK (`remote_commands` +
/// `POST /commands/{id}/ack`) rather than inventing new semantics.
///
/// ## Bounded, and honest about it
///
/// Two independent bounds, because they fail differently:
///
/// - **[capacity]** — a flood (a detector loop, or an attacker deliberately
///   triggering detections to push evidence of their own attack out of the
///   queue) is capped by count.
/// - **[retention]** — an event that has been undeliverable for longer than
///   this is dropped by age, so a permanently-offline device does not carry a
///   week-old queue forever. `DeviceLogReporter` has no age bound at all
///   today (gap **G10**); this closes it.
///
/// ## Critical events are never *silently* dropped
///
/// Eviction removes the lowest-priority, oldest event first, and
/// [SecurityEventPriority.critical] is only ever considered once every other
/// priority is exhausted. If a critical event is dropped anyway — the queue
/// full of nothing but critical events, which is itself a finding — the drop
/// is counted in [criticalDropCount] and [drainOverflowNotice] returns a
/// [SecurityEventType.queueOverflow] description for the pipeline to emit as
/// a real event. The milestone's requirement is that a critical drop is not
/// *silent*; a bounded queue that could never drop anything would be an
/// unbounded queue.
library;

import 'dart:async';
import 'dart:math' as math;

import 'package:flutter/foundation.dart';

import 'security_event_chain.dart';
import 'security_event_type.dart';


/// Where one queued event is in its lifecycle.
enum SecurityEventQueueState {
  /// Waiting to be sent.
  queued,

  /// Handed to the transport, awaiting acknowledgement.
  sent,

  /// A send attempt failed; eligible again on the next drain.
  retrying,

  /// Acknowledged by the backend. Terminal — the entry is removed.
  acknowledged,

  /// Dropped because it exceeded [SecurityEventQueue.retention]. Terminal.
  droppedExpired,
}

extension SecurityEventQueueStateX on SecurityEventQueueState {
  String get wireName {
    switch (this) {
      case SecurityEventQueueState.queued:
        return 'QUEUED';
      case SecurityEventQueueState.sent:
        return 'SENT';
      case SecurityEventQueueState.retrying:
        return 'RETRYING';
      case SecurityEventQueueState.acknowledged:
        return 'ACK';
      case SecurityEventQueueState.droppedExpired:
        return 'DROPPED_EXPIRED';
    }
  }
}

/// One event in the queue, with its delivery bookkeeping.
class QueuedSecurityEvent {
  final SealedSecurityEvent sealed;
  final DateTime queuedAt;
  SecurityEventQueueState state;
  int attempts;

  /// Set by [SecurityEventQueue.markFailed] — exponential backoff. `null`
  /// means eligible now (never failed, or never retried yet).
  DateTime? nextEligibleAt;

  QueuedSecurityEvent({
    required this.sealed,
    required this.queuedAt,
    this.state = SecurityEventQueueState.queued,
    this.attempts = 0,
    this.nextEligibleAt,
  });

  SecurityEventPriority get priority => sealed.event.priority;

  /// Durable-queue persistence round trip — see `SecurityEventQueueStore`.
  Map<String, Object?> toMap() => {
        'sealed': sealed.toMap(),
        'queued_at': queuedAt.toIso8601String(),
        'state': state.wireName,
        'attempts': attempts,
        if (nextEligibleAt != null)
          'next_eligible_at': nextEligibleAt!.toIso8601String(),
      };

  /// `null` on anything malformed — a corrupted persisted entry is dropped,
  /// never crashes queue restoration.
  static QueuedSecurityEvent? fromMap(Map<String, Object?> map) {
    try {
      final sealedRaw = map['sealed'];
      if (sealedRaw is! Map) return null;
      final sealed = SealedSecurityEvent.fromMap(
        sealedRaw.map((k, v) => MapEntry(k.toString(), v)),
      );
      if (sealed == null) return null;
      final queuedAt = DateTime.parse(map['queued_at'] as String);
      final stateWire = map['state'] as String?;
      // A restored entry mid-flight ("SENT", awaiting an ACK that may have
      // arrived while the process was dead) is restarted as RETRYING, never
      // left SENT forever and never silently re-considered ACKed — the same
      // "an ACK that never reached the client must not be assumed" rule
      // this queue's own design doc states for the live, in-memory case.
      final state = stateWire == SecurityEventQueueState.sent.wireName
          ? SecurityEventQueueState.retrying
          : SecurityEventQueueState.values.firstWhere(
              (s) => s.wireName == stateWire,
              orElse: () => SecurityEventQueueState.queued,
            );
      final nextEligibleRaw = map['next_eligible_at'] as String?;
      return QueuedSecurityEvent(
        sealed: sealed,
        queuedAt: queuedAt,
        state: state,
        attempts: map['attempts'] as int? ?? 0,
        nextEligibleAt:
            nextEligibleRaw != null ? DateTime.parse(nextEligibleRaw) : null,
      );
    } catch (_) {
      return null;
    }
  }

  @override
  String toString() =>
      'QueuedSecurityEvent(seq=${sealed.event.sequence}, ${state.wireName}, '
      'attempts=$attempts)';
}

/// Durable at-rest storage for a [SecurityEventQueue] — the "survive a
/// process kill" half of the durable-offline-queue requirement. Plain
/// `List<QueuedSecurityEvent>` held only in memory (the pre-milestone
/// state) is lost the instant the OS kills the process, not just when the
/// app backgrounds; this interface is what closes that gap. See
/// `SecureSecurityEventQueueStore` for the real implementation and
/// `docs/CONTINUOUS_SECURITY_TELEMETRY.md` for the exact guarantee this
/// does and does not make.
abstract class SecurityEventQueueStore {
  Future<void> save(List<QueuedSecurityEvent> entries);
  Future<List<QueuedSecurityEvent>> load();
  Future<void> clear();
}

/// Why something was dropped, for the overflow notice.
class SecurityEventQueueOverflow {
  final int droppedTotal;
  final int droppedCritical;
  final int droppedExpired;

  const SecurityEventQueueOverflow({
    required this.droppedTotal,
    required this.droppedCritical,
    required this.droppedExpired,
  });

  bool get isEmpty =>
      droppedTotal == 0 && droppedCritical == 0 && droppedExpired == 0;

  Map<String, Object?> evidence() => {
        'dropped_total': droppedTotal,
        'dropped_critical': droppedCritical,
        'dropped_expired': droppedExpired,
      };
}

/// A bounded, priority-aware, ordered event queue.
class SecurityEventQueue {
  /// Maximum entries held at once, across all states.
  ///
  /// 512 is deliberately larger than `DeviceLogReporter`'s 200: a log line is
  /// diagnostic, a security event is evidence, and the memory cost of a
  /// sealed event (a few hundred bytes) makes 512 negligible against the
  /// benefit of surviving a longer offline stretch intact.
  final int capacity;

  /// Maximum age before an entry is dropped by [expire].
  final Duration retention;

  /// Maximum entries handed out by one [nextBatch] call.
  ///
  /// 50 matches `DeviceLogReporter._maxBatchSize` exactly — same transport
  /// cadence, same backend, no reason for two different batch sizes.
  final int maxBatchSize;

  /// Base delay before the first retry. Doubles per attempt (capped at
  /// [maxBackoff]) so a persistently-unreachable backend is not hit on
  /// every heartbeat indefinitely — see this file's module doc, "no
  /// infinite retry" gap this closes.
  final Duration baseBackoff;
  final Duration maxBackoff;

  /// Optional durable persistence — `null` (the default) preserves the
  /// exact pre-milestone in-memory-only behaviour, e.g. for tests that
  /// don't want platform-channel storage calls. `RaspShield` wires a real
  /// [SecureSecurityEventQueueStore] in production. See [restore].
  final SecurityEventQueueStore? store;

  final List<QueuedSecurityEvent> _entries = [];

  int _droppedTotal = 0;
  int _droppedCritical = 0;
  int _droppedExpired = 0;

  SecurityEventQueue({
    this.capacity = 512,
    this.retention = const Duration(days: 3),
    this.maxBatchSize = 50,
    this.baseBackoff = const Duration(seconds: 30),
    this.maxBackoff = const Duration(minutes: 30),
    this.store,
  });

  /// Loads persisted entries (if any) into this queue. Call once, before
  /// the first [enqueue]/[nextBatch] — normally from `RaspShield`
  /// initialization. Never throws; a store read failure leaves the queue
  /// empty, exactly as it would have been on any build predating this
  /// milestone.
  Future<void> restore() async {
    final persisted = await store?.load() ?? const [];
    if (persisted.isEmpty) return;
    _entries.addAll(persisted);
    _entries.sort((a, b) => a.sealed.event.sequence.compareTo(b.sealed.event.sequence));
    _evictIfNeeded();
    _persist();
  }

  /// Fire-and-forget persist — never awaited by a mutating call, so a slow
  /// or failing store write can never make `enqueue`/`acknowledge`/etc
  /// block or throw. The in-memory queue is always the authoritative,
  /// immediately-consistent state; the store is a best-effort mirror of it.
  void _persist() {
    final s = store;
    if (s == null) return;
    unawaited(s.save(List.unmodifiable(_entries)));
  }

  int get length => _entries.length;

  bool get isEmpty => _entries.isEmpty;

  /// Entries not currently awaiting acknowledgement.
  int get pendingCount => _entries
      .where((e) => e.state != SecurityEventQueueState.sent)
      .length;

  /// Total events discarded for capacity, since the last overflow drain.
  int get droppedCount => _droppedTotal;

  /// Critical events discarded for capacity, since the last overflow drain.
  int get criticalDropCount => _droppedCritical;

  /// Events discarded for age, since the last overflow drain.
  int get expiredCount => _droppedExpired;

  @visibleForTesting
  List<QueuedSecurityEvent> get entries => List.unmodifiable(_entries);

  /// Adds [sealed] to the queue, evicting if necessary.
  ///
  /// Insertion is **append-only in sequence order**. The queue never reorders
  /// by priority: priority governs what is discarded, never what is sent
  /// first, because reordering the send order would break the hash chain the
  /// backend verifies (`SecurityEventChainVerifier` requires the batch in
  /// chain order). Getting this wrong is the subtle way a priority queue
  /// silently defeats an integrity chain.
  void enqueue(SealedSecurityEvent sealed, {DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();
    _entries.add(QueuedSecurityEvent(sealed: sealed, queuedAt: at));
    _evictIfNeeded();
    _persist();
  }

  /// Drops entries older than [retention]. Returns how many were dropped.
  ///
  /// Age is measured from [QueuedSecurityEvent.queuedAt], not from the
  /// event's own timestamp, so a device whose clock jumped does not
  /// mass-expire its queue — the clock-rollback lesson from
  /// `docs/OFFLINE_CLOCK_TAMPERING.md` applied here.
  int expire({DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();
    final before = _entries.length;
    _entries.removeWhere((e) => at.difference(e.queuedAt) > retention);
    final dropped = before - _entries.length;
    _droppedExpired += dropped;
    if (dropped > 0) _persist();
    return dropped;
  }

  /// The next batch to send, in chain order, marked [SecurityEventQueueState.sent].
  ///
  /// Returns an empty list when nothing is currently sendable — the queue is
  /// empty, everything is already [SecurityEventQueueState.sent] awaiting
  /// acknowledgement, or the **earliest pending entry** is still inside its
  /// backoff window ([QueuedSecurityEvent.nextEligibleAt] in the future).
  ///
  /// ## Why this stops instead of skipping
  ///
  /// `_entries` is always in ascending [SecurityEvent.sequence] order (see
  /// [enqueue], [restore]), and the backend's hash-chain verifier requires a
  /// batch to be a **contiguous** run of sequences anchored at its own
  /// last-accepted digest (`device_security_event_chain_state.chain_head`).
  /// Skipping a not-yet-eligible earlier entry to send later, eligible ones
  /// would hand the transport a batch with a sequence gap — the backend
  /// correctly rejects that (`409 CHAIN_DISCONTINUITY` when the gap is at
  /// the batch's start, `422 CHAIN_INVALID` / `brokenLink` when the gap
  /// falls inside an otherwise-eligible run) and the queue could never
  /// drain, no matter how long it retries. So selection walks entries in
  /// sequence order and **stops** — never skips — at the first entry that
  /// is not currently sendable (still `sent`, or still backing off). An
  /// entry can therefore never be permanently leapfrogged by a later one:
  /// it is always the next entry reconsidered on every subsequent call, and
  /// nothing sequenced after it is ever sent ahead of it.
  ///
  /// This is also why priority ([SecurityEventPriority]) plays no part in
  /// batch selection, only in [_evictIfNeeded]'s capacity trimming — see
  /// [enqueue]'s doc. A priority-ordered send would reorder the batch away
  /// from true chain order and break exactly the same invariant.
  List<QueuedSecurityEvent> nextBatch({DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();
    final batch = <QueuedSecurityEvent>[];
    for (final entry in _entries) {
      // A still-in-flight entry (awaiting ACK from a prior, unresolved
      // batch) and a still-backed-off entry are both "not yet sendable" for
      // the same reason: anything sequenced after either one must wait, or
      // the resulting batch would not be contiguous with what the backend
      // has already accepted (or is already mid-verifying).
      if (entry.state == SecurityEventQueueState.sent) break;
      final eligible = entry.nextEligibleAt;
      if (eligible != null && eligible.isAfter(at)) break;
      batch.add(entry);
      if (batch.length >= maxBatchSize) break;
    }
    for (final entry in batch) {
      entry.state = SecurityEventQueueState.sent;
      entry.attempts++;
    }
    if (batch.isNotEmpty) _persist();
    return batch;
  }

  /// Removes [batch] — the backend confirmed receipt.
  void acknowledge(List<QueuedSecurityEvent> batch) {
    final acknowledged = batch.toSet();
    for (final entry in acknowledged) {
      entry.state = SecurityEventQueueState.acknowledged;
    }
    _entries.removeWhere(acknowledged.contains);
    if (acknowledged.isNotEmpty) _persist();
  }

  /// Returns [batch] to the queue for another attempt, scheduled no sooner
  /// than an exponentially growing delay from now — [baseBackoff] doubled
  /// per attempt, capped at [maxBackoff]. A persistently-unreachable
  /// backend is therefore hit with a shrinking, bounded frequency rather
  /// than once every heartbeat forever; the event itself is still only
  /// ever removed by [acknowledge] or age-based [expire] — backoff paces
  /// retries, it does not itself drop anything.
  void markFailed(List<QueuedSecurityEvent> batch, {DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();
    for (final entry in batch) {
      if (entry.state == SecurityEventQueueState.sent) {
        entry.state = SecurityEventQueueState.retrying;
        final factor = math.min(entry.attempts, 10); // bound 2^n growth
        final delay = baseBackoff * math.pow(2, factor).toInt();
        entry.nextEligibleAt =
            at.add(delay > maxBackoff ? maxBackoff : delay);
      }
    }
    _persist();
  }

  /// Reports and clears the accumulated drop counters.
  ///
  /// Returns `null` when nothing has been dropped, so the pipeline emits an
  /// overflow event only when there is something to say. Clearing on read is
  /// what makes the notice describe one interval rather than all of history.
  SecurityEventQueueOverflow? drainOverflowNotice() {
    if (_droppedTotal == 0 && _droppedExpired == 0) return null;
    final notice = SecurityEventQueueOverflow(
      droppedTotal: _droppedTotal,
      droppedCritical: _droppedCritical,
      droppedExpired: _droppedExpired,
    );
    _droppedTotal = 0;
    _droppedCritical = 0;
    _droppedExpired = 0;
    return notice;
  }

  void clear() {
    _entries.clear();
    _droppedTotal = 0;
    _droppedCritical = 0;
    _droppedExpired = 0;
    final s = store;
    if (s != null) unawaited(s.clear());
  }

  /// Evicts the lowest-priority, oldest entry until the queue fits.
  ///
  /// Entries already in [SecurityEventQueueState.sent] are eligible too: an
  /// unacknowledged send that has been outstanding while the queue filled is
  /// no more valuable than any other entry of the same priority, and
  /// exempting them would let a hung transport pin the whole queue.
  void _evictIfNeeded() {
    while (_entries.length > capacity) {
      final victim = _selectVictim();
      if (victim == null) return;
      if (victim.priority.isProtectedFromEviction) _droppedCritical++;
      _droppedTotal++;
      _entries.remove(victim);
    }
  }

  QueuedSecurityEvent? _selectVictim() {
    QueuedSecurityEvent? victim;
    for (final entry in _entries) {
      if (victim == null) {
        victim = entry;
        continue;
      }
      // Higher rank == less important. Ties broken by age: the earlier
      // entry (lower sequence) goes first, matching "oldest first".
      if (entry.priority.rank > victim.priority.rank) victim = entry;
    }
    return victim;
  }
}
