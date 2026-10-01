/// Phase 5 — deduplication by deterministic identity.
///
/// ## What "the same event" means here
///
/// Identity is `eventType | detectorId | chainId | evidenceDigest`. Two
/// events are the same incident when all four match **and** they fall inside
/// the same [window]. Nothing else participates: not `eventId` (unique by
/// construction, so it would never dedupe anything), not `sequence` (ditto),
/// not `timestamp` (that is what the window is for), and not `riskScore`
/// (a score that drifted by one point between two scans of an unchanged
/// device is not a new incident).
///
/// ## Why evidence, and not just the detector
///
/// A detector firing twice with the *same* evidence is one ongoing condition —
/// a rooted device is still rooted on the next scan, and reporting it every
/// 30 seconds is noise that buries the incident it is part of. A detector
/// firing twice with *different* evidence is two findings: `su` at
/// `/system/xbin/su` and a newly-appeared Magisk package are genuinely
/// different facts about the attack, and collapsing them would delete
/// evidence an investigator needs.
///
/// This is why the key includes [SecurityEvent.evidenceDigest] rather than
/// stopping at the detector id, and it is the single most important thing
/// this class gets right: **suppression must never lose a distinct incident.**
///
/// ## Bounded by construction
///
/// The tracking table is capped at [maxTracked] identities and evicts the
/// least-recently-emitted first. A device under a flood of distinct synthetic
/// events cannot grow this without bound — the storage-exhaustion concern
/// Phase 15 names. The cost of eviction is a duplicate being re-emitted,
/// never a genuine event being lost, which is the correct direction to fail
/// in: a redundant event costs bandwidth, a lost one costs an investigation.
///
/// ## Restart behaviour is deliberate
///
/// State is in-memory and resets with the process. A restarted app re-emits
/// the first occurrence of a still-present condition, which is correct: after
/// a restart the backend has no way to know the condition persisted, and the
/// alternative — persisting suppression state — would let an attacker who can
/// write that state suppress the very events describing their attack.
library;

import 'security_event.dart';
import 'security_event_type.dart';


/// What the deduplicator decided about one event.
class SecurityEventDedupDecision {
  /// `true` when the event should be emitted.
  final bool emit;

  /// The identity key it was evaluated under. Exposed for diagnostics and
  /// for tests that assert on grouping, never sent on the wire.
  final String identity;

  /// How many events with this identity have been suppressed since the last
  /// emitted one. `0` on an emitted event.
  final int suppressedCount;

  const SecurityEventDedupDecision({
    required this.emit,
    required this.identity,
    required this.suppressedCount,
  });

  @override
  String toString() => emit
      ? 'DedupDecision(emit, $identity)'
      : 'DedupDecision(suppress x$suppressedCount, $identity)';
}

class _DedupEntry {
  DateTime lastEmittedAt;
  int suppressed;
  _DedupEntry(this.lastEmittedAt) : suppressed = 0;
}

/// Suppresses repeated reports of the same ongoing incident.
class SecurityEventDeduplicator {
  /// How long an identity stays suppressed after being emitted.
  ///
  /// 60 seconds is roughly two scan cycles: long enough that a device
  /// scanning on a timer does not re-report an unchanged condition every
  /// cycle, short enough that an operator watching a live feed still sees a
  /// persisting incident refresh rather than go quiet.
  final Duration window;

  /// Maximum distinct identities tracked at once.
  final int maxTracked;

  /// Event types that are never suppressed.
  ///
  /// The event system's own failure reports must always get through: if
  /// [SecurityEventType.sequenceIntegrityError] could be deduplicated, a
  /// device whose sequence storage is permanently broken would report it
  /// once and then look healthy.
  static const Set<SecurityEventType> neverSuppressed = {
    SecurityEventType.sequenceIntegrityError,
    SecurityEventType.queueOverflow,
  };

  final Map<String, _DedupEntry> _entries = {};
  final List<String> _order = [];

  SecurityEventDeduplicator({
    this.window = const Duration(seconds: 60),
    this.maxTracked = 256,
  });

  /// The deterministic identity of [event].
  ///
  /// A pure function of the event — the same event always produces the same
  /// key, on any device, in any process. That determinism is what lets a
  /// test assert grouping directly and what would let a backend recompute
  /// the same key if it ever needed to.
  static String identityOf(SecurityEvent event) => [
        event.eventType.wireName,
        event.detectorId ?? '-',
        event.chainId ?? '-',
        event.evidenceDigest,
      ].join('|');

  /// Decides whether [event] should be emitted.
  SecurityEventDedupDecision evaluate(SecurityEvent event, {DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();
    final identity = identityOf(event);

    if (neverSuppressed.contains(event.eventType)) {
      return SecurityEventDedupDecision(
        emit: true,
        identity: identity,
        suppressedCount: 0,
      );
    }

    final existing = _entries[identity];
    if (existing == null) {
      _remember(identity, at);
      return SecurityEventDedupDecision(
        emit: true,
        identity: identity,
        suppressedCount: 0,
      );
    }

    if (at.difference(existing.lastEmittedAt) >= window) {
      existing.lastEmittedAt = at;
      existing.suppressed = 0;
      _touch(identity);
      return SecurityEventDedupDecision(
        emit: true,
        identity: identity,
        suppressedCount: 0,
      );
    }

    existing.suppressed++;
    return SecurityEventDedupDecision(
      emit: false,
      identity: identity,
      suppressedCount: existing.suppressed,
    );
  }

  /// How many events with [identity] are currently suppressed.
  int suppressedCount(String identity) => _entries[identity]?.suppressed ?? 0;

  /// Distinct identities currently tracked. Bounded by [maxTracked].
  int get trackedCount => _entries.length;

  void reset() {
    _entries.clear();
    _order.clear();
  }

  void _remember(String identity, DateTime at) {
    _entries[identity] = _DedupEntry(at);
    _order.add(identity);
    while (_order.length > maxTracked) {
      _entries.remove(_order.removeAt(0));
    }
  }

  void _touch(String identity) {
    _order.remove(identity);
    _order.add(identity);
  }
}
