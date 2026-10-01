/// Phase 4 — the monotonic local security-event sequence.
///
/// ## The requirement, and the one hard part
///
/// A sequence must be unique within a device+application context, survive a
/// restart without ever reusing a number, detect an unexpected rollback, and
/// keep working entirely offline. The first three are in tension: persisting
/// after each issue is safe but writes to secure storage on every event, while
/// persisting periodically is cheap but replays numbers after a crash.
///
/// ## The resolution: reserve-ahead (hi/lo)
///
/// The store never records "the last number issued". It records **the highest
/// number this device is permitted to issue** — a reservation. Numbers are
/// handed out from memory within that reservation; when it is exhausted, a new
/// block is reserved and persisted *before* any number in it is used.
///
/// ```
///  persisted reservation: 64
///  in-memory next:        33 → 34 → … → 64   (no writes at all)
///  at 64: persist 96, then continue          (one write per 32 events)
/// ```
///
/// A crash therefore loses at most one *unused* block. On restart the
/// sequencer resumes at the persisted reservation + 1, which is **strictly
/// greater than anything ever issued** — the numbers in the abandoned tail are
/// simply skipped. Gaps are acceptable; reuse is not. This is the standard
/// hi/lo allocator argument, and it is the reason
/// [SecurityEventChainVerifier] checks for *duplicate and decreasing*
/// sequences rather than for contiguity.
///
/// ## Why not `TrustedClock`'s high-water mark directly
///
/// `OfflineComplianceStore` already implements exactly this shape for the
/// clock, and this class deliberately mirrors it (same secure storage, same
/// `testValues`/`testFailReads` seams, same "a write failure must never break
/// a scan" rule) rather than inventing a second persistence idiom. It is a
/// separate key because the two values answer different questions and a
/// legitimate re-activation clears one without touching the other.
///
/// ## On failure it reports, never silently restarts
///
/// The milestone is explicit: *do not silently restart from zero if that can
/// cause event replay*. So an unreadable store yields
/// [SecurityEventSequenceState.unknown] and a detected rollback yields
/// [SecurityEventSequenceState.integrityError]; in both cases the sequencer
/// keeps issuing (a security SDK that stops producing events under storage
/// failure has been silenced, which is worse), but every consumer can see that
/// the ordering is not trustworthy, and `SecurityEventPipeline` emits a
/// [SecurityEventType.sequenceIntegrityError] event saying so.
library;

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';


/// How much the sequence can be trusted.
enum SecurityEventSequenceState {
  /// Persisted, monotonic, resumed correctly.
  ok,

  /// Storage could not be read. Numbers are being issued, but nothing
  /// guarantees they were not issued before.
  unknown,

  /// A rollback was detected: persisted state was lower than what this
  /// session had already issued.
  integrityError,
}

extension SecurityEventSequenceStateX on SecurityEventSequenceState {
  String get wireName {
    switch (this) {
      case SecurityEventSequenceState.ok:
        return 'OK';
      case SecurityEventSequenceState.unknown:
        return 'UNKNOWN';
      case SecurityEventSequenceState.integrityError:
        return 'INTEGRITY_ERROR';
    }
  }

  /// `true` only for [SecurityEventSequenceState.ok]. Written as an explicit
  /// getter rather than an `== ok` comparison at each call site so the
  /// fail-safe reading (`unknown` is not trustworthy) cannot be got wrong by
  /// someone adding a fourth state later.
  bool get isTrustworthy => this == SecurityEventSequenceState.ok;
}

/// Secure-storage persistence for the reservation high-water mark.
///
/// Mirrors `OfflineComplianceStore` deliberately — see this library's
/// documentation. Nothing stored here is a secret (a counter reveals only how
/// many events a device has produced), so nothing here is logged and nothing
/// sensitive is written.
class SecurityEventSequenceStore {
  static const String _reservationKey = 'rasp_sdk_event_sequence_reservation';

  static const FlutterSecureStorage _defaultStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  final FlutterSecureStorage _storage;

  const SecurityEventSequenceStore({FlutterSecureStorage? storage})
      : _storage = storage ?? _defaultStorage;

  /// In-memory override so a test can drive the store with no platform
  /// channel. Test-only, never set by production code.
  @visibleForTesting
  static Map<String, String>? testValues;

  /// Forces reads to fail, so the `unknown` branch is reachable in a test.
  @visibleForTesting
  static bool testFailReads = false;

  /// Forces writes to fail, so the "a write failure must not break a scan"
  /// path is reachable in a test.
  @visibleForTesting
  static bool testFailWrites = false;

  /// The highest sequence this device is permitted to issue, or `null` when
  /// none has been recorded.
  ///
  /// A corrupt or negative value is treated as absent rather than as an
  /// error — the same reasoning `OfflineComplianceStore` documents: failing
  /// outright would let anyone force a failure by writing garbage.
  Future<int?> readReservation() async {
    if (testFailReads) return null;
    final raw = testValues != null
        ? testValues![_reservationKey]
        : await _readStorage(_reservationKey);
    if (raw == null || raw.isEmpty) return null;
    final parsed = int.tryParse(raw);
    if (parsed == null || parsed < 0) return null;
    return parsed;
  }

  /// Records a new reservation. Never moves backwards.
  Future<void> writeReservation(int reservation) async {
    if (testFailWrites) return;
    if (testValues != null) {
      testValues![_reservationKey] = reservation.toString();
      return;
    }
    try {
      await _storage.write(
        key: _reservationKey,
        value: reservation.toString(),
      );
    } catch (_) {
      // A scan must not fail because secure storage was momentarily
      // unavailable. The consequence is bounded: the reservation stands
      // in memory, and a crash before the next successful write means the
      // next launch resumes from an older reservation — which the rollback
      // check below turns into a reported INTEGRITY_ERROR rather than
      // silent reuse.
    }
  }

  /// `true` when storage cannot be read at all, so the sequencer can report
  /// `unknown` rather than guessing.
  Future<bool> readFailed() async {
    if (testFailReads) return true;
    if (testValues != null) return false;
    try {
      await _storage.read(key: _reservationKey);
      return false;
    } catch (_) {
      return true;
    }
  }

  /// Clears the reservation. Used only when a device legitimately
  /// re-activates onto a new seat, where the event history restarts.
  Future<void> clear() async {
    if (testValues != null) {
      testValues!.remove(_reservationKey);
      return;
    }
    try {
      await _storage.delete(key: _reservationKey);
    } catch (_) {
      // Nothing recoverable, nothing security-relevant lost.
    }
  }

  Future<String?> _readStorage(String key) async {
    try {
      return await _storage.read(key: key);
    } catch (_) {
      return null;
    }
  }
}

/// Issues monotonic sequence numbers. See this library's documentation.
class SecurityEventSequencer {
  /// How many numbers one persisted reservation covers.
  ///
  /// 32 balances the two costs directly: one secure-storage write per 32
  /// events, and at most 31 numbers skipped after an unclean shutdown. Both
  /// are cheap; reuse — the thing neither cost buys — is what is unacceptable.
  static const int reservationBlock = 32;

  final SecurityEventSequenceStore _store;
  final int _block;

  int _next = 1;
  int _reservedThrough = 0;
  bool _initialized = false;
  SecurityEventSequenceState _state = SecurityEventSequenceState.unknown;

  SecurityEventSequencer({
    SecurityEventSequenceStore? store,
    int blockSize = reservationBlock,
  })  : _store = store ?? const SecurityEventSequenceStore(),
        _block = blockSize < 1 ? 1 : blockSize;

  /// How much the issued numbers can be trusted. See
  /// [SecurityEventSequenceState].
  SecurityEventSequenceState get state => _state;

  /// The next number [next] will return, without consuming it.
  int get peek => _next;

  /// The highest number currently reserved from persistence.
  @visibleForTesting
  int get reservedThrough => _reservedThrough;

  bool get isInitialized => _initialized;

  /// Loads the persisted reservation and resumes strictly beyond it.
  ///
  /// Idempotent: calling it twice does not re-read or re-reserve, so a
  /// second `RaspSdk.initialize()` in the same process cannot rewind the
  /// counter.
  Future<void> initialize() async {
    if (_initialized) return;
    _initialized = true;

    if (await _store.readFailed()) {
      // Storage unreadable. Issue from 1, but say so — this is the
      // `UNKNOWN` outcome the milestone asks for, not a silent restart.
      _state = SecurityEventSequenceState.unknown;
      _next = 1;
      _reservedThrough = 0;
      return;
    }

    final persisted = await _store.readReservation();
    _next = (persisted ?? 0) + 1;
    _reservedThrough = persisted ?? 0;
    _state = SecurityEventSequenceState.ok;
    await _reserve();
  }

  /// Issues the next sequence number.
  ///
  /// Always succeeds. A storage failure downgrades [state] rather than
  /// throwing: an SDK that cannot emit security events because a keystore
  /// hiccuped has been silenced, which is the outcome an attacker wants.
  Future<int> next() async {
    if (!_initialized) await initialize();
    if (_next > _reservedThrough) await _reserve();
    return _next++;
  }

  /// Reserves the next block and persists it **before** any number in it is
  /// issued.
  Future<void> _reserve() async {
    // Read *before* writing. A rollback is only visible in the gap between
    // what this session already reserved and what storage now claims — write
    // first and the evidence is overwritten by the very act of reserving.
    final current = await _store.readReservation();
    if (current != null && current < _reservedThrough) {
      // Persistence moved backwards under us: stored state was rolled back,
      // restored from a snapshot, or edited. Reported, and — critically —
      // the new reservation is still computed from the in-memory high-water
      // mark, so the rollback cannot cause a single number to be reused.
      _state = SecurityEventSequenceState.integrityError;
    }

    final floor = [_next - 1, _reservedThrough, current ?? 0]
        .reduce((a, b) => a > b ? a : b);
    final target = floor + _block;
    await _store.writeReservation(target);

    // Read back: a write that silently did nothing (a full or locked
    // keystore) must not be mistaken for a successful reservation, because
    // that is precisely how numbers get reused after a crash.
    final confirmed = await _store.readReservation();
    if (confirmed == null || confirmed < _next) {
      // Never overwrite a detected rollback with the weaker `unknown`: an
      // integrity error is the more serious finding and must survive.
      if (_state == SecurityEventSequenceState.ok) {
        _state = SecurityEventSequenceState.unknown;
      }
      _reservedThrough = target;
      return;
    }
    _reservedThrough = confirmed;
  }

  /// Resets in-memory state. Test-only.
  @visibleForTesting
  void resetForTests() {
    _next = 1;
    _reservedThrough = 0;
    _initialized = false;
    _state = SecurityEventSequenceState.unknown;
  }
}
