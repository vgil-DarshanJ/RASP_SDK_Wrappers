import '../events/security_event_center.dart';
import '../events/security_event_type.dart';
import 'enforcement_state.dart';
import 'pipeline_mode.dart';
import 'protection_action.dart';
import 'protection_result.dart';

/// Authoritative Protection Engine V1 — the one central enforcement path.
///
/// ```
///   ProtectionResult (SecurityAssessment → ProtectionDecision, upstream)
///           │
///           ▼
///   EnforcementController.evaluate()   ← this class
///           │
///           ├─ maps recommendedAction → EnforcementState
///           ├─ composes with the persisted state (never downgrades)
///           ├─ applies it ONLY when the rollout mode is `authoritative`
///           └─ records exactly one SecurityEvent per real transition
///           ▼
///   EnforcementDecision
/// ```
///
/// The detector reports (`DetectionResult`, upstream of this class). The
/// policy decides (`ProtectionPolicy` + `ProtectionEngine`, upstream of
/// this class — this class never recomputes a score or a severity). This
/// class only *executes*: it is the "ActionExecutor" half of
/// `SecurityAssessment → ProtectionDecision → EnforcementController →
/// ActionExecutor` — folded into one class because, unlike a detector or a
/// policy, there is exactly one way to persist and report an enforcement
/// transition, so a separate executor class would be a pass-through with
/// no independent logic of its own.
///
/// ## Staged by [PipelineMode], not a boolean
///
/// [evaluate] is called every scan, in every mode — it always computes and
/// returns what it *would* do (Phase 10's "SHADOW: new enforcement decision
/// observed only"). Only in [PipelineMode.authoritative] does it actually
/// persist the state and count as applied; every mode below that returns a
/// decision with `applied: false` and touches no storage. This mirrors
/// exactly how `PipelineMode.compatibility` already governs whether
/// `CompatibilityEngine`'s decision drives `protection`, or is merely
/// computed for comparison.
class EnforcementController {
  const EnforcementController({
    this.store = const EnforcementStateStore(),
  });

  final EnforcementStateStore store;

  /// Evaluates one scan's [protection] result against the persisted
  /// enforcement state under [mode].
  ///
  /// Fail-safe throughout (Phase 9):
  /// - The new state is never allowed to be *weaker* than whatever was
  ///   already persisted — `max(current, mapped)`, always. A clean scan
  ///   after a BLOCKED one does not clear it; only [clear] can, and that is
  ///   never called from this method.
  /// - A storage write failure does not change what this call *returns* —
  ///   the in-session decision still reflects the stronger state so a
  ///   caller gating the UI *right now* still enforces it — but it is
  ///   flagged via [EnforcementDecision.persisted] so a caller can log that
  ///   the state may not survive a restart.
  /// - Below [PipelineMode.authoritative], nothing is written and nothing
  ///   is enforced, by construction — [EnforcementDecision.applied] is
  ///   `false` and [EnforcementDecision.state] still reports what *would*
  ///   apply, for observability.
  Future<EnforcementDecision> evaluate({
    required ProtectionResult protection,
    required PipelineMode mode,
  }) async {
    final mapped = EnforcementStateX.forAction(protection.recommendedAction);
    final current = await store.read();
    final effective =
        mapped.rank > current.rank ? mapped : current; // never downgrade

    final authoritative = mode == PipelineMode.authoritative;
    final changed = effective != current;

    var persisted = true;
    if (authoritative && changed) {
      persisted = await store.write(effective);
    }

    final decision = EnforcementDecision(
      action: protection.recommendedAction,
      state: authoritative ? effective : mapped,
      applied: authoritative,
      changed: changed,
      persisted: persisted,
      policyVersion: protection.policyVersion,
      decidedAt: protection.evaluatedAt,
    );

    // Phase 15/7: exactly one event per real transition, and only when
    // this decision is actually in force — SHADOW-mode observation must
    // not populate the security-event trail with actions that never
    // happened. Phase 7's idempotency requirement ("BLOCK_APP triggered
    // 100 times → one effective enforcement state") is satisfied by
    // `changed` alone: a repeated scan that keeps recommending the same
    // action recomputes `mapped == current`, so `changed` is false and
    // this branch never re-fires.
    if (authoritative && changed) {
      await SecurityEventCenter.recordEnforcementTransition(
        state: effective,
        action: protection.recommendedAction,
        policyVersion: protection.policyVersion,
      );
    }

    return decision;
  }

  /// The only path that may *lower* the persisted enforcement state.
  ///
  /// Deliberately not called anywhere in [evaluate] — Phase 19's invariant
  /// ("a BLOCK_APP state cannot become ALLOW because one later scan is
  /// clean unless the documented recovery policy explicitly permits
  /// recovery") is satisfied by this being a distinct, explicitly-invoked
  /// method rather than something a clean scan can trigger on its own. A
  /// host application, or [applyRemoteUnlock] below (its first real
  /// caller, added in the Persistent Remote Lock Enforcement milestone),
  /// calls this directly, having already decided recovery is permitted —
  /// this method does not decide that for them.
  Future<void> clear() => store.write(EnforcementState.none);

  /// Persistent Remote Lock Enforcement milestone — applies an
  /// operator-issued, already-authenticated `LOCK_APP` remote command.
  ///
  /// ## Deliberately NOT gated by [PipelineMode]
  ///
  /// [evaluate] is gated by rollout mode because a *scan-driven* decision
  /// is exactly what LEGACY/SHADOW/COMPATIBILITY/AUTHORITATIVE stages —
  /// whether the automated pipeline's own verdict may act. A remote lock
  /// is a different kind of event entirely: an operator, already
  /// authenticated through the same request-signing/device-binding
  /// boundary every other post-activation SDK call uses, explicitly
  /// decided to lock this one device. That decision has never been
  /// staged behind a rollout mode — `RemoteCommandDispatcher._lockApp`
  /// already took immediate, unconditional effect before this milestone
  /// (in-memory only, which is the gap this method closes) — and gating
  /// it behind `AUTHORITATIVE` now would be a *new* restriction on a
  /// capability that has always been live, not a staged promotion of one
  /// that wasn't.
  ///
  /// Fail-safe and idempotent exactly like [evaluate]: never downgrades
  /// (`max(current, blocked)`), a storage failure never changes what is
  /// *returned* (still fail-safe for the current session) only whether it
  /// *persists*, and a repeated command (same id or not) that finds the
  /// device already `blocked` changes nothing and is reported as a
  /// replay, not re-applied.
  Future<RemoteLockDecision> applyRemoteLock({
    required int commandId,
    String? reason,
  }) async {
    final current = await store.read();
    const mapped = EnforcementState.blocked;
    final effective =
        mapped.rank > current.rank ? mapped : current; // never downgrade
    final changed = effective != current;

    var persisted = true;
    if (changed) persisted = await store.write(effective);

    await SecurityEventCenter.recordRemoteLockEvent(
      type: changed
          ? SecurityEventType.remoteLockApplied
          : SecurityEventType.remoteLockReplayed,
      commandId: commandId,
    );
    if (!persisted) {
      await SecurityEventCenter.recordRemoteLockEvent(
        type: SecurityEventType.remoteLockPersistenceError,
        commandId: commandId,
      );
    }

    return RemoteLockDecision(
      commandId: commandId,
      state: effective,
      changed: changed,
      persisted: persisted,
    );
  }

  /// Applies an operator-issued, already-authenticated `UNLOCK_APP`
  /// remote command — the one documented recovery path [clear] exists
  /// for. Idempotent: unlocking an already-unlocked device changes
  /// nothing and emits no event (there is nothing to report — an unlock
  /// that did not need to do anything is not itself a security-relevant
  /// transition the way a no-op *lock* replay is, since it carries no
  /// risk of masking a real block).
  Future<RemoteLockDecision> applyRemoteUnlock({
    required int commandId,
  }) async {
    final current = await store.read();
    if (current == EnforcementState.none) {
      return RemoteLockDecision(
        commandId: commandId,
        state: EnforcementState.none,
        changed: false,
        persisted: true,
      );
    }
    final persisted = await store.write(EnforcementState.none);
    if (persisted) {
      await SecurityEventCenter.recordRemoteLockEvent(
        type: SecurityEventType.remoteUnlockApplied,
        commandId: commandId,
      );
    } else {
      await SecurityEventCenter.recordRemoteLockEvent(
        type: SecurityEventType.remoteLockPersistenceError,
        commandId: commandId,
      );
    }
    return RemoteLockDecision(
      commandId: commandId,
      state: persisted ? EnforcementState.none : current,
      changed: persisted,
      persisted: persisted,
    );
  }
}

/// One [EnforcementController.applyRemoteLock]/[applyRemoteUnlock] outcome.
class RemoteLockDecision {
  final int commandId;
  final EnforcementState state;

  /// `true` when this call actually changed the persisted state — `false`
  /// for a replayed lock (already blocked) or a no-op unlock (already
  /// clear).
  final bool changed;

  final bool persisted;

  const RemoteLockDecision({
    required this.commandId,
    required this.state,
    required this.changed,
    required this.persisted,
  });

  @override
  String toString() =>
      'RemoteLockDecision(command=$commandId, state=${state.wireName}, '
      'changed=$changed, persisted=$persisted)';
}

/// One [EnforcementController.evaluate] outcome.
class EnforcementDecision {
  /// The [ProtectionAction] this decision was derived from — kept even
  /// though [state] collapses [ProtectionAction.lockSession] and
  /// [ProtectionAction.lockApp] to the same [EnforcementState], so an
  /// audit trail never loses which one actually fired.
  final ProtectionAction action;

  /// The enforcement state this decision reflects — the *effective* state
  /// (composed with whatever was already persisted) when [applied] is
  /// `true`, or just this scan's own mapped state when it is `false` (see
  /// [EnforcementController.evaluate]'s doc for why the two differ).
  final EnforcementState state;

  /// `true` only in [PipelineMode.authoritative] — the mode below which
  /// this decision is observation-only, matching Phase 10's rollout
  /// semantics.
  final bool applied;

  /// `true` when [state] differs from what was already persisted before
  /// this call — the signal `evaluate` uses to decide whether to write
  /// storage or record a security event at all (Phase 7 idempotency).
  final bool changed;

  /// `true` unless a storage write actually failed. Always `true` when
  /// [applied] is `false` (nothing was attempted) or [changed] is `false`
  /// (nothing needed writing).
  final bool persisted;

  final int policyVersion;

  final DateTime decidedAt;

  const EnforcementDecision({
    required this.action,
    required this.state,
    required this.applied,
    required this.changed,
    required this.persisted,
    required this.policyVersion,
    required this.decidedAt,
  });

  @override
  String toString() =>
      'EnforcementDecision(${action.wireName} → ${state.wireName}, '
      'applied=$applied, changed=$changed, persisted=$persisted)';
}
