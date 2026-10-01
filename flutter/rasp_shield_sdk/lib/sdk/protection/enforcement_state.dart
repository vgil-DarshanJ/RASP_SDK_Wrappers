import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'protection_action.dart';

/// Authoritative Protection Engine V1, Phase 8 — the persistent security
/// posture `EnforcementController` maintains, in the exact five states this
/// milestone specifies. Ordered least → most restrictive, mirroring
/// [ProtectionAction]'s own ordering so the two can be compared directly.
///
/// ## Why five states, not seven
///
/// [ProtectionAction] has seven values; this has five. [warn] and [stepUp]
/// map one-to-one ([warned], [stepUpRequired]); [block] maps to
/// [restricted]; [lockSession] and [lockApp] both collapse to [blocked] —
/// the *state* a device is left in is the same ("cannot proceed until this
/// clears") even though *how* it got there differs, and that detail is not
/// lost, only not part of the state name — `EnforcementDecision.action`
/// (see `enforcement_controller.dart`) still carries the exact
/// [ProtectionAction] that produced this state, for audit/telemetry.
enum EnforcementState {
  /// No enforcement in effect. Maps from [ProtectionAction.allow] and
  /// [ProtectionAction.monitor] — monitoring has no user-visible effect and
  /// is not itself a restriction.
  none,

  /// A warning has been surfaced. Maps from [ProtectionAction.warn].
  warned,

  /// Re-authentication is required before the device may be treated as
  /// clear. Maps from [ProtectionAction.stepUp].
  stepUpRequired,

  /// Specific sensitive capabilities are disabled. Maps from
  /// [ProtectionAction.block].
  restricted,

  /// The device is fully blocked — session ended or app locked. Maps from
  /// both [ProtectionAction.lockSession] and [ProtectionAction.lockApp];
  /// see the class doc for why the two collapse to one state.
  blocked,
}

/// Semantics and wire parsing for [EnforcementState].
extension EnforcementStateX on EnforcementState {
  String get wireName => name;

  /// Ordering helper, matching [EnforcementState]'s declared order.
  int get rank => index;

  /// The state [action] maps onto. Total — every [ProtectionAction] value
  /// produces exactly one [EnforcementState].
  static EnforcementState forAction(ProtectionAction action) {
    switch (action) {
      case ProtectionAction.allow:
      case ProtectionAction.monitor:
        return EnforcementState.none;
      case ProtectionAction.warn:
        return EnforcementState.warned;
      case ProtectionAction.stepUp:
        return EnforcementState.stepUpRequired;
      case ProtectionAction.block:
        return EnforcementState.restricted;
      case ProtectionAction.lockSession:
      case ProtectionAction.lockApp:
        return EnforcementState.blocked;
    }
  }
}

/// Parses an [EnforcementState] from its [EnforcementStateX.wireName].
/// Returns `null` for an unrecognized name — a corrupted or foreign-written
/// storage value must never be guessed into a state, safe or otherwise; the
/// caller treats `null` as "no trustworthy persisted state" (see
/// `EnforcementStateStore.read`'s fail-safe default).
EnforcementState? enforcementStateFromName(String? name) {
  if (name == null) return null;
  for (final state in EnforcementState.values) {
    if (state.name == name) return state;
  }
  return null;
}

/// Persists [EnforcementState] so a `BLOCKED`/`RESTRICTED` posture survives
/// a force-stop and relaunch (Phase 8/17) — not an in-memory boolean, which
/// a fresh process start would silently reset to "clear".
///
/// Backed by `flutter_secure_storage`, the same primitive
/// `LicenseManager`/`EnrollmentManager` already use for security-relevant
/// device state — not a second persistence mechanism.
///
/// ## Fail-safe reads
///
/// [read] returns [EnforcementState.none] for a missing key (first launch —
/// correct, nothing has ever been enforced) but is otherwise fail-safe
/// toward the *strongest* interpretation available: a value present but
/// unparseable (corrupted storage, a future SDK's unrecognized name written
/// then rolled back to this build) is treated as [EnforcementState.blocked]
/// — the whole point of persisting this state is that its disappearance or
/// corruption must never read as "never blocked."
class EnforcementStateStore {
  const EnforcementStateStore();

  static const _key = 'rasp_enforcement_state';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  /// Test-only: `true` once [enableTestOverride] has armed the in-memory
  /// substitute for the whole storage surface, so enforcement persistence
  /// is exercised with no platform channel. `false` in every production
  /// path — mirrors `DeviceKeyManager.testOverride`'s role, but as an
  /// explicit arm/disarm pair rather than null-checking the value itself,
  /// so a test can start the override at [EnforcementState.none] (the
  /// common case: "nothing persisted yet") without that being
  /// indistinguishable from "override not active."
  @visibleForTesting
  static bool useTestOverride = false;

  @visibleForTesting
  static EnforcementState testOverrideValue = EnforcementState.none;

  /// Test-only: arms the in-memory override at [initial] (default: nothing
  /// persisted yet).
  @visibleForTesting
  static void enableTestOverride(
      [EnforcementState initial = EnforcementState.none]) {
    useTestOverride = true;
    testOverrideValue = initial;
  }

  /// Test-only: disarms the override, so a subsequent read/write falls
  /// through to real storage again.
  @visibleForTesting
  static void resetForTesting() {
    useTestOverride = false;
    testOverrideValue = EnforcementState.none;
  }

  Future<EnforcementState> read() async {
    if (useTestOverride) return testOverrideValue;

    String? raw;
    try {
      raw = await _storage.read(key: _key);
    } catch (_) {
      // Storage unavailable — see class doc: unreadable is not the same as
      // "never blocked". A device that cannot prove it was never blocked
      // must be treated as though it was.
      return EnforcementState.blocked;
    }
    if (raw == null) return EnforcementState.none; // first launch
    return enforcementStateFromName(raw) ?? EnforcementState.blocked;
  }

  /// Persists [state]. Never throws — a write failure is reported to the
  /// caller via the return value so it can decide how to treat the
  /// in-session decision (see `EnforcementController`'s own fail-safe
  /// handling), rather than crashing a security-critical write path.
  Future<bool> write(EnforcementState state) async {
    if (useTestOverride) {
      testOverrideValue = state;
      return true;
    }
    try {
      await _storage.write(key: _key, value: state.wireName);
      return true;
    } catch (_) {
      return false;
    }
  }
}
