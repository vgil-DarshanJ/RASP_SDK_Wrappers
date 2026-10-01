import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Cryptographic Remote Command Integrity milestone, Phase 15 — persisted
/// execution history so a command executes at most once even across a
/// force-stop, process death, or reboot, not merely within one process's
/// in-memory lifetime (`RemoteCommandDispatcher._processed`'s pre-existing,
/// still-present, faster first line of defense).
///
/// Backed by `flutter_secure_storage` — the same primitive
/// `EnforcementStateStore`/`DeviceKeyManager` already use, not a second
/// persistence mechanism, and explicitly not a new nonce *database*
/// (Phase 6/14): a single bounded, secure-storage-backed set of already-
/// executed command ids is sufficient here because every command id is
/// already globally unique (the backend's own auto-increment primary key)
/// and every command this SDK executes (`LOCK_APP`, `UNLOCK_APP`,
/// `FORCE_RESCAN`, `SHOW_MESSAGE`) is independently idempotent by design —
/// see `docs/REMOTE_COMMAND_SECURITY.md` §6. This ledger adds an explicit,
/// auditable guarantee on top of that, rather than being the only thing
/// standing between a replayed command and a bad outcome.
///
/// ## Bounded (Phase 14 — resource limits)
///
/// Capped at [maxEntries] ids, oldest dropped first. A device that has been
/// running for months executes far more than 200 commands' worth of
/// history; unbounded growth of a secure-storage value is exactly the
/// "oversized payload" resource-exhaustion shape this milestone's Phase 14
/// asks to prevent, applied to this SDK's own storage rather than only to
/// an attacker-supplied one.
///
/// ## Fail-safe direction
///
/// Unlike `EnforcementStateStore` (which fails toward the *most
/// restrictive* state, because losing that value must never read as "never
/// blocked"), this ledger fails toward "not yet executed" on a read
/// failure — deliberately, not by oversight. Every command this SDK
/// actually executes is independently idempotent (re-applying `LOCK_APP`
/// or `UNLOCK_APP` is a documented no-op, not a fresh destructive action —
/// see `EnforcementController.applyRemoteLock`/`applyRemoteUnlock`), so a
/// storage read failure here costs at most one redundant, harmless
/// re-execution, never a security regression. Treating it the other way —
/// refusing to execute anything whenever storage is briefly unreadable —
/// would turn a storage hiccup into a denial of legitimate operator
/// commands, which is not this ledger's job to cause.
class RemoteCommandExecutionLedger {
  const RemoteCommandExecutionLedger();

  static const _key = 'rasp_remote_command_ledger';
  static const int maxEntries = 200;
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  @visibleForTesting
  static bool useTestOverride = false;

  @visibleForTesting
  static List<int> testOverrideValue = <int>[];

  @visibleForTesting
  static void enableTestOverride([List<int> initial = const []]) {
    useTestOverride = true;
    testOverrideValue = List<int>.from(initial);
  }

  @visibleForTesting
  static void resetForTesting() {
    useTestOverride = false;
    testOverrideValue = <int>[];
  }

  Future<bool> hasExecuted(int commandId) async {
    final ids = await _readIds();
    return ids.contains(commandId);
  }

  /// Records [commandId] as executed. Never throws — a write failure is
  /// swallowed (returns `false`) rather than propagated, matching
  /// `EnforcementStateStore.write`'s shape; the caller may still proceed,
  /// since (per the class doc) losing this record costs at most one
  /// redundant future re-execution, not a security failure.
  Future<bool> markExecuted(int commandId) async {
    final ids = await _readIds();
    if (ids.contains(commandId)) return true;
    ids.add(commandId);
    while (ids.length > maxEntries) {
      ids.removeAt(0);
    }
    return _writeIds(ids);
  }

  Future<List<int>> _readIds() async {
    if (useTestOverride) return List<int>.from(testOverrideValue);
    try {
      final raw = await _storage.read(key: _key);
      if (raw == null || raw.isEmpty) return <int>[];
      final decoded = jsonDecode(raw);
      if (decoded is! List) return <int>[];
      return decoded.whereType<num>().map((n) => n.toInt()).toList();
    } catch (_) {
      // See class doc: fails toward "not yet executed", not the reverse.
      return <int>[];
    }
  }

  Future<bool> _writeIds(List<int> ids) async {
    if (useTestOverride) {
      testOverrideValue = List<int>.from(ids);
      return true;
    }
    try {
      await _storage.write(key: _key, value: jsonEncode(ids));
      return true;
    } catch (_) {
      return false;
    }
  }
}
