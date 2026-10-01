import 'dart:async';

import 'package:flutter/foundation.dart';

import 'activation_manager.dart';
import 'device_identity.dart';
import 'events/security_event_center.dart';
import 'events/security_event_type.dart';
import 'license_manager.dart';
import 'protection/enforcement_controller.dart';
import 'remote_command.dart';
import 'remote_command_api.dart';
import 'remote_command_ledger.dart';
import 'security/remote_command_verifier.dart';

/// Signature of the ack transport, so tests can observe acknowledgements
/// without a network. Matches [RemoteCommandApi.acknowledge].
typedef CommandAck = Future<void> Function({
  required int commandId,
  required bool succeeded,
  required String result,
});

/// Receives the backend's `pending_commands` (delivered on the **existing**
/// heartbeat — this adds no second polling loop), cryptographically verifies
/// each one (Cryptographic Remote Command Integrity milestone — see
/// `docs/REMOTE_COMMAND_SECURITY.md`), executes the supported ones, and
/// acknowledges each through the **existing** ack endpoint.
///
/// ## Pipeline (Phase 7's lifecycle, as implemented here)
///
/// `PENDING`/`DELIVERED` already happened server-side by the time
/// [ingest] sees a raw entry. From there:
///
/// 1. **Parse** — [RemoteCommand.tryParse]. Malformed → `commandRejected`,
///    never proceeds.
/// 2. **De-duplicate** — the in-memory `_processed` set (this process's
///    lifetime, fast, no I/O) then [RemoteCommandExecutionLedger] (persists
///    across restart). Either hit → `commandReplayed`, never re-executed.
/// 3. **Verify** — [RemoteCommandVerifier]: signature, device/application
///    binding, freshness. Anything but [RemoteCommandVerdict.valid] →
///    `commandRejected` (or `commandExpired` for staleness specifically),
///    never executed.
/// 4. **Execute** — the type-specific handler below.
/// 5. **Acknowledge** — the existing signed ack endpoint.
///
/// Lives in the SDK layer with no `BuildContext`. UI-bound effects are
/// exposed as observable state that [RemoteCommandHost] renders:
///  * FORCE_RESCAN → delegated to [onForceRescan] (the live security scan,
///    which uploads telemetry through the existing live wiring).
///  * SHOW_MESSAGE → [pendingMessage] (a dialog).
///  * LOCK_APP → [lockState] (a full-screen lock) **and** the persisted
///    `EnforcementStateStore` via [EnforcementController.applyRemoteLock].
///  * UNLOCK_APP → the one documented recovery path, via
///    [EnforcementController.applyRemoteUnlock].
/// `WIPE_LOCAL_DATA` and any unknown type are acknowledged as unsupported and
/// never executed — but, as of this milestone, still cryptographically
/// verified first like every other command, so an attacker cannot use an
/// "unsupported" type as a lower-scrutiny injection path.
class RemoteCommandDispatcher extends ChangeNotifier {
  RemoteCommandDispatcher({
    CommandAck? ack,
    this.onForceRescan,
    this.onRecheck,
    bool Function()? isHealthy,
    EnforcementController? enforcement,
    RemoteCommandVerifier? verifier,
    RemoteCommandExecutionLedger? ledger,
    Future<String?> Function()? activationTokenResolver,
    Future<String?> Function()? deviceIdResolver,
    Future<String?> Function()? applicationIdResolver,
  })  : _ack = ack ?? RemoteCommandApi().acknowledge,
        _isHealthy =
            isHealthy ?? (() => LicenseManager.status.value.grantsFeatures),
        _enforcement = enforcement ?? const EnforcementController(),
        _verifier = verifier ?? const RemoteCommandVerifier(),
        _ledger = ledger ?? const RemoteCommandExecutionLedger(),
        _activationTokenResolver =
            activationTokenResolver ?? (() => LicenseManager.activationToken),
        _deviceIdResolver = deviceIdResolver ?? DeviceIdentity.get,
        _applicationIdResolver = applicationIdResolver ?? ActivationManager.bundleId;

  /// App-wide instance shared by the heartbeat sink (RaspSdk), the UI host, and
  /// the shell that runs scans.
  static final RemoteCommandDispatcher instance = RemoteCommandDispatcher();

  final CommandAck _ack;
  final bool Function() _isHealthy;
  final EnforcementController _enforcement;
  final RemoteCommandVerifier _verifier;
  final RemoteCommandExecutionLedger _ledger;
  final Future<String?> Function() _activationTokenResolver;
  final Future<String?> Function() _deviceIdResolver;
  final Future<String?> Function() _applicationIdResolver;

  /// Runs a fresh security scan. Wired to `SecurityCenterController.runScan` by
  /// the shell; that scan uploads telemetry via the existing live wiring.
  Future<void> Function()? onForceRescan;

  /// Runs the existing heartbeat. Wired to `RaspSdk.refresh` — used by the lock
  /// screen to re-check whether the backend has cleared the lock.
  Future<void> Function()? onRecheck;

  final Set<int> _processed = <int>{};
  RemoteMessage? _pendingMessage;
  RemoteLockState _lock = const RemoteLockState.unlocked();
  int? _lockCommandId;

  RemoteMessage? get pendingMessage => _pendingMessage;
  RemoteLockState get lockState => _lock;

  /// Feed the raw `pending_commands` array straight from the heartbeat payload.
  /// Each command runs at most once (idempotent by id, both in-memory this
  /// process's lifetime and persisted across restarts — see
  /// [RemoteCommandExecutionLedger]) and one failing command never aborts
  /// the batch.
  /// Cryptographic Remote Command Integrity milestone, Phase 14 — a resource
  /// bound on the batch itself, independent of the backend's own `LIMIT 20`
  /// (`sdk_router.py::_collect_pending_commands`). Defense in depth: a
  /// tampered or forged heartbeat response is exactly the threat this
  /// milestone's signature defends against, and an oversized array of fake
  /// entries would otherwise make this device do real parsing/verification
  /// work for every one of them before any of it fails.
  static const int maxCommandsPerBatch = 50;

  Future<void> ingest(List<dynamic> rawCommands) async {
    if (rawCommands.isEmpty) return;
    final bounded = rawCommands.length > maxCommandsPerBatch
        ? rawCommands.sublist(0, maxCommandsPerBatch)
        : rawCommands;

    // Resolved once per batch, not per command — this device's own identity
    // does not change mid-batch, and resolving it once avoids redundant
    // platform-channel/secure-storage reads for a heartbeat that commonly
    // carries zero or one command.
    final activationToken = await _activationTokenResolver();
    final deviceId = await _deviceIdResolver();
    final applicationId = await _applicationIdResolver();

    for (final raw in bounded) {
      await _ingestOne(
        raw,
        activationToken: activationToken,
        deviceId: deviceId,
        applicationId: applicationId,
      );
    }
  }

  Future<void> _ingestOne(
    dynamic raw, {
    required String? activationToken,
    required String? deviceId,
    required String? applicationId,
  }) async {
    final cmd = RemoteCommand.tryParse(raw);
    if (cmd == null) {
      final rawId = raw is Map ? raw['id'] : null;
      final id = rawId is int ? rawId : (rawId is num ? rawId.toInt() : null);
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandRejected,
        commandId: id,
        reason: 'malformed',
      ));
      return;
    }

    unawaited(SecurityEventCenter.recordCommandEvent(
      type: SecurityEventType.commandReceived,
      commandId: cmd.id,
      commandType: cmd.type,
    ));

    if (!_processed.add(cmd.id)) {
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandReplayed,
        commandId: cmd.id,
        commandType: cmd.type,
        reason: 'in_memory_duplicate',
      ));
      return;
    }

    if (await _ledger.hasExecuted(cmd.id)) {
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandReplayed,
        commandId: cmd.id,
        commandType: cmd.type,
        reason: 'already_executed',
      ));
      return;
    }

    if (activationToken == null || deviceId == null || applicationId == null) {
      // Cannot verify at all — fail closed, never execute unverifiable.
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandRejected,
        commandId: cmd.id,
        commandType: cmd.type,
        reason: 'verification_context_unavailable',
      ));
      await _ackAndRecord(cmd,
          succeeded: false, result: 'Could not verify: device context unavailable');
      return;
    }

    final verdict = _verifier.verify(
      cmd,
      activationToken: activationToken,
      observedDeviceId: deviceId,
      observedApplicationId: applicationId,
    );

    if (verdict == RemoteCommandVerdict.expired) {
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandExpired,
        commandId: cmd.id,
        commandType: cmd.type,
      ));
      await _ackAndRecord(cmd, succeeded: false, result: 'Command expired');
      return;
    }

    if (verdict != RemoteCommandVerdict.valid) {
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandRejected,
        commandId: cmd.id,
        commandType: cmd.type,
        reason: verdict.name,
      ));
      await _ackAndRecord(cmd,
          succeeded: false, result: 'Command rejected: ${verdict.name}');
      return;
    }

    unawaited(SecurityEventCenter.recordCommandEvent(
      type: SecurityEventType.commandVerified,
      commandId: cmd.id,
      commandType: cmd.type,
    ));

    try {
      await _handle(cmd);
      await _ledger.markExecuted(cmd.id);
      unawaited(SecurityEventCenter.recordCommandEvent(
        type: SecurityEventType.commandExecuted,
        commandId: cmd.id,
        commandType: cmd.type,
      ));
    } catch (_) {
      // Best-effort: one bad command must not break the rest of the batch.
    }
  }

  /// Wraps [_ack] so every acknowledgement also emits `commandAcknowledged`
  /// — centralized here rather than duplicated in each of the five handler
  /// methods below.
  Future<void> _ackAndRecord(
    RemoteCommand cmd, {
    required bool succeeded,
    required String result,
  }) async {
    await _ack(commandId: cmd.id, succeeded: succeeded, result: result);
    unawaited(SecurityEventCenter.recordCommandEvent(
      type: SecurityEventType.commandAcknowledged,
      commandId: cmd.id,
      commandType: cmd.type,
    ));
  }

  Future<void> _handle(RemoteCommand cmd) async {
    switch (cmd.type) {
      case RemoteCommand.forceRescan:
        await _forceRescan(cmd);
        return;
      case RemoteCommand.showMessage:
        await _showMessage(cmd);
        return;
      case RemoteCommand.lockApp:
        await _lockApp(cmd);
        return;
      case RemoteCommand.unlockApp:
        await _unlockApp(cmd);
        return;
      default:
        // WIPE_LOCAL_DATA (out of scope) and any unknown/newer type: honestly
        // acknowledged as unsupported, never executed.
        await _ackAndRecord(
          cmd,
          succeeded: false,
          result: 'Command ${cmd.type} is not supported by this SDK build',
        );
    }
  }

  Future<void> _forceRescan(RemoteCommand cmd) async {
    final rescan = onForceRescan;
    if (rescan == null) {
      await _ackAndRecord(cmd, succeeded: false, result: 'No active scanner');
      return;
    }
    try {
      await rescan();
      await _ackAndRecord(cmd, succeeded: true, result: 'Rescan completed');
    } catch (e) {
      await _ackAndRecord(cmd, succeeded: false, result: 'Rescan failed: $e');
    }
  }

  Future<void> _showMessage(RemoteCommand cmd) async {
    final body = (cmd.payload['message'] as String?)?.trim() ?? '';
    if (body.isEmpty) {
      await _ackAndRecord(cmd, succeeded: false, result: 'Empty message');
      return;
    }
    final rawTitle = (cmd.payload['title'] as String?)?.trim();
    _pendingMessage = RemoteMessage(
      commandId: cmd.id,
      body: body,
      title: (rawTitle == null || rawTitle.isEmpty) ? null : rawTitle,
    );
    notifyListeners();
    await _ackAndRecord(cmd, succeeded: true, result: 'Message displayed');
  }

  /// Clear the current SHOW_MESSAGE dialog (user tapped Dismiss).
  void dismissMessage() {
    if (_pendingMessage == null) return;
    _pendingMessage = null;
    notifyListeners();
  }

  /// Persistent Remote Lock Enforcement milestone — applies both the live,
  /// in-app overlay (unchanged: [RemoteCommandHost] still reads [lockState]
  /// so a device already inside the app locks immediately, with no restart
  /// needed) **and** the persisted [EnforcementStateStore], via
  /// [EnforcementController.applyRemoteLock], so the block survives a
  /// force-stop, process death, or reboot. Order matters: the persistence
  /// call happens first, so a persistence failure is known (via the
  /// security event it emits) before the in-app UI ever claims the device
  /// is locked.
  ///
  /// By the time this runs, [cmd] has already passed cryptographic
  /// verification (Cryptographic Remote Command Integrity milestone) —
  /// device/application binding, freshness, and signature are no longer
  /// this method's concern; see `_ingestOne`.
  Future<void> _lockApp(RemoteCommand cmd) async {
    unawaited(SecurityEventCenter.recordRemoteLockEvent(
      type: SecurityEventType.remoteLockReceived,
      commandId: cmd.id,
    ));

    final reason = (cmd.payload['message'] as String?)?.trim();
    final effectiveReason = (reason == null || reason.isEmpty)
        ? 'Your administrator has locked this app.'
        : reason;

    await _enforcement.applyRemoteLock(commandId: cmd.id, reason: effectiveReason);

    _lock = RemoteLockState.locked(reason: effectiveReason);
    _lockCommandId = cmd.id;
    _pendingMessage = null; // a lock supersedes any dialog underneath it
    notifyListeners();
    await _ackAndRecord(cmd, succeeded: true, result: 'App locked');
  }

  /// Persistent Remote Lock Enforcement milestone — the explicit,
  /// authenticated recovery path (Phase 6). Clears both the persisted
  /// state (so a future launch is no longer gated by `RaspGateScreen`)
  /// and the live in-app overlay (so a device currently inside the locked
  /// screen unlocks immediately, without needing a restart).
  ///
  /// Cryptographic Remote Command Integrity milestone, Phase 10 — UNLOCK_APP
  /// is held to the SAME mandatory verification as every other command by
  /// `_ingestOne` before this method is ever called: unsigned, replayed,
  /// stale, or wrong-device UNLOCK_APP commands never reach here at all.
  /// There is no separate, weaker local unlock path.
  Future<void> _unlockApp(RemoteCommand cmd) async {
    await _enforcement.applyRemoteUnlock(commandId: cmd.id);
    _lock = const RemoteLockState.unlocked();
    _lockCommandId = null;
    notifyListeners();
    await _ackAndRecord(cmd, succeeded: true, result: 'App unlocked');
  }

  /// Lock-screen "Re-check": run the existing heartbeat, then clear the lock
  /// only if the device is healthy again (existing license/session state) and
  /// no fresh LOCK_APP arrived during that heartbeat. This reuses the backend's
  /// own contract — a blocked/unhealthy device stays locked; an ACTIVE one is
  /// released. A clean scan alone never reaches this path and never clears a
  /// remote lock — only a healthy *heartbeat* (the same authenticated channel
  /// a lock/unlock command itself travels) does.
  Future<void> recheckLock() async {
    final before = _lockCommandId;
    await onRecheck?.call();
    if (_lockCommandId != before) return; // re-latched by a new LOCK_APP
    if (_isHealthy()) {
      _lock = const RemoteLockState.unlocked();
      await _enforcement.clear();
      notifyListeners();
    }
  }

  @visibleForTesting
  void resetForTests() {
    _processed.clear();
    _pendingMessage = null;
    _lock = const RemoteLockState.unlocked();
    _lockCommandId = null;
  }
}
