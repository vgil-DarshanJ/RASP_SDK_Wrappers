import 'dart:async';

import 'package:flutter/foundation.dart';

import 'detectors/rasp_native_channel.dart';
import 'events/security_event_center.dart';
import 'events/security_event_reporter.dart';
import 'license_manager.dart';
import 'license_models.dart';
import 'log_reporter.dart';
import 'remote_command_dispatcher.dart';
import 'remote_config_manager.dart';
import 'trust/attestation/attestation_orchestrator.dart';
import 'trust/trust_anchor_collector.dart';

export 'license_models.dart' show Entitlement, Entitlements, LicenseState, LicenseStatus, LicenseStateX;
export 'log_reporter.dart' show RaspLogLevel;

/// Whether the native security engine is actually present and answering.
///
/// [available] is the normal case: the native plugin (`RaspShieldPlugin`,
/// package `com.shieldsdk.rasp`) is registered and detectors run for real.
///
/// [unavailable] means every native call this session has come back
/// `MissingPluginException` — the native plugin is not registered in the
/// running app at all. This is a packaging/integration failure, not a scan
/// result: a consuming app MUST NOT render this as "no threats found" or
/// "device is safe". It means security scanning cannot be trusted on this
/// build. See `RaspSdk.nativeLayerStatus` and the P0-1 final report.
///
/// [unknown] means no native call has been attempted yet (e.g. before the
/// first scan), or the platform has no native detector target at all (see
/// `RaspNativeChannel.isNativePlatform`) — neither is evidence of a broken
/// package.
enum NativeSecurityLayerStatus { available, unavailable, unknown }

extension NativeSecurityLayerStatusCode on NativeSecurityLayerStatus {
  /// Stable wire/log identifier — `NATIVE_SECURITY_LAYER_UNAVAILABLE` is the
  /// exact string a console/UI should key its "integration failure" banner
  /// off, distinct from any ordinary scan verdict.
  String get code => switch (this) {
        NativeSecurityLayerStatus.available => 'NATIVE_SECURITY_LAYER_AVAILABLE',
        NativeSecurityLayerStatus.unavailable => 'NATIVE_SECURITY_LAYER_UNAVAILABLE',
        NativeSecurityLayerStatus.unknown => 'NATIVE_SECURITY_LAYER_UNKNOWN',
      };
}

/// Public entry point of the licensed RASP SDK.
///
/// ```dart
/// await RaspSdk.initialize();
/// if (RaspSdk.status.state == LicenseState.pending) { /* await approval */ }
/// if (RaspSdk.allows(Entitlement.fridaDetection)) { /* detector runs */ }
/// ```
class RaspSdk {
  static Timer? _heartbeatTimer;
  static bool _initialized = false;

  /// Current license status. Listen to [LicenseManager.status] for changes.
  static LicenseStatus get status => LicenseManager.status.value;

  static ValueListenable<LicenseStatus> get statusListenable =>
      LicenseManager.status;

  /// Entitlements granted by the active license.
  static Entitlements get entitlements => LicenseManager.entitlements;

  /// `true` when the license is valid *and* grants [entitlementKey].
  static bool allows(String entitlementKey) => LicenseManager.allows(entitlementKey);

  /// Operator-published runtime configuration.
  static Map<String, dynamic> get config => RemoteConfigManager.values;

  /// Whether the native security engine is present and answering — see
  /// [NativeSecurityLayerStatus]. Check this before trusting a "no threats
  /// found" scan result: [NativeSecurityLayerStatus.unavailable] means the
  /// scan could not actually run, not that the device is clean.
  static NativeSecurityLayerStatus get nativeLayerStatus {
    if (!RaspNativeChannel.isNativePlatform ||
        !RaspNativeChannel.hasAttemptedNativeCall) {
      return NativeSecurityLayerStatus.unknown;
    }
    if (RaspNativeChannel.isNativeLayerUnavailable) {
      return NativeSecurityLayerStatus.unavailable;
    }
    return NativeSecurityLayerStatus.available;
  }

  /// Activate the license and start the heartbeat loop.
  ///
  /// Safe to call more than once; subsequent calls refresh rather than
  /// re-activate. Never throws — a failure surfaces as a [LicenseState].
  static Future<LicenseStatus> initialize() async {
    _wireRemoteCommands();
    await RemoteConfigManager.loadCached();

    final result = _initialized
        ? await LicenseManager.refresh()
        : await LicenseManager.initialize();
    _initialized = true;

    await RemoteConfigManager.syncFromLicense();

    // Record what this install's identity looked like once the seat exists, so
    // the post-activation identity re-check has a baseline to compare against.
    // Write-once (see TrustBaselineStore), and only after the licence actually
    // grants something — capturing on a failed activation would baseline an
    // identity the server never accepted.
    if (result.grantsFeatures) {
      await const TrustAnchorCollector().captureBaseline();
      // Fire-and-forget: never delays initialize(), and TrustAnchorCollector
      // reads whatever AttestationOrchestrator.lastResult holds once this
      // completes — see that class's doc comment for why this runs once per
      // session rather than on every scan/heartbeat.
      //
      // P0-5 ordering fix: LicenseManager now awaits one attestation cycle
      // itself, *before* calling /activate, whenever this session's flow
      // actually reaches /activate — see
      // LicenseManager._attestBeforeActivate's doc comment. That already
      // populated AttestationOrchestrator.lastResult, so firing a second
      // cycle here would just repeat the same native Play Integrity call
      // (and consume a second unit of that quota) for no new information.
      // This call now only fires for the path that never reaches
      // _attestBeforeActivate at all: a warm start where a cached
      // activation token heartbeats successfully with no re-activation
      // needed — the one grantsFeatures path that has genuinely never
      // attested this session.
      if (AttestationOrchestrator.lastResult == null) {
        unawaited(AttestationOrchestrator().run());
      }
    }

    _scheduleHeartbeat();
    // Rides the same heartbeat cycle as remote commands — no second timer.
    // A no-op until the device has activated (nothing buffered, or no
    // activation token yet to authenticate the batch with).
    unawaited(DeviceLogReporter.instance.flush());
    // Security events ride the identical cadence — see
    // docs/SECURITY_EVENT_PIPELINE.md. No new timer.
    unawaited(SecurityEventReporter.instance.flush());
    return result;
  }

  /// Re-validate immediately — used on app resume and while a device waits for
  /// administrator approval.
  static Future<LicenseStatus> refresh() async {
    final result = await LicenseManager.refresh();
    await RemoteConfigManager.syncFromLicense();
    _scheduleHeartbeat();
    unawaited(DeviceLogReporter.instance.flush());
    unawaited(SecurityEventReporter.instance.flush());
    unawaited(_notifyHeartbeatListeners());
    return result;
  }

  static bool _commandsWired = false;

  /// Connect the existing heartbeat to the remote-command dispatcher, once.
  /// The heartbeat already delivers `pending_commands`; [LicenseManager]
  /// forwards them here, and the dispatcher's lock screen re-checks by running
  /// the very same heartbeat ([refresh]). No second polling loop is created.
  static void _wireRemoteCommands() {
    if (_commandsWired) return;
    _commandsWired = true;
    final dispatcher = RemoteCommandDispatcher.instance;
    LicenseManager.onPendingCommands = dispatcher.ingest;
    dispatcher.onRecheck = refresh;
  }

  /// Callbacks invoked after every successful heartbeat tick (periodic timer
  /// or an explicit [refresh]). Additive, not a second timer — this is how
  /// [RaspShield] rides the *same* cadence to re-run its protection scan
  /// instead of scheduling a timer of its own. See `_scheduleHeartbeat`'s
  /// and [refresh]'s own "no second timer" discipline, which this preserves.
  static final List<Future<void> Function()> _heartbeatListeners = [];

  /// Register a callback to run after every heartbeat tick. Returns an
  /// unregister function. Never throws on the caller's behalf — a listener
  /// that throws is caught and reported via [logError], not propagated.
  static void Function() addHeartbeatListener(Future<void> Function() listener) {
    _heartbeatListeners.add(listener);
    return () => _heartbeatListeners.remove(listener);
  }

  static Future<void> _notifyHeartbeatListeners() async {
    for (final listener in List.of(_heartbeatListeners)) {
      try {
        await listener();
      } catch (e) {
        logError('heartbeat', 'Heartbeat listener failed: $e');
      }
    }
  }

  /// Consecutive heartbeat ticks that have failed to reach the backend at
  /// all — see [LicenseManager.lastRefreshWasNetworkFailure]. Tracked here
  /// (the timer owner), not in `LicenseManager`, because "a streak" is a
  /// fact about repeated ticks, which only this loop observes.
  static int _consecutiveHeartbeatFailures = 0;

  /// (Re)arm the periodic heartbeat at the operator-configured interval.
  static void _scheduleHeartbeat() {
    _heartbeatTimer?.cancel();
    final minutes = RemoteConfigManager.heartbeatIntervalMinutes.clamp(1, 1440);
    _heartbeatTimer = Timer.periodic(Duration(minutes: minutes), (_) async {
      await LicenseManager.refresh();
      await _trackHeartbeatOutcome();
      await RemoteConfigManager.syncFromLicense();
      await DeviceLogReporter.instance.flush();
      await SecurityEventReporter.instance.flush();
      await _notifyHeartbeatListeners();
    });
  }

  /// Emits [SecurityEventType.heartbeatFailed] on the first failure of a
  /// new streak (not every tick — a persistently offline device would
  /// otherwise flood the timeline once per heartbeat interval) and
  /// [SecurityEventType.heartbeatRecovered] exactly once, on the tick that
  /// ends a real streak.
  static Future<void> _trackHeartbeatOutcome() async {
    if (LicenseManager.lastRefreshWasNetworkFailure) {
      _consecutiveHeartbeatFailures++;
      if (_consecutiveHeartbeatFailures == 1) {
        unawaited(SecurityEventCenter.recordHeartbeatOutcome(recovered: false));
      }
    } else if (_consecutiveHeartbeatFailures > 0) {
      unawaited(SecurityEventCenter.recordHeartbeatOutcome(
        recovered: true,
        evidence: {'failed_ticks': _consecutiveHeartbeatFailures},
      ));
      _consecutiveHeartbeatFailures = 0;
    }
  }

  /// Stop background work. Call from tests or on logout.
  static Future<void> shutdown() async {
    _heartbeatTimer?.cancel();
    _heartbeatTimer = null;
    _initialized = false;
    _heartbeatListeners.clear();
    _consecutiveHeartbeatFailures = 0;
  }

  // ── Device log reporting ─────────────────────────────────────────────
  // Lets the host app (or any part of this SDK) report a structured log
  // line to the backend so it shows up next to this device on the Super
  // Admin and Customer Portal dashboards. Buffered in memory and shipped on
  // the existing heartbeat cadence above — calling this does not itself
  // make a network call.

  /// Record one log line at [level], tagged [tag], with optional structured
  /// [metadata]. Never throws.
  static void log(RaspLogLevel level, String tag, String message,
          {Map<String, dynamic>? metadata}) =>
      DeviceLogReporter.instance.log(level, tag, message, metadata: metadata);

  static void logDebug(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.debug, tag, message, metadata: metadata);

  static void logInfo(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.info, tag, message, metadata: metadata);

  static void logWarning(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.warning, tag, message, metadata: metadata);

  static void logError(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.error, tag, message, metadata: metadata);
}
