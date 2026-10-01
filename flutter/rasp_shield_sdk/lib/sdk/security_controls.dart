/// A lean, license-free control surface over the native security primitives
/// this SDK ships: screenshot/screen-recording blocking, USB/USB-debugging
/// visibility, and clipboard protection.
///
/// ## Why this exists, separate from [RaspSdk] / `rasp_sdk.dart`
///
/// `RaspSdk.initialize()` activates a licence, starts a heartbeat loop, and
/// gates every detector behind [Entitlement]s — the right entry point for
/// the full commercial platform (SOC console, per-seat licensing, remote
/// kill switch). A consumer that only wants "block screenshots, know when
/// USB debugging is on, stop clipboard leaks" has no reason to touch any of
/// that. Every method here talks straight to the native channel
/// ([RaspNativeChannel]) — no [LicenseManager], no license key, no backend
/// call, ever. Drop this class into an app with nothing else from this
/// package wired up and it works.
///
/// ## Failure model (read before integrating)
///
/// Every method returns a *typed*, never-throwing result:
///
/// * `bool` methods that represent a live native call return `bool?` —
///   `null` means the check could not run (wrong platform, plugin not
///   registered, or the platform threw). **Never treat `null` as `false`.**
///   A `null` result you silently read as "safe" is exactly how a RASP
///   control fails open instead of closed.
/// * "Enable" actions return `bool` — `true` only if the native side
///   confirms the control is actually active afterwards, `false` if it is
///   not (including "not supported on this platform"). They never throw.
/// * Call [verifyIntegration] once at app startup, before relying on any
///   other method here. It tells you, in one shot, whether this plugin is
///   even registered in the running app — the #1 integration mistake this
///   class is built to make loud instead of silent (see its doc).
///
/// ## Platform coverage
///
/// Every control below is Android-only today. On iOS/desktop/web, "enable"
/// methods return `false` and query methods return `null` — see
/// `RaspNativeChannel.isSupportedPlatform`. iOS screenshot *prevention* has
/// no OS-level equivalent to `FLAG_SECURE` at all (Apple does not allow an
/// app to block the system screenshot path); only post-hoc *detection*
/// (`UIApplication.userDidTakeScreenshotNotification`) is possible there,
/// and this class does not paper over that gap with a fake success.
library;

import 'detectors/rasp_native_channel.dart';

/// Physical + logical USB state, returned by [RaspSecurityControls.usbState].
class RaspUsbState {
  const RaspUsbState({
    required this.supported,
    required this.usbConnected,
    required this.usbDebuggingEnabled,
    required this.developerModeEnabled,
    required this.connectedDeviceCount,
  });

  /// `false` means this platform/build cannot answer any of the fields below
  /// — every other field is meaningless (not "negative") in that case.
  final bool supported;

  /// A cable/dock is physically attached right now. `null` when [supported]
  /// is `false` or the read failed.
  final bool? usbConnected;

  /// ADB (USB debugging) is enabled in Developer options. `null` under the
  /// same conditions as [usbConnected].
  final bool? usbDebuggingEnabled;

  /// Developer options are unlocked at all (a weaker signal than
  /// [usbDebuggingEnabled] — a device can have this on with ADB still off).
  final bool? developerModeEnabled;

  /// How many USB devices `UsbManager` currently enumerates. `0` when no
  /// cable is attached or [supported] is `false`.
  final int connectedDeviceCount;

  static const unsupported = RaspUsbState(
    supported: false,
    usbConnected: null,
    usbDebuggingEnabled: null,
    developerModeEnabled: null,
    connectedDeviceCount: 0,
  );

  @override
  String toString() =>
      'RaspUsbState(supported: $supported, usbConnected: $usbConnected, '
      'usbDebuggingEnabled: $usbDebuggingEnabled, '
      'developerModeEnabled: $developerModeEnabled, '
      'connectedDeviceCount: $connectedDeviceCount)';
}

/// Clipboard-guard evidence, returned by [RaspSecurityControls.clipboardEvidence].
class RaspClipboardEvidence {
  const RaspClipboardEvidence({
    required this.supported,
    required this.active,
    required this.autoClearEnabled,
    required this.changeCount,
    required this.lastChangeAt,
  });

  final bool supported;
  final bool active;
  final bool autoClearEnabled;

  /// Primary-clip changes observed since the previous read of this evidence
  /// (read-and-clear, same convention as the screenshot-event counter) —
  /// never the clipboard's actual content.
  final int changeCount;
  final DateTime? lastChangeAt;

  static const unsupported = RaspClipboardEvidence(
    supported: false,
    active: false,
    autoClearEnabled: false,
    changeCount: 0,
    lastChangeAt: null,
  );

  @override
  String toString() =>
      'RaspClipboardEvidence(supported: $supported, active: $active, '
      'autoClearEnabled: $autoClearEnabled, changeCount: $changeCount, '
      'lastChangeAt: $lastChangeAt)';
}

/// Screenshot-*event* evidence — "did someone just take one", distinct from
/// [RaspSecurityControls.isScreenshotProtectionActive] ("is blocking on
/// right now"). See [RaspSecurityControls.screenshotEventEvidence].
///
/// **Android 14 (API 34) and above only.** Below that, [supported] is
/// `false`, honestly — there is no OS callback for this on older Android,
/// and no heuristic (e.g. watching the Pictures/Screenshots folder) is used
/// to fake one.
class RaspScreenshotEventEvidence {
  const RaspScreenshotEventEvidence({
    required this.supported,
    required this.detected,
    required this.count,
    required this.lastAt,
  });

  final bool supported;

  /// `true` when [count] is greater than zero — a real screenshot event
  /// fired since the last read.
  final bool detected;

  /// Screenshot events observed since the previous read (read-and-clear,
  /// same convention as [RaspClipboardEvidence.changeCount]).
  final int count;
  final DateTime? lastAt;

  static const unsupported = RaspScreenshotEventEvidence(
    supported: false,
    detected: false,
    count: 0,
    lastAt: null,
  );

  @override
  String toString() =>
      'RaspScreenshotEventEvidence(supported: $supported, detected: $detected, '
      'count: $count, lastAt: $lastAt)';
}

/// Result of [RaspSecurityControls.verifyIntegration] — a one-shot, loud
/// answer to "is this plugin actually wired into the running app?".
enum RaspIntegrationStatus {
  /// The native plugin answered a real call. Every other method in this
  /// class can be trusted.
  ok,

  /// Every native call attempted so far came back `MissingPluginException` —
  /// the plugin is not registered in this build at all. This is a packaging
  /// mistake (see the class doc's Android integration checklist), not a
  /// device condition. Every "enable" method will silently no-op and every
  /// query will return `null`/`unsupported` until this is fixed.
  pluginNotRegistered,

  /// This platform has no native implementation (anything but Android
  /// today). Expected, not an error.
  unsupportedPlatform,
}

/// The lean, license-free control surface. See the library doc above.
class RaspSecurityControls {
  const RaspSecurityControls._();

  // ── Integration self-check ──────────────────────────────────────────────

  /// Call once at app startup, before relying on any other method here.
  ///
  /// Makes one real native call ([RaspNativeChannel.boolCall] against
  /// `isScreenshotBlockingActive`, already always-on — see
  /// `RaspShieldPlugin`) purely to populate [RaspNativeChannel]'s
  /// attempt/failure counters, then classifies the result.
  ///
  /// The single most common integration mistake with a Flutter plugin is
  /// shipping a build where the plugin never got registered — a stale
  /// `flutter pub get`, a manually edited `settings.gradle` that dropped the
  /// module, R8/ProGuard rules that strip the plugin class. Every symptom of
  /// that mistake looks *identical* to "ran the check, found nothing wrong"
  /// unless something makes it loud. This does.
  static Future<RaspIntegrationStatus> verifyIntegration() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return RaspIntegrationStatus.unsupportedPlatform;
    }
    await RaspNativeChannel.boolCall('isScreenshotBlockingActive');
    if (RaspNativeChannel.isNativeLayerUnavailable) {
      return RaspIntegrationStatus.pluginNotRegistered;
    }
    return RaspIntegrationStatus.ok;
  }

  // ── Screenshot / screen-recording block ─────────────────────────────────
  //
  // FLAG_SECURE is applied automatically at Activity-attach by
  // `RaspShieldPlugin` — a host app does not need to call `enable` for the
  // default case. These are exposed for the two real reasons an app needs
  // manual control: toggling protection off for a specific screen (e.g. a
  // QR code the user is meant to screenshot) and re-enabling it afterwards.

  /// Applies `FLAG_SECURE` to the current window. Returns the real resulting
  /// state (read back from the window, not an assumption) — `true` only if
  /// screenshots/recording are actually blocked afterwards.
  static Future<bool> enableScreenshotProtection() async {
    final result =
        await RaspNativeChannel.boolCall('enableScreenshotRestriction');
    return result ?? false;
  }

  /// Clears `FLAG_SECURE`. Returns the real resulting state, same convention
  /// as [enableScreenshotProtection].
  static Future<bool> disableScreenshotProtection() async {
    final result =
        await RaspNativeChannel.boolCall('disableScreenshotRestriction');
    return result ?? false;
  }

  /// `null` when this could not be determined (no Activity attached yet, or
  /// unsupported platform) — never collapsed into `false`.
  static Future<bool?> isScreenshotProtectionActive() =>
      RaspNativeChannel.boolCall('isScreenshotBlockingActive');

  // ── USB / USB debugging ─────────────────────────────────────────────────

  /// One call for every USB-related fact this SDK can read. Prefer this over
  /// the individual fields below when you need more than one of them — it is
  /// still three native round-trips internally (evidence + adb + dev-mode),
  /// but issued concurrently.
  static Future<RaspUsbState> usbState() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return RaspUsbState.unsupported;
    }
    final results = await Future.wait([
      RaspNativeChannel.mapCall('getUsbConnectionEvidence'),
      RaspNativeChannel.boolCall('isAdbEnabled'),
      RaspNativeChannel.boolCall('isDeveloperModeEnabled'),
    ]);
    final evidence = results[0] as Map<String, Object?>?;
    final adbEnabled = results[1] as bool?;
    final devModeEnabled = results[2] as bool?;
    if (evidence == null || evidence['supported'] != true) {
      return RaspUsbState(
        supported: false,
        usbConnected: null,
        usbDebuggingEnabled: adbEnabled,
        developerModeEnabled: devModeEnabled,
        connectedDeviceCount: 0,
      );
    }
    return RaspUsbState(
      supported: true,
      usbConnected: evidence['connected'] as bool?,
      usbDebuggingEnabled: adbEnabled,
      developerModeEnabled: devModeEnabled,
      connectedDeviceCount: (evidence['device_count'] as int?) ?? 0,
    );
  }

  /// `null` when it could not be determined — never collapsed into `false`.
  static Future<bool?> isUsbConnected() =>
      RaspNativeChannel.boolCall('isUsbConnected');

  /// `null` when it could not be determined — never collapsed into `false`.
  static Future<bool?> isUsbDebuggingEnabled() =>
      RaspNativeChannel.boolCall('isAdbEnabled');

  // ── Clipboard protection ────────────────────────────────────────────────

  /// Starts monitoring the clipboard and, with [autoClearOnCopy] (the
  /// default), overwrites every copy made anywhere on the device while this
  /// app is attached with an empty clip. Returns `true` only if the guard is
  /// actually active afterwards. See the library doc's honest limits — this
  /// raises the bar, it is not an absolute guarantee.
  static Future<bool> enableClipboardProtection({
    bool autoClearOnCopy = true,
  }) async {
    final result = await RaspNativeChannel.boolCall(
      'enableClipboardProtection',
      {'autoClearOnCopy': autoClearOnCopy},
    );
    return result ?? false;
  }

  /// Stops monitoring/enforcing. Idempotent, never throws.
  static Future<void> disableClipboardProtection() async {
    await RaspNativeChannel.boolCall('disableClipboardProtection');
  }

  /// `null` when it could not be determined — never collapsed into `false`.
  static Future<bool?> isClipboardProtectionActive() =>
      RaspNativeChannel.boolCall('isClipboardProtectionActive');

  /// Immediately overwrites the clipboard with an empty clip, independent of
  /// whether protection/auto-clear is enabled. Use this right after copying
  /// something sensitive intentionally (e.g. showing a one-time code the
  /// user copies once) instead of leaving the guard on permanently.
  static Future<bool> clearClipboard() async {
    final result = await RaspNativeChannel.boolCall('clearClipboard');
    return result ?? false;
  }

  /// Read-and-clear evidence of clipboard activity since the last read —
  /// never the clipboard's actual content. See [RaspClipboardEvidence].
  ///
  /// **Destructive, single-consumer state.** [RaspLeanSession] (when you
  /// enable `clipboardProtection`) calls this itself, on its own poll tick,
  /// to decide whether `clipboard_protection`'s reported result changed. A
  /// second independent caller — e.g. your own UI polling this on its own
  /// timer to show a live "changes so far" readout — resets the same
  /// counter out from under the lean session, which then sees an
  /// inconsistent count on nearly every tick and re-ships the "still
  /// SECURE" result far more often than intended. **If you're using
  /// [RaspLeanSession] and just want to show live evidence in your own UI,
  /// call [peekClipboardEvidence] instead** — same data, never resets
  /// anything. Only call this one directly if you are not using
  /// [RaspLeanSession] and are implementing your own shipping loop.
  static Future<RaspClipboardEvidence> clipboardEvidence() async {
    final raw = await RaspNativeChannel.mapCall('getClipboardEvidence');
    return _clipboardEvidenceFromRaw(raw);
  }

  /// Same data as [clipboardEvidence], but read-only — never resets the
  /// change counter. Safe to call from your own UI on any timer, as often
  /// as you like, with zero effect on what [RaspLeanSession] sees or ships.
  /// This is the one to use for a live on-screen display.
  static Future<RaspClipboardEvidence> peekClipboardEvidence() async {
    final raw = await RaspNativeChannel.mapCall('peekClipboardEvidence');
    return _clipboardEvidenceFromRaw(raw);
  }

  static RaspClipboardEvidence _clipboardEvidenceFromRaw(Map<String, Object?>? raw) {
    if (raw == null || raw['supported'] != true) {
      return RaspClipboardEvidence.unsupported;
    }
    final lastAtMillis = raw['last_change_at_millis'] as int?;
    return RaspClipboardEvidence(
      supported: true,
      active: raw['active'] == true,
      autoClearEnabled: raw['auto_clear_enabled'] == true,
      changeCount: (raw['change_count'] as int?) ?? 0,
      lastChangeAt: lastAtMillis == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(lastAtMillis),
    );
  }

  // ── Screenshot event detection (API 34+) ──────────────────────────────

  /// Read-and-clear: screenshot events observed since the last read.
  /// [RaspLeanSession] (with `screenshotEventDetection: true`) calls this
  /// itself on its own poll tick — a second independent caller draining
  /// this on its own timer would corrupt what the lean session sees, same
  /// risk as [clipboardEvidence]. Use [peekScreenshotEventEvidence] instead
  /// for your own live UI.
  static Future<RaspScreenshotEventEvidence> screenshotEventEvidence() async {
    final raw = await RaspNativeChannel.mapCall('getScreenshotEventEvidence');
    return _screenshotEventEvidenceFromRaw(raw);
  }

  /// Same data as [screenshotEventEvidence], read-only — never resets the
  /// counter. Safe to call from your own UI on any timer.
  static Future<RaspScreenshotEventEvidence> peekScreenshotEventEvidence() async {
    final raw = await RaspNativeChannel.mapCall('peekScreenshotEventEvidence');
    return _screenshotEventEvidenceFromRaw(raw);
  }

  static RaspScreenshotEventEvidence _screenshotEventEvidenceFromRaw(Map<String, Object?>? raw) {
    if (raw == null || raw['supported'] != true) {
      return RaspScreenshotEventEvidence.unsupported;
    }
    final lastAtMillis = raw['last_at_millis'] as int?;
    return RaspScreenshotEventEvidence(
      supported: true,
      detected: raw['detected'] == true,
      count: (raw['count'] as int?) ?? 0,
      lastAt: lastAtMillis == null
          ? null
          : DateTime.fromMillisecondsSinceEpoch(lastAtMillis),
    );
  }
}
