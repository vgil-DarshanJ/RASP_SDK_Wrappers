import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// The one place the SDK's detectors talk to native code.
///
/// ## Why this channel and not `sdk/native/native_bridge.dart`
///
/// `NativeBridge` declares `com.shieldsdk.rasp/native_bridge`, which **no
/// platform registers a handler for** — every call through it throws
/// `MissingPluginException` today. `com.shieldsdk.security/security` is the
/// channel `MainActivity.kt` actually answers, and it is what every live
/// check has always used. Detectors therefore go through here.
///
/// When the native SDK target is real, this class is the single seam that
/// has to change: point [_channel] at the new channel (or delegate to
/// `NativeBridge`) and every detector follows, because none of them owns a
/// `MethodChannel` of its own. That is the entire reason this indirection
/// exists — before it, the channel name was copy-pasted into
/// `security_catalog.dart`, `device_fingerprint_service.dart`,
/// `ssl_pinning_service.dart` and `activation_manager.dart` independently.
///
/// ## Failure model
///
/// Nothing here throws. A detector must be able to tell three states apart:
///
/// * `true`  — native ran the check and it fired
/// * `false` — native ran the check and it did not fire
/// * `null`  — the check could not run (not Android, no handler registered,
///             platform threw)
///
/// `null` is **never** collapsed into `false`. A check that could not run is
/// reported as `unavailable`, not as `secure` — silently reporting "no
/// threat" for a check that never executed is how a RASP SDK ends up lying
/// to a bank.
class RaspNativeChannel {
  const RaspNativeChannel._();

  /// The channel `MainActivity.kt` registers. Do not rename without changing
  /// the native side in lockstep.
  static const MethodChannel _channel =
      MethodChannel('com.shieldsdk.security/security');

  /// Overridable for tests, so a detector can be exercised with no platform
  /// channel and no device. Set to `null` to restore the real channel.
  @visibleForTesting
  static Future<Object?> Function(String method)? testHandler;

  /// Argument-aware test override, checked *before* [testHandler].
  ///
  /// [testHandler] predates any native method that takes arguments and its
  /// signature cannot see them, so a test could not drive
  /// `signWithDeviceKey` (which needs the message to sign) through it.
  /// Rather than change that signature — every existing detector test sets
  /// it — this is a second, additive seam. Setting neither restores the real
  /// channel.
  @visibleForTesting
  static Future<Object?> Function(String method, Object? arguments)?
      testInvokeHandler;

  /// `true` when the current platform has the **full** native detector set.
  /// Android is the only commercial native target today — see
  /// `CURRENT_SDK_RELEASE['platforms']` on the backend, which advertises
  /// Android only.
  ///
  /// Detectors gate on this to say "Available on Android only" for
  /// capabilities iOS has no equivalent of at all (overlay, clone,
  /// installed-app enumeration, ADB, developer mode). That message stays
  /// accurate: those are genuinely Android-only, not merely unimplemented.
  static bool get isSupportedPlatform =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  /// `true` when the current platform registers the security channel at all.
  ///
  /// Distinct from [isSupportedPlatform]: iOS now answers a *subset* of the
  /// methods (`AppDelegate.swift`, cross-platform iOS milestone), so calls
  /// must actually be dispatched there. A method iOS does not implement
  /// returns `FlutterMethodNotImplemented` → `null` → `unavailable`, which
  /// is the correct classification for a platform limitation.
  static bool get isNativePlatform =>
      !kIsWeb &&
      (defaultTargetPlatform == TargetPlatform.android ||
          defaultTargetPlatform == TargetPlatform.iOS);

  /// Invoke a native method returning a boolean, or `null` when the check
  /// could not run. Never throws.
  static Future<bool?> boolCall(String method, [Object? arguments]) async {
    final raw = await _invoke(method, arguments);
    return raw is bool ? raw : null;
  }

  /// Invoke a native method returning a string, or `null` when the call could
  /// not run. Used to probe availability of a native surface whose *parsing*
  /// lives elsewhere (see `DeviceFingerprintDetector`).
  static Future<String?> stringCall(String method) async {
    final raw = await _invoke(method);
    return raw is String ? raw : null;
  }

  /// Invoke a native method returning a list of signal strings. Returns an
  /// empty list when unavailable — callers use this only to enrich a result
  /// that [boolCall] already decided, so "no evidence" degrades the report
  /// rather than the verdict.
  static Future<List<String>> stringListCall(String method) async {
    final raw = await _invoke(method);
    if (raw is! List) return const [];
    return raw.map((e) => e.toString()).toList(growable: false);
  }

  /// Invoke a native method returning a list of structured maps (e.g.
  /// `getRiskyAppEvidence`). Returns an empty list when unavailable —
  /// callers that need to distinguish "ran, found nothing" from "could not
  /// run" should pair this with a [boolCall]/[stringCall] availability probe
  /// first, same convention as [stringListCall].
  static Future<List<Map<String, Object?>>> mapListCall(String method) async {
    final raw = await _invoke(method);
    if (raw is! List) return const [];
    return raw
        .whereType<Map>()
        .map((e) => e.map((k, v) => MapEntry(k.toString(), v)))
        .toList(growable: false);
  }

  /// Invoke a native method returning a structured map, or `null` when the
  /// call could not run. Unlike [mapListCall] this distinguishes "ran and
  /// returned nothing" (`null`) from "ran and returned an empty map"
  /// (`{}`), which the device-key surface needs: an absent key and a
  /// malformed key description are different outcomes.
  static Future<Map<String, Object?>?> mapCall(String method,
      [Object? arguments]) async {
    final raw = await _invoke(method, arguments);
    if (raw is! Map) return null;
    return raw.map((k, v) => MapEntry(k.toString(), v));
  }

  /// Like [mapCall], but a platform error is rethrown as
  /// [PlatformException] instead of becoming `null` — for host-facing calls
  /// whose caller must see why they failed (invalid input, feature off).
  /// `null` still means nothing answered (not a native platform, no plugin).
  static Future<Map<String, Object?>?> mapCallOrThrow(String method, [Object? arguments]) async {
    final Object? raw;
    final argHandler = testInvokeHandler;
    if (argHandler != null) {
      raw = await argHandler(method, arguments);
    } else {
      if (!isNativePlatform) return null;
      _nativeCallAttempts++;
      try {
        raw = await _channel.invokeMethod<Object?>(method, arguments);
      } on MissingPluginException {
        _missingPluginResponses++;
        return null;
      }
    }
    if (raw is! Map) return null;
    return raw.map((k, v) => MapEntry(k.toString(), v));
  }

  // ── Native-layer health (P0-1 loud-failure safety net) ─────────────────
  //
  // `MissingPluginException` specifically means "no plugin answered this
  // channel at all" — a distinct, much stronger signal than a detector
  // returning `false`/`null` for an ordinary reason (permission denied,
  // platform limitation, a genuine negative result). If a packaging mistake
  // ever ships an SDK without its native plugin again (the exact P0-1
  // defect this extraction fixed), every single native call fails this way,
  // and [isNativeLayerUnavailable] below is how a consuming app tells that
  // apart from "scanned, found nothing" — see `RaspSdk.nativeLayerStatus`.
  //
  // Test seams ([testHandler]/[testInvokeHandler]) never touch these
  // counters, so a test suite exercising a fake channel does not skew real
  // production telemetry.
  static int _nativeCallAttempts = 0;
  static int _missingPluginResponses = 0;

  /// `true` only when this platform registers native detectors at all
  /// ([isNativePlatform]), at least one native call has actually been
  /// attempted, and **every** attempt so far has come back
  /// `MissingPluginException` — i.e. the native plugin is not registered in
  /// the running app at all. This is never true from a handful of ordinary
  /// detector negatives; it requires a total, category-level absence.
  static bool get isNativeLayerUnavailable =>
      isNativePlatform &&
      _nativeCallAttempts > 0 &&
      _missingPluginResponses == _nativeCallAttempts;

  /// `true` once at least one native call has actually been attempted (a
  /// real invocation through the platform channel, not a test stub) — lets
  /// a caller distinguish "no evidence yet" from "evidence says available".
  static bool get hasAttemptedNativeCall => _nativeCallAttempts > 0;

  /// How many native calls this app session has attempted — evidence for
  /// [SecurityEventCenter.recordNativeLayerUnavailable]'s event payload, not
  /// itself a decision input (that is [isNativeLayerUnavailable]).
  static int get nativeCallAttemptCount => _nativeCallAttempts;

  /// Test-only reset so one test's channel stubbing cannot leak into
  /// another's assertions about [isNativeLayerUnavailable].
  @visibleForTesting
  static void resetNativeLayerHealthForTesting() {
    _nativeCallAttempts = 0;
    _missingPluginResponses = 0;
  }

  static Future<Object?> _invoke(String method, [Object? arguments]) async {
    final argHandler = testInvokeHandler;
    if (argHandler != null) {
      try {
        return await argHandler(method, arguments);
      } catch (_) {
        return null;
      }
    }
    final handler = testHandler;
    if (handler != null) {
      try {
        return await handler(method);
      } catch (_) {
        return null;
      }
    }
    if (!isNativePlatform) return null;
    _nativeCallAttempts++;
    try {
      return await _channel.invokeMethod<Object?>(method, arguments);
    } on MissingPluginException {
      _missingPluginResponses++;
      return null;
    } catch (_) {
      return null;
    }
  }
}
