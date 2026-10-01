import 'package:flutter/services.dart';

/// Flutter ↔ native platform channel surface for the RASP SDK.
///
/// ## Why this exists
///
/// Every native read the SDK/demo app does today (`security_catalog.dart`,
/// `device_fingerprint_service.dart`, `ssl_pinning_service.dart`,
/// `location_manager.dart`'s network-operator read, and others) calls its own
/// ad-hoc `MethodChannel('com.shieldsdk.security/security')` directly,
/// handled inline by the demo app's `MainActivity.kt`. That channel is
/// owned by the demo app, not the SDK, and mixes unrelated concerns behind
/// one name — it cannot become a real platform integration surface without
/// either the SDK depending on the demo app's `MainActivity`, or every
/// existing call site being rewritten.
///
/// `NativeBridge` is a **separate**, SDK-owned channel
/// (`com.shieldsdk.rasp/native_bridge`), so the SDK's future native
/// integrity/anti-tamper/hooking checks have a home that does not touch — or
/// risk breaking — anything the demo app's existing channel already does.
///
/// ## Current state: architecture only
///
/// This class only *defines* the channel surface. Nothing in the app calls
/// it, and no native side registers a handler for it (see
/// `android/src/main/kotlin/com/shieldsdk/rasp/bridge/`,
/// `ios/Classes/Bridge/`) — every method here would throw a
/// `MissingPluginException` if invoked today, exactly as an unregistered
/// channel should. That is intentional: this task prepares the shape of the
/// bridge, not a working implementation.
///
/// ## Future migration plan
///
/// 1. A native stub (Kotlin `MethodCallHandler` / Swift `FlutterPlugin`) is
///    implemented in `bridge/` to actually answer these calls, delegating to
///    `platform/`, `detectors/`, `integrity/`, `network/`, `security/` on
///    each platform.
/// 2. [executeDetector] becomes the transport a native-backed
///    `SecurityDetector` (see `sdk/detectors/security_detector.dart`) uses
///    inside its `scan()` — the native side does the check, this bridge
///    carries the answer back, and the Dart detector wraps it into a
///    `DetectionResult` exactly like a pure-Dart detector would.
/// 3. [startProtection] / [stopProtection] become the hook for native-side
///    continuous monitoring (e.g. anti-hooking, memory integrity) that a
///    pure-Dart detector cannot perform on its own — orchestrated by
///    whatever eventually calls `ProtectionEngine.evaluate()`, not by this
///    class itself.
class NativeBridge {
  const NativeBridge._();

  /// Channel name is namespaced to the SDK (`com.shieldsdk.rasp`), distinct
  /// from the demo app's existing `com.shieldsdk.security/security` channel.
  static const MethodChannel _channel =
      MethodChannel('com.shieldsdk.rasp/native_bridge');

  /// Prepares the native side for use. Intended to run once, before
  /// [startProtection] — the native equivalent of `SdkConfig.configure()`.
  static Future<void> initialize() {
    return _channel.invokeMethod<void>('initialize');
  }

  /// Starts native-side continuous protection (future: anti-tamper,
  /// anti-hooking, integrity monitoring). No-op contract until a native
  /// implementation exists.
  static Future<void> startProtection() {
    return _channel.invokeMethod<void>('startProtection');
  }

  /// Stops whatever [startProtection] started.
  static Future<void> stopProtection() {
    return _channel.invokeMethod<void>('stopProtection');
  }

  /// The native platform's version string (e.g. Android API level, iOS
  /// version), for diagnostics and minimum-version policy decisions.
  static Future<String?> getPlatformVersion() {
    return _channel.invokeMethod<String>('getPlatformVersion');
  }

  /// Runs a single native-backed detector by id and returns its raw result.
  ///
  /// Returns a plain map rather than a `DetectionResult` on purpose — this
  /// bridge has no opinion about SDK Core; the Dart-side detector that calls
  /// this is responsible for mapping the native answer into a
  /// `DetectionResult`, the same way every other detector does.
  static Future<Map<String, dynamic>?> executeDetector(
    String detectorId,
  ) async {
    final result = await _channel.invokeMapMethod<String, dynamic>(
      'executeDetector',
      {'detectorId': detectorId},
    );
    return result;
  }
}
