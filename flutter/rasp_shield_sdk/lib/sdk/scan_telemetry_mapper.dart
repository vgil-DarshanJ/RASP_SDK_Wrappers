import 'core/detection_result.dart';

/// Translates the live Security Center's per-feature outcomes into the boolean
/// threat flags the backend's `POST /api/v1/security/analyze` endpoint expects.
///
/// This is the **only** bridge between the live detector's feature ids
/// (defined in `SecurityCatalog`, in `rasp/security_catalog.dart`) and the
/// backend telemetry schema. It is deliberately a pure function of "is
/// feature X a threat?", so it can be unit-tested with no device, no network,
/// and no running scan.
///
/// Depends only on SDK Core (`sdk/core/`) — plain Dart data, no
/// `material.dart`, no `FeatureOutcome`/`SecurityFeature`. The live Security
/// Center still evaluates and renders with its own UI-shaped types; this
/// mapper is reached only through a caller-supplied predicate ([threatFlags])
/// or a plain [DetectionResult] map ([threatFlagsFromDetections]), so it
/// never needs to know how a feature is displayed.
///
/// ## Field coverage
///
/// The map produced here is exactly the flag set the existing
/// `TelemetryManager.report()` already sends, so the request format is reused
/// unchanged. The backend schema (`ThreatAnalysisRequest`) also accepts
/// `location_spoof`, `time_spoof`, and `screenshot_detected`, but **no live
/// Security Center feature detects those yet**, so they are intentionally
/// omitted rather than reported as a fabricated `false` (the backend defaults
/// each unspecified flag to `false`, so the persisted row is identical either
/// way — omitting keeps the payload honest about what was actually evaluated).
///
/// ## Detectors with no backend flag
///
/// Three live features have no corresponding column in the telemetry schema and
/// so cannot be represented as a dedicated flag without inventing a new field
/// (explicitly out of scope): `device_binding`, `device_fingerprint`, and
/// `high_risk_ip`. A threat from one of those still contributes to the device's
/// on-screen protection score, but does not set a boolean in the uploaded
/// payload. This is a known, documented gap — see LIVE_TELEMETRY_WIRING.md.
class ScanTelemetryMapper {
  const ScanTelemetryMapper._();

  /// Build the backend threat-flag payload from a predicate that answers
  /// "did the Security Center feature with this id report a threat?".
  ///
  /// Keeping the input as a predicate (rather than the controller or its
  /// private results map) is what makes this trivially testable and keeps the
  /// mapper free of any dependency on `SecurityCenterController`.
  static Map<String, bool> threatFlags(bool Function(String featureId) isThreat) {
    return {
      'root_detected': isThreat('root_jailbreak'),
      'frida_detected': isThreat('frida'),
      'debugger_detected': isThreat('debugger'),
      'emulator_detected': isThreat('emulator'),
      // Both app-integrity checks collapse onto the single backend flag, matching
      // the legacy report() mapping (isTampered || isRepackaged).
      'tamper_detected': isThreat('tamper') || isThreat('repackage'),
      'vpn_detected': isThreat('vpn'),
      'proxy_detected': isThreat('mitm'),
      'overlay_detected': isThreat('overlay'),
      'accessibility_abuse': isThreat('accessibility'),
      'hook_detected': isThreat('re_tools'),
      'malware_detected': isThreat('clone'),
      // Device-posture flags. Unlike the detections above these describe how
      // exposed the device is rather than an attack in progress, and the
      // backend weights them accordingly.
      'untrusted_install_source': isThreat('untrusted_install_source'),
      'adb_enabled': isThreat('adb_enabled'),
      'device_lock_missing': isThreat('device_lock_missing'),
      'developer_mode_enabled': isThreat('developer_mode'),
      'secure_hardware_unavailable': isThreat('secure_hardware_unavailable'),
    };
  }

  /// Convenience over [threatFlags] for an already-resolved map of SDK Core
  /// [DetectionResult]s, e.g. a snapshot of a detector run mapped by feature
  /// id. A missing entry is treated as "not a threat", same as before.
  ///
  /// This replaces the previous `threatFlagsFromOutcomes(Map<String,
  /// FeatureOutcome>)` overload, which depended on `rasp/security_feature.dart`
  /// (and, transitively, `material.dart`). No production caller used that
  /// overload — `SecurityCenterController` has always called [threatFlags]
  /// directly with a predicate — so this rename carries no behavior change
  /// for the running app.
  static Map<String, bool> threatFlagsFromDetections(
    Map<String, DetectionResult> detections,
  ) =>
      threatFlags((id) => detections[id]?.threatDetected ?? false);
}
