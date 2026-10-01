import '../license_models.dart';

/// Maps a detector's [SecurityDetector.detectorId] to the license
/// entitlement that unlocks it — the SDK-core home for what used to be
/// duplicated as `SecurityCatalog.entitlementByFeatureId` in the reference
/// app. Promoted here (verbatim, not reinvented) so [RaspShield]'s automatic
/// scan can gate correctly without a host app having to re-supply this
/// mapping itself, and so a customer's own UI and the SDK's own automatic
/// scan can never disagree about which detectors their plan actually grants.
///
/// A detector id with no entry here is **always available** — this is a
/// deliberate, pre-existing distinction (not every detector is a licensed
/// feature; some, like `device_lock_missing` or `adb_enabled`, are baseline
/// device-posture checks every plan includes).
class DetectorEntitlements {
  const DetectorEntitlements._();

  static const Map<String, String> byDetectorId = {
    'root_jailbreak': Entitlement.rootDetection,
    'emulator': Entitlement.emulatorDetection,
    'device_binding': Entitlement.deviceBinding,
    'device_fingerprint': Entitlement.deviceFingerprint,
    'clone': Entitlement.cloneDetection,
    'frida': Entitlement.fridaDetection,
    'debugger': Entitlement.debuggerDetection,
    're_tools': Entitlement.reToolsDetection,
    'tamper': Entitlement.tamperDetection,
    'repackage': Entitlement.repackagingDetection,
    'vpn': Entitlement.vpnDetection,
    'mitm': Entitlement.mitmDetection,
    'high_risk_ip': Entitlement.geoFiltering,
    'overlay': Entitlement.overlayDetection,
    'accessibility': Entitlement.accessibilityDetection,
    'screenshot_protection': Entitlement.screenshotProtection,
    'offline_compliance': Entitlement.offlineCompliance,
  };

  /// The entitlement key gating [detectorId], or `null` when ungated.
  static String? entitlementFor(String detectorId) => byDetectorId[detectorId];
}
