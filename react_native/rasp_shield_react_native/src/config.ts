import type { DetectorId, RaspLeanConfig } from './types';

/**
 * The config switch that turns each detector on. One source of truth for
 * "which flag runs which detector" — `configFromDetectors` and the
 * UNAVAILABLE fallback (no native module) both read it.
 */
export const DETECTOR_FLAGS: Readonly<Record<DetectorId, keyof RaspLeanConfig>> = {
  screenshot_protection: 'screenshotProtection',
  usb_connection: 'usbDetection',
  adb_enabled: 'adbDetection',
  clipboard_protection: 'clipboardProtection',
  root_jailbreak: 'rootDetection',
  emulator: 'emulatorDetection',
  device_binding: 'deviceBindingCheck',
  clone: 'cloneDetection',
  developer_mode: 'developerModeDetection',
  device_lock_missing: 'deviceLockCheck',
  secure_hardware_unavailable: 'secureHardwareCheck',
  device_fingerprint: 'deviceFingerprintCheck',
  device_state_attestation: 'deviceStateAttestationDetection',
  sim_change: 'simChangeDetection',
  mock_location: 'mockLocationDetection',
  time_spoofing: 'timeSpoofingDetection',
  malware_reputation: 'malwareReputationDetection',
  frida: 'fridaDetection',
  debugger: 'debuggerDetection',
  re_tools: 'reverseEngineeringToolsDetection',
  hook_detection: 'hookDetection',
  risky_app: 'riskyAppDetection',
  tamper: 'tamperDetection',
  repackage: 'repackagingDetection',
  untrusted_install_source: 'untrustedInstallSourceDetection',
  task_hijack: 'taskHijackDetection',
  remote_config_rejected: 'remoteConfigEnabled',
  vpn: 'vpnDetection',
  mitm: 'mitmDetection',
  high_risk_ip: 'highRiskIpDetection',
  unsafe_wifi: 'unsafeWifiDetection',
  overlay: 'overlayDetection',
  accessibility: 'accessibilityDetection',
  external_display: 'externalDisplayDetection',
  screenshot_event: 'screenshotEventDetection',
  screen_recording: 'screenRecordingDetection',
  vishing_call: 'vishingCallDetection',
  third_party_keyboard: 'thirdPartyKeyboardDetection',
  remote_control_app: 'remoteControlAppDetection',
  screen_sharing_risk: 'screenSharingDetection',
  otp_interception_risk: 'otpInterceptionDetection',
  sms_reader_abuse: 'smsReaderAbuseDetection',
  otp_forwarding_risk: 'otpForwardingDetection',
};

/** The detectors whose result is a field of {@link RaspLeanState} rather
 *  than an entry of `extendedDetectors`. */
export const BASIC_CONTROL_IDS: readonly DetectorId[] = [
  'screenshot_protection',
  'usb_connection',
  'adb_enabled',
  'clipboard_protection',
];

/**
 * Builds a session config with exactly the given detectors on (and every
 * other detector off), merged over `base` for the non-detector settings
 * (pins, signing cert, intervals…). Flags in `base` for detectors are
 * overridden — the id list is the source of truth.
 */
export function configFromDetectors(
  enabled: Iterable<DetectorId | string>,
  base: RaspLeanConfig = {},
): RaspLeanConfig {
  const on = new Set<string>(enabled);
  const config: Record<string, unknown> = { ...base };
  for (const [id, flag] of Object.entries(DETECTOR_FLAGS)) {
    config[flag] = on.has(id);
  }
  return config as RaspLeanConfig;
}

/** Detector ids a config switches on. */
export function enabledDetectorIds(config: RaspLeanConfig): DetectorId[] {
  return (Object.entries(DETECTOR_FLAGS) as Array<[DetectorId, keyof RaspLeanConfig]>)
    .filter(([, flag]) => config[flag] === true)
    .map(([id]) => id);
}
