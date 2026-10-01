/**
 * Public types — kept field-for-field identical to the Flutter SDK
 * (`lib/sdk/lean_session.dart`) and the Android Native SDK
 * (`RaspLeanSession.kt`), so all three SDKs share one mental model and
 * ship byte-identical events to the dashboard.
 */

/**
 * Every detector reports exactly one of these — never a bare boolean.
 *
 * The single most important rule of this SDK: a check that could not run
 * or could not conclude is NEVER reported as `SECURE`. Only `DETECTED` is
 * a threat; only `SECURE` is safe; the other three mean "no verdict".
 */
export type DetectionStatus = 'SECURE' | 'DETECTED' | 'UNAVAILABLE' | 'UNKNOWN' | 'ERROR';

export type EvidenceValue =
  | string
  | number
  | boolean
  | null
  | EvidenceValue[]
  | { [key: string]: EvidenceValue };

/** One supporting signal behind a result — never raw sensitive data
 *  (e.g. clipboard evidence is a change *count*, never the content). */
export interface DetectionEvidence {
  key: string;
  value: EvidenceValue;
  note?: string | null;
}

export interface DetectionResult {
  detectorId: DetectorId | string;
  status: DetectionStatus;
  evidence: DetectionEvidence[];
  /** Set for UNAVAILABLE / UNKNOWN / ERROR only. */
  reason: string | null;
  observedAtMillis: number;
}

/** Every detector id the SDK can report. Identical across all three SDKs
 *  and the backend's `detectors/severity.ts`. */
export type DetectorId =
  // Original lean controls
  | 'screenshot_protection'
  | 'screenshot_event'
  | 'usb_connection'
  | 'adb_enabled'
  | 'clipboard_protection'
  // Device integrity
  | 'root_jailbreak'
  | 'emulator'
  | 'device_binding'
  | 'clone'
  | 'developer_mode'
  | 'device_lock_missing'
  | 'secure_hardware_unavailable'
  | 'device_fingerprint'
  // Runtime protection
  | 'frida'
  | 'debugger'
  | 're_tools'
  | 'hook_detection'
  | 'risky_app'
  // App integrity
  | 'tamper'
  | 'untrusted_install_source'
  | 'repackage'
  // Network
  | 'vpn'
  | 'mitm'
  | 'high_risk_ip'
  // Privacy & screen
  | 'overlay'
  | 'accessibility'
  | 'external_display'
  // One-shot only (RaspShieldCore.check) — not part of the lean session
  | 'app_intelligence';

/**
 * Which detectors a session runs. Every detector defaults to `false` —
 * nothing activates unless you ask for it.
 */
export interface RaspLeanConfig {
  // Original lean controls
  /** Blocks screenshots & screen recording of your app (FLAG_SECURE). */
  screenshotProtection?: boolean;
  usbDetection?: boolean;
  adbDetection?: boolean;
  /** Watches clipboard changes (count only, never content). */
  clipboardProtection?: boolean;
  /** With clipboardProtection: clears the clipboard on every copy.
   *  Default `true`. Changes real app behavior — users cannot paste
   *  anything copied while your app is running. */
  clipboardAutoClear?: boolean;

  // Device integrity
  rootDetection?: boolean;
  emulatorDetection?: boolean;
  deviceBindingCheck?: boolean;
  cloneDetection?: boolean;
  developerModeDetection?: boolean;
  deviceLockCheck?: boolean;
  secureHardwareCheck?: boolean;
  deviceFingerprintCheck?: boolean;

  // Runtime protection
  fridaDetection?: boolean;
  debuggerDetection?: boolean;
  reverseEngineeringToolsDetection?: boolean;
  hookDetection?: boolean;
  riskyAppDetection?: boolean;

  // App integrity
  tamperDetection?: boolean;
  untrustedInstallSourceDetection?: boolean;
  repackagingDetection?: boolean;
  /** Your release signing certificate SHA-256 (with or without `:`).
   *  Required for `repackagingDetection` to give a real verdict — without
   *  it, `repackage` honestly reports UNAVAILABLE. */
  expectedSigningCertSha256?: string;

  // Network
  vpnDetection?: boolean;
  mitmDetection?: boolean;
  /** Calls the third-party `ipapi.co` API directly. Opt in only if you
   *  accept that dependency. */
  highRiskIpDetection?: boolean;

  // Privacy & screen
  overlayDetection?: boolean;
  accessibilityDetection?: boolean;
  externalDisplayDetection?: boolean;
  /** A screenshot was actually taken (Android 14 / API 34+ only). */
  screenshotEventDetection?: boolean;

  // Timing
  /** How often every enabled detector is re-read. Default 4000 ms,
   *  minimum 1000 ms. */
  pollIntervalMillis?: number;
  /** How often a *standing* DETECTED threat re-confirms itself to the
   *  dashboard. Unchanged SECURE results never re-ship. Default 20000 ms. */
  heartbeatIntervalMillis?: number;
}

/**
 * A point-in-time snapshot of every control the session watches. A
 * control you did not enable always reads `null` / `0` here — never a
 * stale or guessed value.
 */
export interface RaspLeanState {
  screenshotActive: boolean | null;
  usbConnected: boolean | null;
  usbDeviceCount: number;
  usbDebuggingEnabled: boolean | null;
  developerModeEnabled: boolean | null;
  clipboardActive: boolean | null;
  clipboardChangeCount: number;
  /** Every detector beyond the original lean controls, keyed by detector
   *  id — only present for ones you enabled. */
  extendedDetectors: Partial<Record<DetectorId, DetectionResult>>;
  /** When this snapshot was taken (device clock). 0 for the initial state. */
  observedAtMillis: number;
}

/** A location reading supplied entirely by your app — this SDK contains
 *  no location code and never requests location permission. Attached to
 *  DETECTED events only. */
export interface RaspLocationSnapshot {
  latitude: number;
  longitude: number;
  accuracyMeters?: number;
  /** When your app obtained the reading. Defaults to now. */
  capturedAtMillis?: number;
}

/** Contents of the `credential.json` downloaded from the dashboard. */
export interface RaspCredential {
  organization_id: string;
  application_id: string;
  api_key: string;
  api_secret: string;
  ingestion_url: string;
}

export interface RaspSelfTestReport {
  results: DetectionResult[];
  /** `false` means R8/ProGuard stripped or renamed classes the hook
   *  detector inspects — run selfTest() on your RELEASE build in CI. */
  criticalReflectionIntact: boolean;
  erroredDetectorIds: string[];
  unavailableDetectorIds: string[];
}

export interface RaspSdkInfo {
  /** This React Native package's version. */
  sdkVersion: string;
  /** The android_core engine's event-shipper version, when available. */
  engineVersion: string | null;
  platform: string;
  /** `true` only when the native detection engine is linked and running
   *  on this platform. When `false`, every detector reports UNAVAILABLE. */
  nativeAvailable: boolean;
  osVersion: string | null;
  apiLevel: number | null;
}

/** Emitted when the native layer hits a non-fatal fault — e.g. an event
 *  failed to ship (network down, HTTP 401) or a detector threw. The SDK
 *  never throws these into your app; subscribe to observe them. */
export interface RaspShieldErrorEvent {
  source: string;
  message: string;
}
