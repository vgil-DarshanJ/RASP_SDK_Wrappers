/**
 * Public types — field-for-field identical to the Flutter SDK
 * (`lib/sdk/lean_session.dart`) and the Android Native SDK, so all three
 * SDKs share one mental model and ship the same events to the dashboard.
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

/** The 43 on-device detector ids. Identical across all SDKs and the
 *  backend's `detectors/severity.ts`. */
export type DetectorId =
  // Basic controls
  | 'screenshot_protection'
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
  | 'device_state_attestation'
  | 'sim_change'
  | 'mock_location'
  | 'time_spoofing'
  | 'malware_reputation'
  // Runtime protection
  | 'frida'
  | 'debugger'
  | 're_tools'
  | 'hook_detection'
  | 'risky_app'
  // App integrity
  | 'tamper'
  | 'repackage'
  | 'untrusted_install_source'
  | 'task_hijack'
  | 'remote_config_rejected'
  // Network security
  | 'vpn'
  | 'mitm'
  | 'high_risk_ip'
  | 'unsafe_wifi'
  // Privacy & screen
  | 'overlay'
  | 'accessibility'
  | 'external_display'
  | 'screenshot_event'
  | 'screen_recording'
  | 'vishing_call'
  | 'third_party_keyboard'
  | 'remote_control_app'
  | 'screen_sharing_risk'
  | 'otp_interception_risk'
  | 'sms_reader_abuse'
  | 'otp_forwarding_risk';

/**
 * Which detectors a session runs and how. Every detector defaults to
 * `false` — nothing activates unless you ask for it. Names match the
 * Kotlin `RaspLeanConfig` exactly.
 */
export interface RaspLeanConfig {
  // Basic controls
  /** Blocks screenshots & screen recording of your app (FLAG_SECURE). */
  screenshotProtection?: boolean;
  usbDetection?: boolean;
  adbDetection?: boolean;
  /** Watches clipboard changes (count only, never content). */
  clipboardProtection?: boolean;
  /** With clipboardProtection: clears the clipboard on every copy (default `true`). */
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
  deviceStateAttestationDetection?: boolean;
  /** Reject a security patch older than this many days. */
  maxSecurityPatchAgeDays?: number;
  /** Needs the READ_PHONE_STATE permission. */
  simChangeDetection?: boolean;
  /** Needs a location from {@link RaspLeanSession.setLocation}. */
  mockLocationDetection?: boolean;
  timeSpoofingDetection?: boolean;
  /** A trusted server time, e.g. from an HTTP `Date` header. */
  serverTimeMillis?: number;
  malwareReputationDetection?: boolean;
  malwareReputationListJson?: string;
  malwareReputationPublicKey?: string;
  /** Fetch the signed list from the backend (needs a credential). */
  malwareReputationAutoUpdate?: boolean;
  malwareReputationRefreshHours?: number;

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
   *  Without it `tamper` reports UNKNOWN and `repackage` UNAVAILABLE. */
  expectedSigningCertSha256?: string;
  expectedInstallers?: string[];
  expectedClassesDexSha256?: string;
  expectedResourcesArscSha256?: string;
  taskHijackDetection?: boolean;

  // Network
  vpnDetection?: boolean;
  mitmDetection?: boolean;
  certificatePinHost?: string;
  certificatePins?: string[];
  /** Asks the platform backend (needs a credential). */
  highRiskIpDetection?: boolean;
  unsafeWifiDetection?: boolean;

  // Privacy & screen
  overlayDetection?: boolean;
  accessibilityDetection?: boolean;
  externalDisplayDetection?: boolean;
  /** A screenshot was actually taken (Android 14+, DETECT_SCREEN_CAPTURE). */
  screenshotEventDetection?: boolean;
  screenRecordingDetection?: boolean;
  /** Needs READ_PHONE_STATE. */
  vishingCallDetection?: boolean;
  thirdPartyKeyboardDetection?: boolean;
  trustedKeyboardPackages?: string[];
  remoteControlAppDetection?: boolean;
  remoteControlListJson?: string;
  remoteControlListPublicKey?: string;
  screenSharingDetection?: boolean;
  otpInterceptionDetection?: boolean;
  notificationListenerAllowlist?: string[];
  smsReaderAbuseDetection?: boolean;
  smsAppAllowlist?: string[];
  otpForwardingDetection?: boolean;
  autoForwardPackages?: string[];

  // Session risk
  sessionRiskScoring?: boolean;
  riskMediumThreshold?: number;
  riskHighThreshold?: number;
  stepUpThreshold?: number;
  highRiskTransactionMode?: boolean;
  /** `account_hash_salt` from the credential, when set explicitly. */
  accountHashSalt?: string;

  // Delivery
  /** Device-key-signed evidence envelopes (default `true`). */
  useEvidenceEnvelope?: boolean;
  /** How often every enabled detector is re-read. Default 4000, minimum 1000. */
  pollIntervalMillis?: number;
  /** How often a standing DETECTED threat re-confirms itself. Default 20000. */
  heartbeatIntervalMillis?: number;
  locationHeartbeatIntervalMillis?: number;

  // Signed remote configuration
  remoteConfigEnabled?: boolean;
  remoteManagedDetectors?: string[];
  remoteConfigPollMinutes?: number;
  remoteConfigPublicKey?: string;
}

export type RiskVerdict = 'LOW' | 'MEDIUM' | 'HIGH' | 'UNKNOWN';

export interface RaspRiskAssessment {
  /** `null` until the first evaluation (or when scoring is off). */
  score: number | null;
  maxPossibleScore: number | null;
  verdict: RiskVerdict;
  stepUpRecommended: boolean;
  firedGroups: string[];
  undecidedGroups: string[];
  contributingDetectors: string[];
  highRiskTransactionMode: boolean;
  evaluatedAtMillis: number;
}

export type RemoteConfigStatus =
  | 'OFF'
  | 'UNAVAILABLE'
  | 'WAITING'
  | 'APPLIED'
  | 'REJECTED'
  | 'EXPIRED';

export interface RaspLocationHeartbeatStatus {
  atMillis: number;
  outcome: 'DELIVERED' | 'NOT_DELIVERED' | 'REJECTED' | 'NOT_CONFIGURED';
  detail: string;
  cleared: boolean;
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
  /** Every detector beyond the basic controls, keyed by detector id —
   *  only present for ones you enabled. */
  extendedDetectors: Partial<Record<DetectorId, DetectionResult>>;
  risk: RaspRiskAssessment | null;
  locationHeartbeat: RaspLocationHeartbeatStatus | null;
  remoteConfigVersion: number | null;
  remoteConfigStatus: RemoteConfigStatus;
  /** When this snapshot was taken (device clock). 0 for the initial state. */
  observedAtMillis: number;
}

/** A location reading supplied entirely by your app — this SDK contains
 *  no location code and never requests location permission. */
export interface RaspLocationSnapshot {
  latitude: number;
  longitude: number;
  accuracyMeters?: number;
  /** When your app obtained the reading. Defaults to now. */
  capturedAtMillis?: number;
  /** The fix's own mock flag, when you have it. */
  isMock?: boolean;
  provider?: string;
  /** `true` only if the user opted in to sharing location with the backend. */
  shareWithBackend?: boolean;
}

/** Contents of the `credential.json` downloaded from the dashboard. */
export interface RaspCredential {
  organization_id: string;
  application_id: string;
  api_key: string;
  api_secret: string;
  ingestion_url: string;
  account_hash_salt?: string;
  reputation_public_key?: string;
  config_public_key?: string;
}

export type RaspSessionEvent = 'login' | 'resume' | 'logout';

export interface RaspSessionReport {
  accountHash: string;
  sessionHash: string;
  event: RaspSessionEvent;
  risk: RaspRiskAssessment;
  sentToBackend: boolean;
}

export interface RaspSignedTransaction {
  canonical: string;
  signatureBase64: string;
  counter: number;
  nonce: string;
  timestampMillis: number;
  beneficiaryHash: string;
  bindingSha256: string;
  deviceKeyId: string;
  risk: RaspRiskAssessment;
}

export interface RaspTransactionReport {
  transaction: RaspSignedTransaction;
  channel: string;
  sentToBackend: boolean;
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
  /** The android-core engine version this build binds to. */
  engineVersion: string | null;
  platform: string;
  /** `true` only when the native detection engine is linked and running
   *  on this platform. When `false`, every detector reports UNAVAILABLE. */
  nativeAvailable: boolean;
  osVersion: string | null;
  apiLevel: number | null;
}

/** Emitted when the native layer hits a non-fatal fault — e.g. a detector
 *  threw. The SDK never throws these into your app; subscribe to observe. */
export interface RaspShieldErrorEvent {
  source: string;
  message: string;
}
