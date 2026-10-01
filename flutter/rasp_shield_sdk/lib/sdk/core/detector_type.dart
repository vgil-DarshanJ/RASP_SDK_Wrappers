/// Identifies which detector produced a `DetectionResult`.
///
/// Named after the detector's *mechanism*, not its current UI feature id
/// (`security_catalog.dart` uses ids like `'root_jailbreak'`, `'re_tools'`)
/// and not the backend's wire flag (`root_detected`, `hook_detected`) — this
/// is a third, stable vocabulary that both of those can map onto, so neither
/// the live Security Center's feature ids nor the backend telemetry schema
/// need to change for SDK Core to exist alongside them.
///
/// `custom` exists so a detector added later — by this project or a host
/// app — never has to wait for this enum to be extended before it can
/// produce a `DetectionResult`.
enum DetectorType {
  /// Root/jailbreak, device binding, fingerprint mismatch, device cloning.
  root,

  /// Emulator or virtualized-environment execution.
  emulator,

  /// Attached debugger.
  debugger,

  /// Frida or an equivalent dynamic instrumentation framework.
  frida,

  /// Reverse-engineering tooling present on the device (disassemblers, etc.).
  reverseEngineeringTools,

  /// Method interception / hooking — a resident hooking framework, code
  /// mapped from a writable location, or tampering with the SDK's own
  /// security-critical methods. Distinct from [frida]: dynamic
  /// instrumentation and Java-level method hooking are independent
  /// mechanisms, observed by independent native signals.
  hook,

  /// The app binary/package has been modified since signing.
  tamper,

  /// The app has been repackaged under a different identity.
  repackage,

  /// Signing certificate does not match the expected one.
  signatureMismatch,

  /// An active VPN connection.
  vpn,

  /// Man-in-the-middle / intercepted-traffic proxy.
  proxy,

  /// Traffic originates from an IP with a known-bad reputation.
  highRiskIp,

  /// A view is drawn on top of the app (tapjacking / overlay attack).
  overlay,

  /// The Accessibility service is being used to read or drive the app.
  accessibility,

  /// A screenshot or screen recording was taken while protection was active.
  screenshot,

  /// The reported location is spoofed or otherwise implausible.
  locationSpoof,

  /// The device clock has been shifted to defeat time-based checks.
  timeSpoof,

  /// A known-risky application (remote-access tool, instrumentation
  /// framework) or a risky environment capability (an active third-party
  /// accessibility service) was found present — see
  /// `docs/RISKY_APP_DETECTION.md`. Not a malware scanner: a curated,
  /// evidence-based check, distinct from [reverseEngineeringTools] (which
  /// covers on-device RE tooling, not remote-access/social-engineering
  /// tools).
  riskyApp,

  /// A detector not covered by the named values above.
  custom,
}
