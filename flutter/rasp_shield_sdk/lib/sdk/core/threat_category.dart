/// Logical grouping of a `DetectionResult`, independent of any UI section.
///
/// Deliberately mirrors the groupings already used by
/// `rasp/security_feature.dart`'s `SecurityCategory` (device integrity,
/// runtime protection, app integrity, network security, privacy/screen) so a
/// future migration is a rename, not a redesign — plus two categories no
/// current detector reports yet, added so this enum does not need to change
/// the moment a new detector class ships.
enum ThreatCategory {
  /// The physical/virtual device itself: root, jailbreak, emulator, cloning.
  deviceIntegrity,

  /// Live instrumentation of the running process: Frida, hooking, debuggers.
  runtimeProtection,

  /// The app binary/package: tampering, repackaging, signature mismatch.
  appIntegrity,

  /// The network path: VPN, proxy, MITM, high-risk IP.
  networkSecurity,

  /// Screen and input surface: overlays, accessibility abuse, screenshots.
  privacyScreen,

  /// Where the device claims to be: spoofed or implausible location signals.
  locationIntegrity,

  /// No detector-specific category fits; used sparingly, never as a default
  /// that silently hides a missing categorization.
  other,
}
