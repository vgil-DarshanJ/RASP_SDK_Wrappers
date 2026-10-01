/// Production release-signing guard.
///
/// Sibling to `SdkConfig`'s production licence guard, not a merge into it —
/// two independent questions ("does this build carry a real licence key?"
/// and "is this build actually signed with a real release certificate?")
/// checked together at startup (Phase 8), each with its own clear failure
/// message, rather than one guard trying to explain two unrelated defects at
/// once.
///
/// ## Why this guard's trigger is `RASP_SIGNING_MODE`, not
/// `RASP_BUILD_ENVIRONMENT`
///
/// The existing licence guard is keyed on `SdkConfig.buildEnvironment`
/// (`RASP_BUILD_ENVIRONMENT`, a Dart `--dart-define`) — deliberately
/// defaulting to `production` when unset, "the stricter reading, so an
/// operator who forgets this flag gets the guard rather than silently
/// bypassing it." That default is exactly why the licence guard was never
/// wired into `main()`: doing so would make a plain `flutter build apk
/// --release` (no dart-defines at all — the whole point of "local
/// development builds continue to work") crash on launch, since the
/// compiled-in demo licence key would trip `demoKeyInRelease` under the
/// defaulted-to-`production` environment.
///
/// `RASP_SIGNING_MODE` (`android/app/build.gradle.kts`'s `raspSigningMode`
/// Gradle property, surfaced via `BuildConfig`) does not have this problem:
/// it defaults to `local`, matching Gradle's own convenience-preserving
/// default. Keying this guard on it means a plain `flutter build apk
/// --release` is genuinely, safely exempt — not "exempt because we forgot
/// to check" — while `-PraspSigningMode=production` (an explicit,
/// deliberate request) is the one and only trigger for strict enforcement.
/// See `docs/RELEASE_SIGNING_MODES.md`.
library;

/// What `MainActivity.signingIdentity()` reports about the installed APK,
/// read once at startup.
///
/// Every field is nullable/has an honest "could not tell" state — the same
/// discipline every other native-channel-backed model in this SDK follows
/// (`DetectionResult`, `DeviceKeyInfo`). `null` is never treated as "safe."
class ReleaseSigningInfo {
  /// Whether the certificate that actually signed the installed APK, right
  /// now, matches Android's well-known debug Distinguished Name
  /// (`CN=Android Debug`). `null` when the native side could not read the
  /// installed certificate at all.
  final bool? isDebugCertificate;

  /// Mirrors `BuildConfig.RASP_RELEASE_SIGNING_CONFIGURED` — whether
  /// `android/key.properties` declared a real keystore when this build was
  /// compiled. `null` when the platform call itself did not answer (wrong
  /// platform, channel not registered).
  final bool? signingConfigured;

  /// Mirrors `BuildConfig.RASP_SIGNING_MODE` (`local` / `staging` /
  /// `production` on Android; `null` on any platform with no native
  /// implementation — currently iOS, see `docs/RELEASE_SIGNING_MODES.md`
  /// "Platform scope"). Self-reported, like `RASP_BUILD_ENVIRONMENT`; a
  /// repackaged build reports whatever its repackager compiled.
  final String? signingMode;

  const ReleaseSigningInfo({
    this.isDebugCertificate,
    this.signingConfigured,
    this.signingMode,
  });

  /// The native call answered nothing usable at all — wrong platform, no
  /// handler registered, or a malformed response. Every field is `null`.
  static const ReleaseSigningInfo unavailable = ReleaseSigningInfo();

  factory ReleaseSigningInfo.fromMap(Map<String, Object?>? raw) {
    if (raw == null) return unavailable;
    return ReleaseSigningInfo(
      isDebugCertificate: raw['is_debug_certificate'] as bool?,
      signingConfigured: raw['signing_configured'] as bool?,
      signingMode: raw['signing_mode'] as String?,
    );
  }
}

/// Outcome of [evaluateProductionSigningGuard] — the release-signing
/// counterpart to `ProductionLicenseGuardResult`, same shape deliberately.
enum ProductionSigningGuardResult {
  /// A real, non-debug signing certificate is confirmed for a build that
  /// declared `RASP_SIGNING_MODE=production`.
  ok,

  /// `kDebugMode` — the guard never applies to a debug build.
  debugExempt,

  /// `RASP_SIGNING_MODE` is `local` (the default) or unset — this build
  /// never claimed to be a production shipment, so nothing is enforced.
  /// This is the state a plain `flutter build apk --release` reports.
  localExempt,

  /// `RASP_SIGNING_MODE=staging` — explicitly a non-production lane;
  /// debug/unconfirmed signing is expected there.
  stagingExempt,

  /// No native signal was available at all (wrong platform — e.g. iOS
  /// today — or the channel did not answer). Distinct from
  /// [signingUnverifiableInProduction]: this build never even declared
  /// itself production, so there is nothing to enforce, only nothing to
  /// report either.
  platformUnavailable,

  /// A build that declared `RASP_SIGNING_MODE=production` whose installed
  /// certificate IS the Android debug certificate —
  /// `NOT_DEBUG_CERTIFICATE` failed.
  debugCertificateInProduction,

  /// A build that declared `RASP_SIGNING_MODE=production` where
  /// `RASP_RELEASE_SIGNING_CONFIGURED` is `false` — no real
  /// `key.properties` was present at build time.
  /// `PRODUCTION_SIGNING_CONFIGURED` failed. In practice this should be
  /// unreachable — the Gradle-level guard already refuses to produce such
  /// a build at all — but the runtime guard does not trust that as its
  /// only line of defence.
  signingNotConfiguredInProduction,

  /// A build that declared `RASP_SIGNING_MODE=production` where the native
  /// side could not determine the installed certificate at all. Never
  /// treated as [ok] — an unproven certificate under a declared-production
  /// build is a failure, not a pass.
  signingUnverifiableInProduction,
}

/// Pure decision function — every branch testable with no platform channel,
/// no real build, mirroring `SdkConfig.evaluateProductionLicenseGuard`
/// exactly. [SdkConfig.checkProductionSigningGuard] is the version any real
/// caller should use.
ProductionSigningGuardResult evaluateProductionSigningGuard({
  required bool isDebug,
  required ReleaseSigningInfo signing,
}) {
  if (isDebug) return ProductionSigningGuardResult.debugExempt;

  final mode = signing.signingMode?.trim().toLowerCase();
  if (mode == null) return ProductionSigningGuardResult.platformUnavailable;
  if (mode == 'staging') return ProductionSigningGuardResult.stagingExempt;
  if (mode != 'production') {
    // 'local', or anything else this build did not explicitly claim as
    // production — the safe, convenience-preserving default.
    return ProductionSigningGuardResult.localExempt;
  }

  // PRODUCTION_SIGNING_CONFIGURED — checked first: a build that never even
  // attempted real signing is the clearer failure to report.
  if (signing.signingConfigured != true) {
    return ProductionSigningGuardResult.signingNotConfiguredInProduction;
  }

  // NOT_DEBUG_CERTIFICATE — the independent, installed-certificate signal.
  final isDebugCert = signing.isDebugCertificate;
  if (isDebugCert == null) {
    return ProductionSigningGuardResult.signingUnverifiableInProduction;
  }
  if (isDebugCert) {
    return ProductionSigningGuardResult.debugCertificateInProduction;
  }

  return ProductionSigningGuardResult.ok;
}
