import 'package:flutter/foundation.dart';

import 'detectors/rasp_native_channel.dart';
import 'trust/release_signing.dart';

/// Retry behaviour for a single SDK network call (challenge, activate,
/// heartbeat, telemetry).
///
/// Reserved configuration surface: no HTTP client in the SDK reads this yet
/// (`activation_manager.dart`, `remote_command_api.dart`, and
/// `telemetry_manager.dart` build a single `Dio` call with no retry loop
/// today). A host app may still supply a policy now; it becomes effective
/// the moment a future migration wires it into those clients, with no
/// further change required on the host app's side.
class SdkRetryPolicy {
  /// Total attempts for one logical call, including the first. `1` means
  /// "no retry" — the SDK's current, unchanged behaviour.
  final int maxAttempts;

  /// Wait between attempts.
  final Duration delayBetweenAttempts;

  /// Creates a retry policy. Defaults to no retry.
  const SdkRetryPolicy({
    this.maxAttempts = 1,
    this.delayBetweenAttempts = const Duration(seconds: 2),
  });

  /// No retry — a single attempt only. The SDK's default until a host app
  /// requests otherwise.
  static const none = SdkRetryPolicy(maxAttempts: 1);
}

/// Runtime configuration for the licensed RASP SDK.
///
/// **The SDK carries no backend URL of its own.** Every value the SDK needs
/// to reach a server is supplied by the host application through
/// [configure], typically as the very first line of `main()`, before
/// [RaspSdk.initialize] or any other SDK call. This is deliberate: a
/// packaged SDK must never bake one customer's (or one demo's) backend
/// address into the artifact every customer ships.
///
/// ```dart
/// void main() {
///   WidgetsFlutterBinding.ensureInitialized();
///   SdkConfig.configure(
///     backendUrl: 'https://api.your-backend.example.com',
///   );
///   runApp(const MyApp());
/// }
/// ```
///
/// The customer license key remains a build-time secret — unrelated to
/// [configure] and unchanged by this class — supplied via:
///
/// ```
/// flutter build apk --dart-define=RASP_LICENSE_KEY=RASP-XXXX-XXXX-XXXX-XXXX
/// ```
class SdkConfig {
  SdkConfig._();

  static String? _backendUrl;
  static Duration _requestTimeout = const Duration(seconds: 12);
  static Duration _heartbeatInterval = const Duration(minutes: 15);
  static bool _enableDebugLogging = false;
  static SdkRetryPolicy _retryPolicy = SdkRetryPolicy.none;

  /// Supplies every host-provided runtime value in one call. Safe to call
  /// more than once (e.g. hot restart in debug); the latest call wins.
  ///
  /// | Parameter | Host app must supply | SDK default until configured |
  /// |---|---|---|
  /// | [backendUrl] | **Required.** The customer's backend origin, no trailing slash. | none — reading [sdkApiBaseUrl]/[securityApiBaseUrl] before this is called throws [StateError]. |
  /// | [requestTimeout] | Optional. Wall-clock budget for one licensing/telemetry HTTP call. | 12 seconds, matching the SDK's historical behaviour. |
  /// | [heartbeatInterval] | Optional. Local fallback cadence before the server's own remote-config interval (`RemoteConfigManager.heartbeatIntervalMinutes`) has ever been fetched. | 15 minutes. |
  /// | [enableDebugLogging] | Optional. Whether the SDK's `[RASP-TRACE]` diagnostics should be considered enabled by the host app's own logging setup. | `false`. |
  /// | [retryPolicy] | Optional. See [SdkRetryPolicy] — reserved for a future HTTP-client migration. | [SdkRetryPolicy.none]. |
  static void configure({
    required String backendUrl,
    Duration requestTimeout = const Duration(seconds: 12),
    Duration heartbeatInterval = const Duration(minutes: 15),
    bool enableDebugLogging = false,
    SdkRetryPolicy retryPolicy = SdkRetryPolicy.none,
  }) {
    _backendUrl = backendUrl;
    _requestTimeout = requestTimeout;
    _heartbeatInterval = heartbeatInterval;
    _enableDebugLogging = enableDebugLogging;
    _retryPolicy = retryPolicy;
  }

  /// `true` once [configure] has been called at least once.
  static bool get isConfigured => _backendUrl != null;

  static String get _requireBackendUrl {
    final url = _backendUrl;
    if (url == null) {
      throw StateError(
        'SdkConfig.configure(backendUrl: ...) must be called before any SDK '
        'network call. Call it once, e.g. as the first line of main(), '
        'before RaspSdk.initialize(). The SDK intentionally has no built-in '
        'backend URL.',
      );
    }
    return url;
  }

  /// Licensing endpoints (challenge / activate / heartbeat). Derived from the
  /// host-supplied [configure]'s `backendUrl`.
  static String get sdkApiBaseUrl => '$_requireBackendUrl/api/v1/sdk';

  /// Telemetry + AI endpoints. Derived from the host-supplied [configure]'s
  /// `backendUrl`.
  static String get securityApiBaseUrl => '$_requireBackendUrl/api/v1';

  /// Customer license key. Build-time secret, unrelated to [configure] — see
  /// the class-level doc for how a host app supplies it.
  static const String licenseKey = String.fromEnvironment(
    'RASP_LICENSE_KEY',
    defaultValue: 'RASP-DEMO-BANK-TEST-0001',
  );

  /// Per-Build Security Personalization — this build's non-secret identity,
  /// e.g. `bld_3_5_a1b2c3d4`. Compiled in by the customer ZIP's generated
  /// example (`--dart-define=RASP_BUILD_ID=...`), reported at activate and
  /// every heartbeat so the backend can classify it against
  /// `sdk_packages` — see `app/licensing/build_identity.py`.
  ///
  /// Empty for any SDK build predating this milestone or one built without
  /// the define: the server reports [BuildTrustStatus.NOT_REPORTED] for such
  /// a device, a distinct and honest state, never treated as authorized nor
  /// as untrusted. Not a secret — the same category of value as [sdkVersion]
  /// or a bundle id, safe to log and safe to omit.
  static const String buildId = String.fromEnvironment('RASP_BUILD_ID');

  /// Reported to the backend for minimum-version enforcement.
  static const String sdkVersion = '2.0.0';

  /// Wall-clock budget for a single licensing/telemetry HTTP call. Backed by
  /// the host-supplied [configure]'s `requestTimeout` (same value as
  /// [requestTimeout] below); kept under its original name because
  /// `activation_manager.dart`, `remote_command_api.dart`, and
  /// `telemetry_manager.dart` already reference it.
  static Duration get networkTimeout => _requestTimeout;

  /// Same value as [networkTimeout], under the name used by [configure].
  static Duration get requestTimeout => _requestTimeout;

  /// Local heartbeat cadence fallback. See [configure]'s parameter table.
  static Duration get heartbeatInterval => _heartbeatInterval;

  /// Whether the host app has opted into the SDK's debug trace logging.
  static bool get enableDebugLogging => _enableDebugLogging;

  /// Host-supplied retry policy. See [SdkRetryPolicy].
  static SdkRetryPolicy get retryPolicy => _retryPolicy;

  // ── Production license guard ──────────────────────────────────────────
  //
  // A release build that forgets `--dart-define=RASP_LICENSE_KEY=...` at
  // build time silently ships with [licenseKey]'s compiled-in demo default
  // rather than failing to build — there is no compile-time mechanism in
  // Dart to turn "this dart-define was never overridden" into a build
  // error. This is the closest safely-possible substitute: a loud,
  // synchronous, first-line-of-main() check.

  /// The only value [licenseKey] can silently default to. Compared, never
  /// printed — see [assertProductionLicenseConfigured].
  static const String _demoLicenseKey = 'RASP-DEMO-BANK-TEST-0001';

  /// Declares which environment this build is for. `debug` builds
  /// (`kDebugMode`) are always exempt regardless of this value — a demo key
  /// during development is expected, not a defect.
  ///
  /// ```
  /// flutter build apk --release --dart-define=RASP_BUILD_ENVIRONMENT=staging
  /// ```
  ///
  /// Unset in a release/profile build defaults to `production` — the
  /// stricter reading, so an operator who forgets this flag gets the guard
  /// rather than silently bypassing it.
  static const String buildEnvironment = String.fromEnvironment(
    'RASP_BUILD_ENVIRONMENT',
    defaultValue: 'production',
  );

  /// Non-throwing check — safe to call from anywhere, including telemetry
  /// or a dashboard, without risking a crash. Delegates to
  /// [evaluateProductionLicenseGuard], the pure decision function, applying
  /// this build's real compile-time values.
  static ProductionLicenseGuardResult checkProductionLicenseGuard() =>
      evaluateProductionLicenseGuard(
        isDebug: kDebugMode,
        licenseKeyValue: licenseKey,
        environment: buildEnvironment,
      );

  /// Pure decision logic, independent of the real (compile-time-frozen)
  /// [kDebugMode]/[licenseKey]/[buildEnvironment] — so a test can exercise
  /// every branch (including "release + demo key") without needing an
  /// actual release build. [checkProductionLicenseGuard] is the version of
  /// this every real caller should use.
  @visibleForTesting
  static ProductionLicenseGuardResult evaluateProductionLicenseGuard({
    required bool isDebug,
    required String licenseKeyValue,
    required String environment,
  }) {
    if (isDebug) return ProductionLicenseGuardResult.debugExempt;
    if (licenseKeyValue != _demoLicenseKey) return ProductionLicenseGuardResult.ok;
    return environment.toLowerCase() == 'staging'
        ? ProductionLicenseGuardResult.demoKeyInStaging
        : ProductionLicenseGuardResult.demoKeyInRelease;
  }

  /// Throws when this is a non-debug, non-staging build still carrying the
  /// compiled-in demo license key. Call as the first line of `main()`,
  /// before [configure] or `runApp()` — see `docs/PRODUCTION_LICENSE_GUARD.md`.
  ///
  /// The thrown message never includes the license key value itself (the
  /// value is a fixed, already-public demo constant, but this method does
  /// not treat that as license to print any license key, including a real
  /// one a future caller might mistakenly compare here).
  static void assertProductionLicenseConfigured() =>
      throwIfProductionLicenseGuardFailed(checkProductionLicenseGuard());

  /// Split out from [assertProductionLicenseConfigured] so a test can drive
  /// the throw path directly from a [ProductionLicenseGuardResult] value,
  /// without needing a real release build to produce one.
  @visibleForTesting
  static void throwIfProductionLicenseGuardFailed(
    ProductionLicenseGuardResult result,
  ) {
    if (result == ProductionLicenseGuardResult.demoKeyInRelease) {
      throw StateError(
        'RASP SDK: this is a release build still using the compiled-in demo '
        'license key. Build with --dart-define=RASP_LICENSE_KEY=<your real '
        'license key>, or pass --dart-define=RASP_BUILD_ENVIRONMENT=staging '
        'if this is intentionally a staging build.',
      );
    }
  }

  // ── Production signing guard (Release-Signing Hardening milestone) ─────
  //
  // Sibling to the licence guard above, not merged into it — see
  // release_signing.dart's library doc for why. Async, because it reads a
  // native platform channel (MainActivity.signingIdentity()); the licence
  // guard above stays synchronous because it needs nothing but compile-time
  // constants. Both are called from main(), one after the other — see
  // docs/PRODUCTION_BUILD_SECURITY.md.

  /// Reads this install's actual signing identity from the platform. Never
  /// throws — every failure resolves to [ReleaseSigningInfo.unavailable],
  /// which [evaluateProductionSigningGuard] treats as unverifiable, never as
  /// safe.
  static Future<ReleaseSigningInfo> readReleaseSigningInfo() async {
    final raw = await RaspNativeChannel.mapCall('getSigningIdentity');
    return ReleaseSigningInfo.fromMap(raw);
  }

  /// Non-throwing check — mirrors [checkProductionLicenseGuard]'s shape,
  /// async because [readReleaseSigningInfo] is.
  static Future<ProductionSigningGuardResult>
      checkProductionSigningGuard() async {
    final signing = await readReleaseSigningInfo();
    return evaluateProductionSigningGuard(isDebug: kDebugMode, signing: signing);
  }

  /// Throws when this is a non-debug, non-staging build whose installed
  /// certificate is the Android debug certificate, or whose build never
  /// configured real release signing at all. Call as the second line of
  /// `main()`, right after [assertProductionLicenseConfigured] — see
  /// `docs/PRODUCTION_BUILD_SECURITY.md`.
  static Future<void> assertProductionSigningConfigured() async =>
      throwIfProductionSigningGuardFailed(await checkProductionSigningGuard());

  /// Split out so a test can drive the throw path directly from a
  /// [ProductionSigningGuardResult] value, without a real release build.
  @visibleForTesting
  static void throwIfProductionSigningGuardFailed(
    ProductionSigningGuardResult result,
  ) {
    switch (result) {
      case ProductionSigningGuardResult.debugCertificateInProduction:
        throw StateError(
          'RASP SDK: this is a production build signed with the Android '
          'DEBUG certificate. Configure android/key.properties with a real '
          'release keystore before shipping — see '
          'docs/RELEASE_SIGNING_MODES.md.',
        );
      case ProductionSigningGuardResult.signingNotConfiguredInProduction:
        throw StateError(
          'RASP SDK: this is a production build with no release signing '
          'configured (android/key.properties is missing or incomplete). '
          'Build with -PraspSigningMode=production and a real keystore, or '
          'pass --dart-define=RASP_BUILD_ENVIRONMENT=staging if this is '
          'intentionally a staging build.',
        );
      case ProductionSigningGuardResult.signingUnverifiableInProduction:
        throw StateError(
          'RASP SDK: this is a production build whose installed signing '
          'certificate could not be verified. Refusing to assume it is '
          'safe — see docs/RELEASE_SIGNING_MODES.md.',
        );
      case ProductionSigningGuardResult.ok:
      case ProductionSigningGuardResult.debugExempt:
      case ProductionSigningGuardResult.localExempt:
      case ProductionSigningGuardResult.stagingExempt:
      case ProductionSigningGuardResult.platformUnavailable:
        return;
    }
  }

  /// The combined production-build-security check (Phase 8): runs the
  /// licence guard and the signing guard together, so a build that is
  /// genuinely, verifiably production-signed (`RASP_SIGNING_MODE=production`
  /// AND a real, non-debug certificate confirmed) is also held to the
  /// licence guard's standard — closing the gap where the licence guard's
  /// own default (`RASP_BUILD_ENVIRONMENT` defaulting to `production`) was
  /// too strict to safely wire into every build unconditionally, and so had
  /// never been called from `main()` at all.
  ///
  /// Call once, from `main()`, after `WidgetsFlutterBinding.ensureInitialized()`
  /// and before `runApp()` — see `docs/PRODUCTION_BUILD_SECURITY.md`.
  ///
  /// A plain `flutter build apk --release` (no flags) is completely
  /// unaffected: [checkProductionSigningGuard] resolves
  /// [ProductionSigningGuardResult.localExempt] for it, and this method
  /// never reaches the licence check in that case.
  static Future<void> assertProductionBuildSecurity() async {
    final signingResult = await checkProductionSigningGuard();
    throwIfProductionSigningGuardFailed(signingResult);

    // The licence guard only runs once the build has PROVEN itself a real,
    // verifiably-signed production build — never merely because
    // RASP_BUILD_ENVIRONMENT defaulted to the string "production", which a
    // build could reach by doing nothing at all.
    if (signingResult == ProductionSigningGuardResult.ok) {
      throwIfProductionLicenseGuardFailed(checkProductionLicenseGuard());
    }
  }
}

/// Outcome of [SdkConfig.checkProductionLicenseGuard].
enum ProductionLicenseGuardResult {
  /// A real license key is configured, or this is a debug/staging build
  /// where the demo default is expected.
  ok,

  /// `kDebugMode` — the guard never applies to a debug build.
  debugExempt,

  /// Demo key, but `RASP_BUILD_ENVIRONMENT=staging` explicitly allows it.
  demoKeyInStaging,

  /// Demo key in what this build declares (or defaults to) as `production`
  /// — the state [SdkConfig.assertProductionLicenseConfigured] throws on.
  demoKeyInRelease,
}
