import 'obfuscation_state.dart';
import 'release_environment.dart';

/// Release Obfuscation + Self-Integrity Verification milestone.
///
/// [BuildSecurityIdentity] is a deterministic, **non-secret** snapshot of
/// what this running build actually is — never a private key, signing
/// password, licence key, or token. See `docs/BUILD_SECURITY_IDENTITY.md`.
class BuildSecurityIdentity {
  final String? applicationId;
  final String sdkVersion;
  final String buildVersion;

  /// `RASP_SIGNING_MODE` — `local` / `staging` / `production` on Android;
  /// `null` where no native signal exists (see `release_signing.dart`).
  final String? buildChannel;

  /// What the toolchain actually did — `kDebugMode`. Outranks every
  /// self-declared field below it, the same precedence
  /// `ReleaseEnvironmentEvaluator` already established.
  final bool compiledInDebugMode;

  /// `RASP_BUILD_ENVIRONMENT` — a compile-time self-declaration, cross-
  /// checked against [compiledInDebugMode] by [BuildIdentityClassifier].
  final ReleaseEnvironment declaredEnvironment;

  /// Mirrors `BuildConfig.RASP_RELEASE_SIGNING_CONFIGURED`. `null` when
  /// unavailable (wrong platform, channel not registered).
  final bool? signingConfigured;

  /// Whether the certificate that actually signed this install is
  /// Android's well-known debug certificate. `null` when unreadable.
  final bool? isDebugCertificate;

  final ObfuscationState obfuscationState;

  const BuildSecurityIdentity({
    required this.sdkVersion,
    required this.buildVersion,
    required this.compiledInDebugMode,
    required this.declaredEnvironment,
    required this.obfuscationState,
    this.applicationId,
    this.buildChannel,
    this.signingConfigured,
    this.isDebugCertificate,
  });

  Map<String, Object?> toMap() => {
        'application_id': applicationId,
        'sdk_version': sdkVersion,
        'build_version': buildVersion,
        'build_channel': buildChannel,
        'compiled_in_debug_mode': compiledInDebugMode,
        'declared_environment': declaredEnvironment.name,
        'signing_configured': signingConfigured,
        'is_debug_certificate': isDebugCertificate,
        'obfuscation_state': obfuscationState.name,
      };
}

/// The six states a build's identity may resolve to. See
/// `docs/BUILD_SECURITY_IDENTITY.md` §2 for the full decision table.
enum BuildIdentityVerdict {
  expectedRelease,
  expectedDebug,
  expectedStaging,
  unexpectedBuild,
  unknown,
  error,
}

/// Classifies a [BuildSecurityIdentity] by cross-checking its own
/// **independent** signals against each other — compile mode (compiler-
/// controlled), signing certificate (OS-verified at install time), and
/// obfuscation marker (a real runtime artifact) each have to agree for a
/// build to read as genuinely `EXPECTED_RELEASE`. This is deliberately
/// **not** a single self-declared boolean: an attacker who wants to fake
/// `EXPECTED_RELEASE` has to simultaneously falsify all three, not flip one
/// flag. See "Never do: local value == same local value" in
/// `docs/BUILD_SECURITY_IDENTITY.md` §1 for why this shape was chosen over
/// a simpler one.
///
/// Pure and deterministic — no platform channel, no I/O. Never throws:
/// any internal failure resolves to [BuildIdentityVerdict.error].
class BuildIdentityClassifier {
  const BuildIdentityClassifier();

  BuildIdentityVerdict classify(BuildSecurityIdentity identity) {
    try {
      return _classify(identity);
    } catch (_) {
      return BuildIdentityVerdict.error;
    }
  }

  BuildIdentityVerdict _classify(BuildSecurityIdentity identity) {
    // The compiler's own answer outranks every self-declared field — the
    // same precedence rule `ReleaseEnvironmentEvaluator` already uses.
    if (identity.compiledInDebugMode) {
      return BuildIdentityVerdict.expectedDebug;
    }

    // From here on, this is a release-compiled artifact. A release build
    // that still LOOKS like debug — declares the debug lane, or is signed
    // with the debug certificate — is the "silently looks like DEBUG"
    // case the milestone brief calls out by name: it must not pass as
    // EXPECTED_RELEASE or EXPECTED_STAGING just because the compiler said
    // release.
    if (identity.declaredEnvironment == ReleaseEnvironment.debug ||
        identity.isDebugCertificate == true) {
      return BuildIdentityVerdict.unexpectedBuild;
    }

    switch (identity.declaredEnvironment) {
      case ReleaseEnvironment.staging:
        return BuildIdentityVerdict.expectedStaging;

      case ReleaseEnvironment.production:
        // A production claim needs every corroborating signal to agree —
        // any one of them being unreadable makes the verdict UNKNOWN, not
        // a pass, and any one of them actively disagreeing makes it
        // UNEXPECTED_BUILD.
        if (identity.buildChannel != null &&
            identity.buildChannel != 'production') {
          return BuildIdentityVerdict.unexpectedBuild;
        }
        if (identity.signingConfigured == false) {
          return BuildIdentityVerdict.unexpectedBuild;
        }
        if (identity.obfuscationState == ObfuscationState.notObfuscated) {
          return BuildIdentityVerdict.unexpectedBuild;
        }
        if (identity.isDebugCertificate == null ||
            identity.signingConfigured == null ||
            identity.obfuscationState == ObfuscationState.unknown ||
            identity.obfuscationState == ObfuscationState.error) {
          return BuildIdentityVerdict.unknown;
        }
        return BuildIdentityVerdict.expectedRelease;

      case ReleaseEnvironment.debug:
        // Unreachable — handled above — kept for exhaustiveness.
        return BuildIdentityVerdict.unexpectedBuild;

      case ReleaseEnvironment.unknown:
        // An undeclared lane on a release-compiled artifact is unproven,
        // never silently treated as production.
        return BuildIdentityVerdict.unknown;
    }
  }
}

/// What the backend's signed configuration says this device's build
/// SHOULD look like — the "trusted source" Phase 4 of the milestone
/// requires, so this comparison is never a build checking itself against
/// itself. Parsed only from an already-authenticated configuration, the
/// same rule `SdkIntegrityManifest.fromConfig` follows — see
/// `sdk_integrity.dart`'s doc comment and
/// `TrustAnchorCollector.collect()`'s `certificateGateOpen` gate.
class ExpectedBuildIdentity {
  final String? expectedApplicationId;
  final String? expectedReleaseEnvironment;
  final bool requireObfuscation;

  const ExpectedBuildIdentity({
    this.expectedApplicationId,
    this.expectedReleaseEnvironment,
    this.requireObfuscation = false,
  });

  static ExpectedBuildIdentity? fromMap(Object? raw) {
    if (raw is! Map) return null;
    final appId = raw['expected_application_id'];
    final env = raw['expected_release_environment'];
    final requireObf = raw['require_obfuscation'];
    return ExpectedBuildIdentity(
      expectedApplicationId: appId is String && appId.isNotEmpty ? appId : null,
      expectedReleaseEnvironment:
          env is String && env.isNotEmpty ? env.trim().toLowerCase() : null,
      requireObfuscation: requireObf == true,
    );
  }
}
