import 'package:flutter/foundation.dart';

import 'trust_anchor.dart';
import 'trust_evidence.dart';

/// Which build lane produced this artifact.
///
/// Flutter models compile mode (`kDebugMode` / `kProfileMode` /
/// `kReleaseMode`) but has no notion of a *deployment* lane — a staging build
/// and a production build are both `kReleaseMode`. The distinction is supplied
/// explicitly at build time, which is why it is a separate concept here.
enum ReleaseEnvironment {
  debug,
  staging,
  production,

  /// Declared value was absent or unrecognised. Never silently treated as
  /// production.
  unknown,
}

/// The build lane this artifact declares, resolved the same way
/// `TrustAnchorCollector.declaredEnvironment` always has: an explicit
/// `RASP_BUILD_ENVIRONMENT` wins; absent that, a debug compile reports
/// `debug` and a release compile with no declared lane reports `unknown`
/// rather than silently claiming production.
///
/// A free function (not a method on any collector) so both
/// `TrustAnchorCollector` and `BuildIdentityCollector` share one
/// resolution rule without importing each other.
ReleaseEnvironment declaredReleaseEnvironment() {
  const declared = String.fromEnvironment('RASP_BUILD_ENVIRONMENT');
  if (declared.isNotEmpty) return releaseEnvironmentFrom(declared);
  return kDebugMode ? ReleaseEnvironment.debug : ReleaseEnvironment.unknown;
}

/// Parses the `RASP_BUILD_ENVIRONMENT` value a build declares.
ReleaseEnvironment releaseEnvironmentFrom(String? declared) {
  switch (declared?.trim().toLowerCase()) {
    case 'debug':
      return ReleaseEnvironment.debug;
    case 'staging':
      return ReleaseEnvironment.staging;
    case 'production':
    case 'prod':
      return ReleaseEnvironment.production;
    default:
      return ReleaseEnvironment.unknown;
  }
}

/// What the customer's deployment requires of the build lane.
enum ReleaseEnvironmentPolicy {
  /// No requirement. The default, so existing integrations are unaffected.
  any,

  /// A production deployment: a debug build here is a finding.
  requireProduction,
}

/// Outcome of judging the build lane.
class ReleaseEnvironmentVerdict {
  final TrustAnchorState state;
  final List<TrustEvidence> evidence;

  const ReleaseEnvironmentVerdict({
    required this.state,
    this.evidence = const [],
  });
}

/// Judges the build lane against the customer's policy.
///
/// **This anchor detects misconfiguration, not attackers.** The declared lane
/// is a compile-time constant, so a repackaged build declares whatever its
/// repackager compiled. It is rooted in [TrustRoot.local] and weighted
/// accordingly — see `docs/TRUST_ANCHOR_MODEL.md` §1.7.
class ReleaseEnvironmentEvaluator {
  const ReleaseEnvironmentEvaluator();

  ReleaseEnvironmentVerdict evaluate({
    required ReleaseEnvironment environment,
    required ReleaseEnvironmentPolicy policy,
    /// Whether the compiler itself says this is a debug build. Cross-checked
    /// against [environment] so a build that *declares* production while
    /// compiled in debug mode is caught — the "DEBUG == RELEASE" assumption
    /// the audit flagged.
    required bool compiledInDebugMode,
  }) {
    if (policy == ReleaseEnvironmentPolicy.any) {
      return const ReleaseEnvironmentVerdict(state: TrustAnchorState.valid);
    }

    // The compile mode outranks the declared lane: a declaration is a string
    // the build chose, `kDebugMode` is what the toolchain actually did.
    if (compiledInDebugMode) {
      return const ReleaseEnvironmentVerdict(
        state: TrustAnchorState.mismatch,
        evidence: [
          TrustEvidence(
            TrustEvidenceCode.debugBuildInProductionPolicy,
            detail: 'compiled in debug mode under a production policy',
          ),
        ],
      );
    }

    switch (environment) {
      case ReleaseEnvironment.production:
        return const ReleaseEnvironmentVerdict(state: TrustAnchorState.valid);
      case ReleaseEnvironment.debug:
        return const ReleaseEnvironmentVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [
            TrustEvidence(TrustEvidenceCode.debugBuildInProductionPolicy),
          ],
        );
      case ReleaseEnvironment.staging:
        return const ReleaseEnvironmentVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [
            TrustEvidence(TrustEvidenceCode.stagingBuildInProductionPolicy),
          ],
        );
      case ReleaseEnvironment.unknown:
        // An undeclared lane under a production policy is unproven, not
        // proven-bad — and specifically not silently treated as production.
        return const ReleaseEnvironmentVerdict(
          state: TrustAnchorState.unknown,
          evidence: [
            TrustEvidence(TrustEvidenceCode.releaseEnvironmentUnknown),
          ],
        );
    }
  }
}
