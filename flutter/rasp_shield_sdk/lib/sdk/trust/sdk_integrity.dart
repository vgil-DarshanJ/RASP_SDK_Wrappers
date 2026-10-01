import 'package:flutter/foundation.dart';

import '../core/core.dart';
import '../protection/protection.dart';
import '../risk/risk.dart';
import 'build_identity.dart';
import 'obfuscation_state.dart';
import 'trust_anchor.dart';
import 'trust_assessment.dart';
import 'trust_engine.dart';
import 'trust_evidence.dart';
import 'trust_inputs.dart';

/// SDK Self-Integrity — behavioral canary manifest.
///
/// ## Why behavioral, not a file hash
///
/// A file-level hash of, say, `trust_engine.dart` — computed at build time
/// and checked at runtime — is circular: the only code that can read and
/// compare it is code compiled into the very artifact an attacker who
/// modified the logic can also modify. See
/// `docs/SDK_SELF_INTEGRITY_AUDIT.md` §17 for the full reasoning.
///
/// Instead, each canary runs one of this SDK's own **pure**, already-tested
/// decision functions (`TrustEngine`, `CorrelationEngine`, `ProtectionEngine`)
/// against a **fixed, hardcoded input** and compares the real output against
/// an **expected output the backend delivers inside the signed remote
/// configuration** — the exact same Ed25519-signed envelope
/// (`SignedConfigEnvelope`/`SignedConfigVerifier` ↔ `config_signing.py`)
/// every other piece of security configuration already rides. No new crypto
/// system, no new delivery channel, no secret in the APK: the fixed inputs
/// and the comparison logic are not secrets — only the fact that the
/// *expected outputs* come from a source an in-process attacker cannot
/// forge (the backend's private signing key) is what makes this
/// meaningfully harder to defeat than editing a local constant. See
/// `docs/SDK_SELF_INTEGRITY.md` §2 for the full design record.
///
/// A patched build that, say, made `TrustEngine` always report `trusted`
/// would compute a *different* actual value for [_trustEngineIdentity]'s
/// fixed input than the signed manifest declares — and that disagreement is
/// exactly what this anchor reports. An attacker can still defeat this by
/// *also* patching the canary comparison itself — this is a cost-raising
/// control, not a guarantee, matching this milestone's explicit "increase
/// attack cost, not promise unhackable" framing.
class SdkIntegrityManifest {
  /// Version of the manifest *shape*, not the SDK. Lets a future SDK version
  /// add new canary kinds without breaking an older SDK build reading an
  /// older manifest — an unrecognized canary id is simply skipped (see
  /// [SdkIntegrityEvaluator.evaluate]), not treated as a failure.
  final int manifestVersion;

  /// Canary id → expected value, exactly as delivered (already
  /// authenticated by the caller before this is constructed — see
  /// [SdkIntegrityManifest.fromConfig]'s doc comment).
  final Map<String, String> canaries;

  /// Release Obfuscation + Self-Integrity Verification milestone — what
  /// the backend expects this device's build to look like. Rides the
  /// SAME signed manifest section as [canaries] (same authenticity gate,
  /// same delivery channel) rather than a second signed document — see
  /// `docs/BUILD_SELF_INTEGRITY.md` §2. `null` when the operator has not
  /// published one, the honest "nothing to check" state, never treated as
  /// a pass.
  final ExpectedBuildIdentity? expectedBuildIdentity;

  const SdkIntegrityManifest({
    required this.manifestVersion,
    this.canaries = const {},
    this.expectedBuildIdentity,
  });

  /// Parses the `sdk_integrity` section out of a remote-config bundle.
  ///
  /// Returns `null` when the section is absent — the honest "operator has
  /// not published a manifest yet" state, not a failure. **Callers must only
  /// pass a [config] whose authenticity has already been established** the
  /// same way `TrustAnchorCollector` already gates `certificateStore`
  /// (`certificateGateOpen`) — this parser does not itself verify a
  /// signature; it trusts whatever map it is given, exactly like
  /// `SecurityConfigEnvelope.fromConfig` does.
  static SdkIntegrityManifest? fromConfig(Map<String, dynamic> config) {
    final section = config['sdk_integrity'];
    if (section is! Map) return null;
    final rawVersion = section['manifest_version'];
    final version = rawVersion is num ? rawVersion.toInt() : 0;
    if (version <= 0) return null;

    final rawCanaries = section['canaries'];
    final canaries = <String, String>{};
    if (rawCanaries is Map) {
      for (final entry in rawCanaries.entries) {
        final key = entry.key;
        final value = entry.value;
        if (key is String && value is String && key.isNotEmpty) {
          canaries[key] = value;
        }
      }
    }
    return SdkIntegrityManifest(
      manifestVersion: version,
      canaries: canaries,
      expectedBuildIdentity:
          ExpectedBuildIdentity.fromMap(section['expected_build_identity']),
    );
  }
}

/// Outcome of running the canary suite against a manifest.
class SdkIntegrityVerdict {
  final TrustAnchorState state;
  final List<TrustEvidence> evidence;

  const SdkIntegrityVerdict({required this.state, this.evidence = const []});
}

/// Runs every canary this SDK build knows and judges the result against a
/// [SdkIntegrityManifest].
///
/// Pure and deterministic: every canary input is a compile-time constant, so
/// the same manifest always produces the same verdict on the same SDK build.
class SdkIntegrityEvaluator {
  const SdkIntegrityEvaluator();

  /// One canary per critical pure component this milestone protects.
  /// Adding a canary here requires the backend's delivered manifest to also
  /// carry its expected value (see `docs/SDK_SELF_INTEGRITY.md` §4) — an
  /// SDK-known canary the manifest does not mention is simply not checked
  /// (never treated as a failure; an older manifest predating a new canary
  /// must not brick every device on the new SDK build).
  static final Map<String, String Function()> _canaries = {
    'trust_engine_identity_v1': _trustEngineIdentityCanary,
    'correlation_engine_chain_v1': _correlationEngineChainCanary,
    'protection_engine_ladder_v1': _protectionEngineLadderCanary,
  };

  /// [TrustAnchor.applicationId] and [TrustAnchor.signingCertificate] are
  /// identity anchors — a mismatch on either forces
  /// [TrustLevel.compromised] unconditionally (see
  /// `TrustEngine._levelFor`'s precedence rule 1), regardless of every other
  /// field. Deliberately using a real identity mismatch — not a synthetic
  /// "always fails" input — so this canary genuinely exercises the same
  /// precedence logic a real repackaging attempt would trigger.
  static String _trustEngineIdentityCanary() {
    final assessment = const TrustEngine().evaluate(
      const TrustInputs(
        observedApplicationId: 'com.rasp.integrity.canary',
        expectedApplicationId: 'com.rasp.integrity.canary.expected',
      ),
      now: DateTime.utc(2026, 1, 1),
    );
    return assessment.level.wireName;
  }

  /// A fully-corroborated root+Frida chain — exactly
  /// `CorrelationEngine.defaultRules`'s `CRITICAL_RUNTIME_COMPROMISE` rule's
  /// required signals, nothing else, so exactly one chain fires. Exercises
  /// `CorrelationRule.matches` end to end (confidence floor, `threatDetected`
  /// gating, rule matching) — not just a scoring number.
  static String _correlationEngineChainCanary() {
    DetectionResult signal(String id) => DetectionResult(
          detectorId: id,
          detectorType: DetectorType.custom,
          category: ThreatCategory.deviceIntegrity,
          status: DetectionStatus.detected,
          severity: DetectionSeverity.critical,
          confidence: DetectionConfidence.veryHigh,
          title: id,
          description: id,
          observedAt: DateTime.utc(2026, 1, 1),
        );
    const engine = CorrelationEngine();
    final chains = engine.correlate([signal('root_jailbreak'), signal('frida')]);
    final ids = chains.map((c) => c.id).toList()..sort();
    return ids.join(',');
  }

  /// The same fixed root+Frida detections, run through the LIVE
  /// (`evaluate`, not `evaluateWithRisk`) `ProtectionEngine` path under a
  /// fixed strict policy. This is the canary most directly tied to what the
  /// live app actually does with a detection — see
  /// `docs/SDK_SELF_INTEGRITY_AUDIT.md` §6 for why that distinction matters.
  static String _protectionEngineLadderCanary() {
    DetectionResult signal(String id) => DetectionResult(
          detectorId: id,
          detectorType: DetectorType.custom,
          category: ThreatCategory.deviceIntegrity,
          status: DetectionStatus.detected,
          severity: DetectionSeverity.critical,
          confidence: DetectionConfidence.veryHigh,
          title: id,
          description: id,
          observedAt: DateTime.utc(2026, 1, 1),
        );
    const engine = ProtectionEngine();
    final result = engine.evaluate(
      [signal('root_jailbreak'), signal('frida')],
      context: const ProtectionContext(
        sdkVersion: '2.0.0',
        license: ProtectionLicenseInfo(state: 'active', entitlements: {}),
      ),
      policy: ProtectionPolicy.strict,
    );
    return result.recommendedAction.name.toUpperCase();
  }

  /// The real, current output of every canary this SDK build knows how to
  /// run — what a genuine, correct build's manifest must declare as its
  /// expected values. Used by this SDK's own test suite to build the
  /// "valid" fixture (see `test/sdk_integrity_test.dart`) and by whoever
  /// maintains the backend's `sdk_integrity` manifest template to keep it in
  /// sync with this SDK version — the same "computed once, kept in sync by a
  /// test" discipline `config_signing.py`'s canonicalization mirror already
  /// uses for signed configuration. Never used by production code.
  @visibleForTesting
  static Map<String, String> computeAllForTesting() =>
      {for (final entry in _canaries.entries) entry.key: entry.value()};

  /// Evaluates every canary the [manifest] declares that this SDK build also
  /// knows how to run.
  ///
  /// - `manifest == null` → [TrustAnchorState.unavailable]: no manifest has
  ///   been published (or the config it would have come from was not
  ///   authenticated) — never treated as a pass.
  /// - `manifest.canaries` empty → [TrustAnchorState.unknown]: a manifest
  ///   exists but declares nothing to check.
  /// - Every declared-and-known canary matches → [TrustAnchorState.valid].
  /// - Any declared-and-known canary disagrees → [TrustAnchorState.mismatch].
  /// - Never throws: an individual canary that throws is caught and treated
  ///   as a mismatch for that canary specifically, not a crash.
  ///
  /// [observedBuildIdentity] is the Release Obfuscation + Self-Integrity
  /// Verification milestone's addition — this SDK's own current build
  /// identity, checked against [SdkIntegrityManifest.expectedBuildIdentity]
  /// when both are present. Extends this SAME evaluator/anchor rather than
  /// standing up a second integrity engine — see that field's doc comment.
  SdkIntegrityVerdict evaluate(
    SdkIntegrityManifest? manifest, {
    BuildSecurityIdentity? observedBuildIdentity,
  }) {
    if (manifest == null) {
      return const SdkIntegrityVerdict(
        state: TrustAnchorState.unavailable,
        evidence: [TrustEvidence(TrustEvidenceCode.sdkIntegrityUnavailable)],
      );
    }

    final canaryVerdict = _evaluateCanaries(manifest);
    final buildVerdict = _evaluateBuildIdentity(manifest, observedBuildIdentity);

    if (canaryVerdict == null && buildVerdict == null) {
      // Nothing to check on either side — the manifest exists but declares
      // no canaries and either no expected build identity or nothing
      // observed to compare it against.
      return const SdkIntegrityVerdict(
        state: TrustAnchorState.unknown,
        evidence: [TrustEvidence(TrustEvidenceCode.sdkIntegrityNoCanaries)],
      );
    }
    if (canaryVerdict == null) return buildVerdict!;
    if (buildVerdict == null) return canaryVerdict;

    // Both ran: worse of the two wins. `mismatch` outranks `unknown`, which
    // outranks `valid` — the same "never let a pass paper over a failure"
    // rule every other combined verdict in this codebase follows.
    const severity = {
      TrustAnchorState.mismatch: 3,
      TrustAnchorState.unknown: 2,
      TrustAnchorState.valid: 1,
    };
    final worse = (severity[buildVerdict.state] ?? 0) >
            (severity[canaryVerdict.state] ?? 0)
        ? buildVerdict
        : canaryVerdict;
    return SdkIntegrityVerdict(
      state: worse.state,
      evidence: [...canaryVerdict.evidence, ...buildVerdict.evidence],
    );
  }

  /// `null` when the manifest declares no canaries at all — distinct from
  /// [TrustAnchorState.unknown], so the caller can tell "nothing to check
  /// here" from "checked and inconclusive" when combining with the build-
  /// identity half below.
  SdkIntegrityVerdict? _evaluateCanaries(SdkIntegrityManifest manifest) {
    if (manifest.canaries.isEmpty) return null;

    var checked = 0;
    final failed = <String>[];
    for (final entry in manifest.canaries.entries) {
      final canary = _canaries[entry.key];
      if (canary == null) continue; // forward-compat: unknown to this build
      checked++;
      String actual;
      try {
        actual = canary();
      } catch (_) {
        failed.add(entry.key);
        continue;
      }
      if (actual != entry.value) failed.add(entry.key);
    }

    if (checked == 0) {
      // The manifest exists but names only canaries this build predates or
      // has never heard of — nothing was actually verified.
      return const SdkIntegrityVerdict(
        state: TrustAnchorState.unknown,
        evidence: [TrustEvidence(TrustEvidenceCode.sdkIntegrityNoCanaries)],
      );
    }

    if (failed.isNotEmpty) {
      return SdkIntegrityVerdict(
        state: TrustAnchorState.mismatch,
        evidence: [
          TrustEvidence(
            TrustEvidenceCode.sdkIntegrityMismatch,
            detail: '${failed.length} of $checked canaries disagreed',
          ),
        ],
      );
    }

    return const SdkIntegrityVerdict(state: TrustAnchorState.valid);
  }

  /// `null` when there is nothing to check (no expected identity published,
  /// or no observed identity supplied) — see [_evaluateCanaries]'s doc
  /// comment for why this is distinct from `unknown`.
  ///
  /// This is the comparison Phase 4 of the milestone requires be rooted in
  /// an external trusted source: [ExpectedBuildIdentity] only ever reaches
  /// here after [SdkIntegrityManifest.fromConfig] parsed it out of an
  /// already-authenticated, backend-signed configuration
  /// (`TrustAnchorCollector`'s `certificateGateOpen` gate) — never from
  /// anything the running process asserted about itself.
  SdkIntegrityVerdict? _evaluateBuildIdentity(
    SdkIntegrityManifest manifest,
    BuildSecurityIdentity? observed,
  ) {
    final expected = manifest.expectedBuildIdentity;
    if (expected == null || observed == null) return null;

    final mismatches = <TrustEvidence>[];

    if (expected.expectedApplicationId != null &&
        observed.applicationId != null &&
        expected.expectedApplicationId != observed.applicationId) {
      mismatches.add(const TrustEvidence(TrustEvidenceCode.buildIdentityMismatch));
    }

    if (expected.expectedReleaseEnvironment != null) {
      final expectedName = expected.expectedReleaseEnvironment;
      final observedName = observed.declaredEnvironment.name;
      if (expectedName != observedName) {
        mismatches.add(const TrustEvidence(TrustEvidenceCode.buildIdentityMismatch));
      }
    }

    if (expected.requireObfuscation &&
        observed.obfuscationState == ObfuscationState.notObfuscated) {
      mismatches.add(const TrustEvidence(TrustEvidenceCode.releaseObfuscationMissing));
    }

    if (observed.obfuscationState == ObfuscationState.error) {
      mismatches.add(const TrustEvidence(TrustEvidenceCode.buildSecurityError));
    }

    if (mismatches.isNotEmpty) {
      return SdkIntegrityVerdict(state: TrustAnchorState.mismatch, evidence: mismatches);
    }

    if (expected.requireObfuscation &&
        observed.obfuscationState == ObfuscationState.unknown) {
      // Required, but this build's own check could not confirm it either
      // way — reported as unknown, never as a silent pass.
      return const SdkIntegrityVerdict(
        state: TrustAnchorState.unknown,
        evidence: [TrustEvidence(TrustEvidenceCode.buildSecurityUnknown)],
      );
    }

    // Deliberately empty evidence on the clean path — matching every other
    // anchor's convention (`TrustAssessment.toDetectionResults()` skips a
    // satisfied anchor with no evidence, so a confirmed-clean build does
    // not manufacture an extra per-scan DetectionResult). `buildIdentityValid`
    // stays defined for a caller that wants to log a positive confirmation
    // explicitly (e.g. a one-time startup log line — see
    // `docs/BUILD_SELF_INTEGRITY.md` §5) rather than being emitted here.
    return const SdkIntegrityVerdict(state: TrustAnchorState.valid);
  }
}
