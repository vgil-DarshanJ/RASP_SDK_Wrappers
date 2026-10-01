import '../device/device_binding_state.dart';
import '../device/device_key.dart';
import 'attestation/attestation_result.dart';
import 'build_identity.dart';
import 'certificate_trust.dart';
import 'configuration_trust.dart';
import 'release_environment.dart';
import '../protection/pipeline_mode.dart';
import 'sdk_integrity.dart';
import 'sdk_version_trust.dart';
import 'signed_config_verifier.dart';

/// Everything the trust engine needs, as plain data.
///
/// Separating *observation* from *judgement* is what makes the whole engine
/// unit-testable with no device: `TrustAnchorCollector` does the platform
/// reads and fills this in, `TrustEngine` decides. Every field is nullable
/// because "we could not read it" is a first-class outcome — the engine turns
/// a null into `unavailable`/`unknown`, never into a pass.
class TrustInputs {
  // ── Application identity ────────────────────────────────────────────────

  /// The package/bundle id the platform reports right now.
  final String? observedApplicationId;

  /// The id this install is expected to be, from the licence binding or the
  /// value captured when the seat was established.
  final String? expectedApplicationId;

  /// The application id captured at activation, for the runtime-identity
  /// anchor. Distinct from [expectedApplicationId]: that one is what the
  /// *server* says, this one is what *this install* previously observed.
  final String? activationApplicationId;

  /// The certificate fingerprint captured at activation, same reasoning.
  final String? activationCertificate;

  // ── Signing identity ────────────────────────────────────────────────────

  final String? observedCertificate;
  final CertificateTrustStore certificateStore;

  // ── Licence binding ─────────────────────────────────────────────────────

  /// Whether the licence currently grants anything. A licence that is not
  /// active cannot bind anything.
  final bool? licenseActive;

  /// The application id the licence was issued against.
  final String? licenseApplicationId;

  /// The certificate fingerprint the licence was issued against.
  final String? licenseCertificate;

  /// The device id the seat was issued to.
  final String? licenseDeviceId;

  // ── Device binding ──────────────────────────────────────────────────────

  final String? observedDeviceId;

  /// `true` when the platform Keystore binding still resolves.
  ///
  /// Note the polarity is normalized here: the native
  /// `verifyDeviceBinding()` returns `true` when binding *failed*, a quirk
  /// preserved in the shipped detector. The collector inverts it once, at the
  /// boundary, so nothing downstream has to remember.
  final bool? keystoreBindingIntact;

  /// The cryptographic device-key verdict, as decided by
  /// `LicenseBindingValidator` during licence evaluation.
  ///
  /// **Read, not re-derived.** The trust engine does not repeat the
  /// comparison licensing already performed — it reports it. Two independent
  /// derivations of "is this the bound device?" could disagree, and a
  /// console showing one answer while the licence gate acts on the other is
  /// worse than either answer alone.
  ///
  /// `null` means licensing has not evaluated a token yet in this process —
  /// the state during the very first scan and in every test written before
  /// this milestone, which is why the legacy signals below still stand on
  /// their own.
  final DeviceBindingVerdict? deviceKeyVerdict;

  /// How this device's binding key is protected, when there is one.
  ///
  /// Reported so a verdict's authority can be capped honestly: a
  /// software-backed key is a real key managed by the OS, but it is not a
  /// TEE and this SDK never says it is. See `DeviceKeyBacking`.
  final DeviceKeyBacking deviceKeyBacking;

  /// **Superseded by [attestationResult].** Kept only so the constructor's
  /// existing named parameter never breaks source compatibility for a caller
  /// that already passes it — nothing in this SDK ever read it (confirmed:
  /// referenced nowhere outside this file before the Attestation Trust Layer
  /// milestone), so nothing needed migrating.
  final bool? attestationPassed;

  /// The platform/hardware attestation verdict (Google Play Integrity /
  /// Apple App Attest), already run through `AttestationReplayGuard`. `null`
  /// means no attestation was attempted or possible — the honest default on
  /// every build today, since no native implementation is registered (see
  /// `docs/ATTESTATION_ARCHITECTURE.md`).
  final AttestationResult? attestationResult;

  // ── SDK version ─────────────────────────────────────────────────────────

  final String? reportedSdkVersion;
  final SdkVersionPolicy sdkVersionPolicy;

  // ── Security configuration ──────────────────────────────────────────────

  final SecurityConfigEnvelope? configEnvelope;

  /// Version the SDK already held, for downgrade detection.
  final int? heldConfigVersion;

  /// Document id the SDK already held. Replay — the same version number
  /// carrying a *different* document — cannot be detected without it, and
  /// version monotonicity alone cannot see it.
  final String? heldConfigId;

  /// Fingerprint recomputed from the values actually in force.
  final String? liveConfigFingerprint;

  /// Result of cryptographic signature verification, computed by the
  /// collector before `TrustEngine.evaluate` ever runs.
  ///
  /// `null` means verification did not run — the pre-signing behaviour,
  /// preserved so every caller that predates signed configuration is
  /// unaffected. `TrustEngine` stays synchronous and pure; the necessarily
  /// async Ed25519 check lives entirely in `TrustAnchorCollector`.
  final SignedConfigVerification? configVerification;

  // ── Release environment ─────────────────────────────────────────────────

  final ReleaseEnvironment releaseEnvironment;
  final ReleaseEnvironmentPolicy releaseEnvironmentPolicy;
  final bool compiledInDebugMode;

  // ── SDK self-integrity ──────────────────────────────────────────────────

  /// The signed behavioral-canary manifest, parsed from the same
  /// authenticated configuration source [configEnvelope]/[configVerification]
  /// already gate — `null` means no manifest has been published, or the
  /// configuration it would have come from was not authenticated. See
  /// `sdk_integrity.dart`.
  final SdkIntegrityManifest? sdkIntegrityManifest;

  /// Release Obfuscation + Self-Integrity Verification milestone — this
  /// SDK's own current build identity (application id, signing/obfuscation
  /// state, declared lane). `null` before it has ever been collected.
  /// Judged against [sdkIntegrityManifest]'s `expectedBuildIdentity` inside
  /// the SAME `sdkIntegrity` anchor — see `sdk_integrity.dart`.
  final BuildSecurityIdentity? buildIdentity;

  /// The risk-pipeline rollout mode resolved from the same authenticated
  /// configuration source as [sdkIntegrityManifest] above.
  ///
  /// **Not a trust anchor and not judged by [TrustEngine.evaluate] at
  /// all** — [TrustAssessment] never reads this field. It rides on
  /// [TrustInputs] purely so `SecurityCenterController` can obtain it from
  /// the one authenticated-configuration read `TrustAnchorCollector.collect()`
  /// already performs each scan, rather than duplicating the (async,
  /// Ed25519-verifying) authenticity check a second time just to resolve a
  /// rollout switch. Defaults to [PipelineRolloutConfig.legacy] — the safe,
  /// pre-milestone behavior — for every caller that does not supply one
  /// (every test written before this milestone, and any future caller of
  /// [TrustEngine.evaluate] directly). See
  /// `docs/RISK_PIPELINE_ROLLOUT.md`.
  final PipelineRolloutConfig pipelineRollout;

  const TrustInputs({
    this.observedApplicationId,
    this.expectedApplicationId,
    this.activationApplicationId,
    this.activationCertificate,
    this.observedCertificate,
    this.certificateStore = CertificateTrustStore.empty,
    this.licenseActive,
    this.licenseApplicationId,
    this.licenseCertificate,
    this.licenseDeviceId,
    this.observedDeviceId,
    this.keystoreBindingIntact,
    this.deviceKeyVerdict,
    this.deviceKeyBacking = DeviceKeyBacking.unavailable,
    this.attestationPassed,
    this.attestationResult,
    this.reportedSdkVersion,
    this.sdkVersionPolicy = SdkVersionPolicy.permissive,
    this.configEnvelope,
    this.heldConfigVersion,
    this.heldConfigId,
    this.liveConfigFingerprint,
    this.configVerification,
    this.releaseEnvironment = ReleaseEnvironment.unknown,
    this.releaseEnvironmentPolicy = ReleaseEnvironmentPolicy.any,
    this.compiledInDebugMode = false,
    this.sdkIntegrityManifest,
    this.buildIdentity,
    this.pipelineRollout = PipelineRolloutConfig.legacy,
  });
}
