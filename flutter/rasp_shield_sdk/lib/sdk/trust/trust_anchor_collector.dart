import 'package:flutter/foundation.dart';

import '../activation_manager.dart';
import '../detectors/rasp_native_channel.dart';
import '../device/device_key.dart';
import '../device/device_key_manager.dart';
import '../device_identity.dart';
import '../license_manager.dart';
import '../remote_config_manager.dart';
import '../sdk_config.dart';
import 'attestation/attestation_orchestrator.dart';
import 'build_identity_collector.dart';
import 'certificate_trust.dart';
import 'certificate_trust_gate.dart';
import 'config_signing_keys.dart';
import '../protection/pipeline_mode.dart';
import 'configuration_trust.dart';
import 'release_environment.dart';
import 'sdk_integrity.dart';
import 'sdk_version_trust.dart';
import 'signed_config_verifier.dart';
import 'trust_baseline.dart';
import 'trust_inputs.dart';

/// Gathers the observations [TrustEngine] judges.
///
/// This is the only impure part of the trust engine: platform channels,
/// secure storage, the licence, the remote config. Keeping it separate from
/// the decision logic is what lets every rule in `TrustEngine` be tested
/// exhaustively with no device — which matters here, because no physical
/// Android device is available to this project.
///
/// Every read is individually guarded. A failure yields `null`, which the
/// engine turns into `unavailable`/`unknown` — never into a pass.
class TrustAnchorCollector {
  /// The SDK's pinned configuration-signing trust root.
  ///
  /// `null` (the default) resolves to whatever the build declared via
  /// `--dart-define` at the moment [collect] runs (see
  /// [ConfigTrustRoot.fromBuildEnvironment]) — not resolved eagerly, because
  /// that call is not a compile-time constant and this constructor is `const`.
  /// Every build produced by this repository today declares no key, so the
  /// resolved root is empty — no production signing infrastructure exists
  /// yet. Overridable so a host app, or a test, can pin its own.
  final ConfigTrustRoot? trustRoot;

  /// Caches the expensive Ed25519 step across repeated calls to [collect] —
  /// see [SignedConfigAuthenticationCache]'s doc comment for the exact,
  /// deterministic invalidation rule. Shared across every `const
  /// TrustAnchorCollector()` instance (Dart canonicalizes identical const
  /// constructor calls to one object), which is what makes it actually
  /// persist across the repeated scans `SecurityCenterController` performs.
  static final SignedConfigAuthenticationCache _authenticationCache =
      SignedConfigAuthenticationCache();

  const TrustAnchorCollector({this.trustRoot});

  /// The build lane this artifact declares.
  ///
  /// Flutter's `kReleaseMode` cannot tell staging from production, so the lane
  /// is declared explicitly at build time:
  ///
  /// ```
  /// flutter build apk --dart-define=RASP_BUILD_ENVIRONMENT=production
  /// ```
  ///
  /// Unset, it resolves from the compile mode alone — debug builds report
  /// `debug`, and a release build with no declared lane reports `unknown`
  /// rather than silently claiming production.
  static ReleaseEnvironment get declaredEnvironment =>
      declaredReleaseEnvironment();

  /// Collects everything currently observable.
  ///
  /// [policy] lets a host app state what its deployment requires of the build
  /// lane; it defaults to no requirement so existing integrations are
  /// unaffected.
  Future<TrustInputs> collect({
    ReleaseEnvironmentPolicy policy = ReleaseEnvironmentPolicy.any,
  }) async {
    final config = LicenseManager.remoteConfig;
    final observedApplicationId = await _observedApplicationId();
    final observedCertificate = await _observedCertificate();
    final baseline = await TrustBaselineStore.read();

    // The version this device actually holds — see the fromConfig doc comment
    // for why this cannot be read out of `config` itself.
    final heldConfigVersion = LicenseManager.status.value.configVersion;
    final heldConfigId = _stringOrNull(RemoteConfigManager.values, 'config_id');

    SignedConfigVerification? configVerification;
    if (config.isNotEmpty) {
      final signedEnvelope = SignedConfigEnvelope.fromConfig(
        config,
        configVersionOverride: heldConfigVersion,
      );
      final verifier = SignedConfigVerifier(
        trustRoot: trustRoot ?? ConfigTrustRoot.fromBuildEnvironment(),
      );
      // heldVersion/heldConfigId are intentionally NOT passed here.
      //
      // This evaluation runs *after* `RemoteConfigManager.syncFromLicense()`
      // has already merged the latest bundle — by the time `collect()` runs,
      // `heldConfigVersion` above already reflects the bundle being verified,
      // not some earlier document to compare it against. Passing it as both
      // the envelope's own version and the value to check it against would be
      // a no-op self-comparison that can never detect a downgrade or replay,
      // which would be worse than admitting the gap: it would look tested and
      // protected without being either.
      //
      // The real gap this exposes: `RemoteConfigManager._merge()` overwrites
      // the top-level config values on every heartbeat with **no version
      // gate at all** — only the nested `protection_policy` has real
      // monotonic gating, via `_adoptPolicy()`. Closing that needs
      // `RemoteConfigManager` to retain the previously-held version
      // separately from the one it just adopted, which is a change to
      // existing customer-facing merge behaviour and is out of scope for a
      // signing milestone. Recorded as a known limitation in
      // `docs/SIGNED_SECURITY_CONFIGURATION.md` rather than silently
      // engineered around. The pure `SignedConfigVerifier`/
      // `ConfigurationTrustEvaluator` layer beneath this fully supports
      // downgrade/replay detection today — given a genuine held value — and
      // is tested exhaustively against synthetic ones.
      configVerification = await verifier.verify(
        signedEnvelope,
        now: DateTime.now(),
        authenticationCache: _authenticationCache,
      );
    }

    // Certificate trust gating (Phase 6/7 of the Backend Signed Configuration
    // milestone): the certificate trust store may only be populated from a
    // configuration that has been PROVEN authentic — signed, fresh, and
    // in-order. An unsigned, forged, expired, replayed, or downgraded
    // configuration must not become the authoritative source of what
    // certificate this device trusts; it silently falling back to
    // NOT_CONFIGURED is the fail-safe outcome, not a crash and not a false
    // "secure." See docs/CERTIFICATE_TRUST_GATING.md for the full rationale
    // and the exact state table.
    final certificateTrustSource = certificateTrustSourceStateFor(configVerification);
    final certificateGateOpen = certificateTrustSource.maysPopulateCertificateTrust;

    // Publish the *same* gate for offline compliance, which needs to know
    // whether `offline_max_minutes` arrived in an authenticated bundle
    // before it will honour it (Phase 5 of the offline-compliance
    // milestone). Deliberately reusing this already-computed verdict rather
    // than verifying a second time: a second verification path is a second
    // thing to get wrong, and the project's standing convention is one
    // signing mechanism, one verifier. See
    // docs/OFFLINE_COMPLIANCE_MODEL.md §4.
    RemoteConfigManager.setConfigAuthenticated(certificateGateOpen);
    final certificateStore =
        certificateGateOpen ? CertificateTrustStore.fromConfig(config) : CertificateTrustStore.empty;

    // Same gate, applied to `licenseCertificate`: it is the identical
    // `signing_cert_sha256` value, reused by the licence-binding anchor's
    // cross-check. Feeding it from an unauthenticated configuration would let
    // an attacker who can forge that one field suppress a genuine
    // LICENSE_CERTIFICATE_MISMATCH by making the unsigned claim agree with
    // whatever certificate their own repackaged build carries — the same
    // "unsigned config quietly becomes authoritative" pattern Phase 6 exists
    // to close, just reached through a second consumer of the same field.
    // Passing `null` here is the safe default already handled by
    // `_licenseBindingAnchor`: that specific comparison is simply skipped,
    // not forced to any verdict.
    final licenseCertificate =
        certificateGateOpen ? _stringOrNull(config, 'signing_cert_sha256') : null;

    // Same authenticity gate as `certificateStore`/`licenseCertificate`
    // above: the SDK-integrity manifest is only meaningful when it is known
    // to have come from the operator's signed configuration, not from an
    // unsigned/forged/downgraded one an attacker could otherwise use to
    // ship a manifest declaring its own tampering "expected". An
    // unauthenticated bundle yields `null` — the honest "no manifest" state
    // `SdkIntegrityEvaluator` already treats as `unavailable`, never as a
    // pass.
    final sdkIntegrityManifest =
        certificateGateOpen ? SdkIntegrityManifest.fromConfig(config) : null;

    // Same authenticity gate again: the risk-pipeline rollout mode can only
    // ever advance past PipelineMode.legacy from an authenticated
    // configuration. An unsigned/forged/downgraded config resolving to
    // `compatibility` would be exactly the "malformed config accidentally
    // enables the new engine" bypass the Risk Pipeline Promotion milestone's
    // brief explicitly forbids — see docs/RISK_PIPELINE_ROLLOUT.md §Safety.
    final pipelineRollout = certificateGateOpen
        ? PipelineRolloutConfig.fromConfig(config)
        : PipelineRolloutConfig.legacy;

    return TrustInputs(
      observedApplicationId: observedApplicationId,
      expectedApplicationId: _stringOrNull(config, 'bundle_id') ??
          _stringOrNull(config, 'application_id'),
      activationApplicationId: baseline.applicationId,
      activationCertificate: baseline.certificateFingerprint,
      observedCertificate: observedCertificate,
      certificateStore: certificateStore,
      licenseActive: LicenseManager.status.value.grantsFeatures,
      licenseApplicationId: _stringOrNull(config, 'bundle_id'),
      licenseCertificate: licenseCertificate,
      licenseDeviceId: _stringOrNull(config, 'device_id'),
      observedDeviceId: await _observedDeviceId(),
      keystoreBindingIntact: await _keystoreBindingIntact(),
      // Read from the verdict licensing already reached, not re-derived
      // here. `null` until a token has been evaluated in this process, which
      // is what keeps the legacy signals above authoritative for a build
      // that has no device binding. See TrustInputs.deviceKeyVerdict.
      deviceKeyVerdict: LicenseManager.bindingResult?.verdict,
      deviceKeyBacking: DeviceKeyManager.lastBacking,
      reportedSdkVersion: SdkConfig.sdkVersion,
      sdkVersionPolicy: SdkVersionPolicy.fromConfig(config),
      configEnvelope: config.isEmpty
          ? null
          : SecurityConfigEnvelope.fromConfig(
              config,
              versionOverride: heldConfigVersion,
            ),
      // heldConfigVersion/heldConfigId are passed for API completeness and
      // for direct callers/tests that supply genuinely distinct held values —
      // see the note above `configVerification` for why, in *this* collector,
      // they compare a document against itself and cannot detect a downgrade
      // or replay of the top-level config today.
      heldConfigVersion: heldConfigVersion,
      heldConfigId: heldConfigId,
      liveConfigFingerprint:
          SecurityConfigEnvelope.fingerprintOf(RemoteConfigManager.values),
      configVerification: configVerification,
      releaseEnvironment: declaredEnvironment,
      releaseEnvironmentPolicy: policy,
      compiledInDebugMode: kDebugMode,
      // Read-only: this collector never triggers an attestation run itself
      // (see AttestationOrchestrator's doc comment for why) — it reports
      // whatever the most recently completed run found, or `null` before
      // any run has ever completed, which TrustEngine's optionalAnchors
      // handling already treats as UNAVAILABLE rather than a threat.
      attestationResult: AttestationOrchestrator.lastResult,
      sdkIntegrityManifest: sdkIntegrityManifest,
      buildIdentity: await const BuildIdentityCollector().collect(),
      pipelineRollout: pipelineRollout,
    );
  }

  /// Records this install's identity baseline, once, for the post-activation
  /// re-check. Call after a successful activation.
  Future<void> captureBaseline() async {
    final applicationId = await _observedApplicationId();
    final certificate = await _observedCertificate();
    if (applicationId == null && certificate == null) return;
    await TrustBaselineStore.captureIfAbsent(TrustBaseline(
      applicationId: applicationId,
      certificateFingerprint: certificate,
    ));
  }

  static String? _stringOrNull(Map<String, dynamic> map, String key) {
    final value = map[key];
    if (value is! String) return null;
    final trimmed = value.trim();
    return trimmed.isEmpty ? null : trimmed;
  }

  static Future<String?> _observedApplicationId() async {
    try {
      final value = await ActivationManager.bundleId();
      return value.isEmpty ? null : value;
    } catch (_) {
      return null;
    }
  }

  static Future<String?> _observedCertificate() async {
    try {
      final value = await ActivationManager.signingCertSha256();
      return value.isEmpty ? null : CertificateTrustStore.normalize(value);
    } catch (_) {
      return null;
    }
  }

  /// Whether the Keystore binding still resolves.
  ///
  /// The native `verifyDeviceBinding()` returns `true` when binding **failed**
  /// — an inverted polarity preserved from the shipped implementation. It is
  /// inverted exactly once, here at the boundary, so nothing downstream has to
  /// remember. `null` (the check could not run) stays `null`.
  static Future<bool?> _keystoreBindingIntact() async {
    final failed = await RaspNativeChannel.boolCall('verifyDeviceBinding');
    return failed == null ? null : !failed;
  }

  static Future<String?> _observedDeviceId() async {
    try {
      final value = await DeviceIdentity.get();
      return value.isEmpty ? null : value;
    } catch (_) {
      return null;
    }
  }
}
