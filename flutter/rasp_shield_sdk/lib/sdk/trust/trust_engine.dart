import '../core/core.dart';
import '../device/device_binding_state.dart';
import '../device/device_key.dart';
import 'attestation/attestation_trust.dart';
import 'certificate_trust.dart';
import 'configuration_trust.dart';
import 'release_environment.dart';
import 'sdk_integrity.dart';
import 'sdk_version_trust.dart';
import 'trust_anchor.dart';
import 'trust_assessment.dart';
import 'trust_evidence.dart';
import 'trust_inputs.dart';

/// Turns observed [TrustInputs] into a deterministic [TrustAssessment].
///
/// ```
///   TrustInputs ──→ evaluate() ──→ TrustAssessment ──→ RiskEngine
/// ```
///
/// Pure: no I/O, no shared state, and the clock is injected. The same inputs
/// always produce the same assessment, which is what lets a stored assessment
/// be re-explained months later — the same discipline `RiskEngine` and
/// `CorrelationEngine` already follow.
///
/// **This engine does not replace `RiskEngine`.** It computes no score and
/// recommends no action; it reports identity standing, and
/// [TrustAssessment.toDetectionResults] hands that to the existing risk
/// pipeline through its ordinary entry point.
class TrustEngine {
  final CertificateTrustEvaluator certificateEvaluator;
  final ConfigurationTrustEvaluator configurationEvaluator;
  final SdkVersionTrustEvaluator sdkVersionEvaluator;
  final ReleaseEnvironmentEvaluator releaseEnvironmentEvaluator;
  final AttestationTrustEvaluator attestationEvaluator;
  final SdkIntegrityEvaluator sdkIntegrityEvaluator;

  const TrustEngine({
    this.certificateEvaluator = const CertificateTrustEvaluator(),
    this.configurationEvaluator = const ConfigurationTrustEvaluator(),
    this.sdkVersionEvaluator = const SdkVersionTrustEvaluator(),
    this.releaseEnvironmentEvaluator = const ReleaseEnvironmentEvaluator(),
    this.attestationEvaluator = const AttestationTrustEvaluator(),
    this.sdkIntegrityEvaluator = const SdkIntegrityEvaluator(),
  });

  /// Anchors whose contradiction means the application's *identity* cannot be
  /// believed. A contradiction here forces [TrustLevel.compromised].
  ///
  /// [TrustAnchor.sdkIntegrity] belongs here, unlike [TrustAnchor.attestation]
  /// (deliberately excluded — see `TrustEngine._attestationAnchor`'s doc
  /// comment): a disagreement between what a fixed, versioned canary
  /// actually computed and what the signed manifest says it should compute
  /// has no benign reading the way an unproven third-party attestation
  /// parser might. A legitimate SDK upgrade that changes a canary's
  /// behavior ships a manifest with a new `manifest_version`/new canary ids,
  /// which this anchor's evaluator treats as "nothing checked" (`unknown`),
  /// never as a mismatch — see `sdk_integrity.dart`.
  static const Set<TrustAnchor> identityAnchors = {
    TrustAnchor.applicationId,
    TrustAnchor.signingCertificate,
    TrustAnchor.runtimeApplicationIdentity,
    TrustAnchor.sdkIntegrity,
  };

  /// Anchors that may only ever *withdraw* trust, never confer it.
  ///
  /// Both compare a value against an earlier copy of itself, which is circular
  /// if used to grant trust and sound if used only to detect change — see
  /// `docs/TRUST_ANCHOR_MODEL.md` §2.3. Their `valid` state is treated exactly
  /// like `unknown` when deciding whether [TrustLevel.trusted] is reachable.
  ///
  /// [TrustAnchor.sdkIntegrity] joins this set for the same shape of reason:
  /// a canary that computed the expected value proves only that *this run*
  /// was not observed to be tampered — the same process could, in principle,
  /// also have patched the comparison itself, so `valid` here is not
  /// independent, additional evidence the way a platform-verified anchor is.
  static const Set<TrustAnchor> selfReferentialAnchors = {
    TrustAnchor.runtimeApplicationIdentity,
    TrustAnchor.securityConfiguration,
    TrustAnchor.sdkIntegrity,
  };

  /// Anchors that must be explicitly `valid` before [TrustLevel.trusted] is
  /// possible. Everything else may be indeterminate without preventing trust —
  /// otherwise a phone with no readable Keystore could never be trusted, which
  /// would make the engine useless in the field.
  static const Set<TrustAnchor> requiredForTrusted = {
    TrustAnchor.applicationId,
    TrustAnchor.signingCertificate,
  };

  /// Anchors whose verdict reflects an actual observation.
  ///
  /// `sdkVersion` and `releaseEnvironment` are excluded: both return `valid`
  /// when no policy has been published, which is a deliberate default so
  /// existing customers are not punished for an operator's silence — not
  /// evidence that anything was checked. Counting those as observations would
  /// make [TrustLevel.unknown] unreachable and would report "we verified some
  /// things" when nothing was verified at all.
  static const Set<TrustAnchor> substantiveAnchors = {
    TrustAnchor.applicationId,
    TrustAnchor.signingCertificate,
    TrustAnchor.licenseBinding,
    TrustAnchor.deviceBinding,
    TrustAnchor.securityConfiguration,
    TrustAnchor.runtimeApplicationIdentity,
    TrustAnchor.sdkIntegrity,
  };

  /// Anchors whose *unavailability* must never, by itself, prevent
  /// [TrustLevel.trusted] — distinct from [selfReferentialAnchors] (which are
  /// excluded because trusting them would be circular) and from
  /// [substantiveAnchors]'s exclusion of `sdkVersion`/`releaseEnvironment`
  /// (which default to `valid`, so they never reach this check at all).
  ///
  /// `attestation`'s honest default *is* `unavailable` — fabricating `valid`
  /// when no provider is configured is exactly what this milestone's brief
  /// forbids ("DO NOT FAKE ATTESTATION") — so unlike `sdkVersion`, it
  /// genuinely reaches the indeterminate check below, and needs its own
  /// exclusion or every device without Play Services/a Secure Enclave
  /// (every device today — no native attestation implementation exists yet)
  /// would silently stop reaching `TRUSTED` the moment this anchor was
  /// added. That regression was caught by the existing trust-engine test
  /// suite failing after this anchor was wired in — fixed here, not by
  /// weakening attestation's own fail-safe default.
  static const Set<TrustAnchor> optionalAnchors = {
    TrustAnchor.attestation,
  };

  TrustAssessment evaluate(TrustInputs inputs, {DateTime? now}) {
    final at = (now ?? DateTime.now()).toUtc();

    final anchors = <TrustAnchorResult>[
      _applicationIdAnchor(inputs),
      _signingCertificateAnchor(inputs),
      _licenseBindingAnchor(inputs),
      _deviceBindingAnchor(inputs),
      _sdkVersionAnchor(inputs),
      _securityConfigurationAnchor(inputs, at),
      _releaseEnvironmentAnchor(inputs),
      _runtimeIdentityAnchor(inputs),
      _attestationAnchor(inputs),
      _sdkIntegrityAnchor(inputs),
    ];

    final evidence = <TrustEvidence>[];
    final seen = <TrustEvidenceCode>{};
    for (final anchor in anchors) {
      for (final item in anchor.evidence) {
        if (seen.add(item.code)) evidence.add(item);
      }
    }

    return TrustAssessment(
      level: _levelFor(anchors),
      anchors: List.unmodifiable(anchors),
      evidence: List.unmodifiable(evidence),
      reasons: _reasonsFor(anchors),
      evaluatedAt: at,
    );
  }

  // ── Level derivation ────────────────────────────────────────────────────

  /// The level, derived in strict precedence order so the result never depends
  /// on anchor ordering.
  static TrustLevel _levelFor(List<TrustAnchorResult> anchors) {
    // 1. An identity contradiction outranks everything. A certificate or
    //    application-id mismatch can never be softened by other anchors
    //    passing — that is the fail-safe rule, not a heuristic.
    for (final anchor in anchors) {
      if (anchor.state.isContradicted &&
          identityAnchors.contains(anchor.anchor)) {
        return TrustLevel.compromised;
      }
    }

    // 2. Any other contradiction.
    if (anchors.any((a) => a.state.isContradicted)) {
      return TrustLevel.suspicious;
    }

    // 3. Nothing contradicted. Trust requires the required anchors to be
    //    *explicitly* valid — never merely un-contradicted.
    final required = anchors.where((a) => requiredForTrusted.contains(a.anchor));
    final allRequiredValid =
        required.length == requiredForTrusted.length &&
            required.every((a) => a.state.isSatisfied);

    if (!allRequiredValid) {
      // If nothing could actually be *observed*, say so rather than implying a
      // partial check succeeded. Only substantive anchors count: `sdkVersion`
      // and `releaseEnvironment` return `valid` when no policy has been
      // published, which is a deliberate "do not punish existing customers"
      // default rather than evidence that anything was verified.
      final anyObserved = anchors.any((a) =>
          !a.state.isIndeterminate && substantiveAnchors.contains(a.anchor));
      return anyObserved ? TrustLevel.degraded : TrustLevel.unknown;
    }

    // 4. Required anchors valid, but coverage elsewhere is incomplete.
    //    Self-referential anchors are excluded from conferring trust, so a
    //    `valid` from them does not count toward completeness either.
    //    Optional anchors (attestation) are excluded for the opposite-shaped
    //    reason: their *absence* must not cost a device TRUSTED status.
    final indeterminate = anchors.any((a) =>
        a.state.isIndeterminate &&
        !selfReferentialAnchors.contains(a.anchor) &&
        !optionalAnchors.contains(a.anchor));
    return indeterminate ? TrustLevel.degraded : TrustLevel.trusted;
  }

  static List<String> _reasonsFor(List<TrustAnchorResult> anchors) {
    final contradicted = [
      for (final a in anchors)
        if (a.state.isContradicted)
          '${a.anchor.name}: ${a.state.wireName}'
              '${a.evidence.isEmpty ? '' : ' (${a.evidence.map((e) => e.code.wireName).join(', ')})'}',
    ];
    final indeterminate = [
      for (final a in anchors)
        if (a.state.isIndeterminate)
          '${a.anchor.name}: ${a.state.wireName} — not verified',
    ];
    return List.unmodifiable([...contradicted, ...indeterminate]);
  }

  // ── Confidence ──────────────────────────────────────────────────────────

  /// Confidence for a verdict, capped by the authority of its weakest source.
  ///
  /// This is the whole of Phase 13's requirement in one place: a mismatch is
  /// not automatically certain. A `local`-rooted anchor — one the app asserts
  /// about itself — can never report better than `medium`, because an attacker
  /// in the process controls the claim. A `platform`-rooted anchor may reach
  /// `veryHigh`, because the OS asserted it. And an indeterminate state always
  /// reports `low`: we did not learn anything, and confidence must say so.
  static DetectionConfidence _confidence(
    TrustAnchorState state,
    TrustRoot root, {
    /// Set when several independent facts agree — e.g. a licence that
    /// mismatches on both application id and certificate.
    int corroboratingSignals = 1,
  }) {
    if (state.isIndeterminate) return DetectionConfidence.low;

    final DetectionConfidence ceiling;
    switch (root) {
      case TrustRoot.local:
        ceiling = DetectionConfidence.medium;
        break;
      case TrustRoot.server:
      case TrustRoot.platform:
        ceiling = DetectionConfidence.veryHigh;
        break;
      case TrustRoot.hardware:
        ceiling = DetectionConfidence.veryHigh;
        break;
    }

    final base = root == TrustRoot.local
        ? DetectionConfidence.low
        : DetectionConfidence.high;
    final boosted =
        (base.rank + (corroboratingSignals - 1)).clamp(0, ceiling.rank);
    return DetectionConfidence.values[boosted];
  }

  // ── Per-anchor evaluation ───────────────────────────────────────────────

  static TrustAnchorResult _applicationIdAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.applicationId;
    const root = TrustRoot.platform;

    final observed = inputs.observedApplicationId?.trim();
    if (observed == null || observed.isEmpty) {
      // Inability to read identity is never proof of identity.
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.unavailable,
        root: root,
        confidence: _confidence(TrustAnchorState.unavailable, root),
        evidence: const [
          TrustEvidence(TrustEvidenceCode.applicationIdUnavailable),
        ],
      );
    }

    // A package id is a dotted reverse-DNS name. Anything else did not come
    // from a real PackageManager read.
    if (!RegExp(r'^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$').hasMatch(observed)) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.unknown,
        root: root,
        confidence: _confidence(TrustAnchorState.unknown, root),
        evidence: const [
          TrustEvidence(TrustEvidenceCode.applicationIdMalformed),
        ],
      );
    }

    final expected = inputs.expectedApplicationId?.trim();
    if (expected == null || expected.isEmpty) {
      // Nothing to compare against yet — the check has not run, which is not
      // the same as passing.
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.unavailable,
        root: root,
        confidence: _confidence(TrustAnchorState.unavailable, root),
        evidence: const [
          TrustEvidence(
            TrustEvidenceCode.applicationIdUnavailable,
            detail: 'no expected application id is configured',
          ),
        ],
      );
    }

    if (observed != expected) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.mismatch,
        root: root,
        confidence: _confidence(TrustAnchorState.mismatch, root),
        evidence: const [
          TrustEvidence(
            TrustEvidenceCode.applicationIdMismatch,
            detail: 'running package differs from the registered application',
          ),
        ],
      );
    }

    return TrustAnchorResult(
      anchor: anchor,
      state: TrustAnchorState.valid,
      root: root,
      confidence: _confidence(TrustAnchorState.valid, root),
    );
  }

  TrustAnchorResult _signingCertificateAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.signingCertificate;
    const root = TrustRoot.platform;
    final verdict = certificateEvaluator.evaluate(
      observedFingerprint: inputs.observedCertificate,
      store: inputs.certificateStore,
    );
    return TrustAnchorResult(
      anchor: anchor,
      state: verdict.state,
      root: root,
      confidence: _confidence(verdict.state, root),
      evidence: verdict.evidence,
    );
  }

  /// The licence anchor is the cross-check that makes a stolen licence
  /// useless: it never asks "is this licence valid", it asks "does this valid
  /// licence describe *this* application, certificate and device".
  static TrustAnchorResult _licenseBindingAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.licenseBinding;
    const root = TrustRoot.server;

    if (inputs.licenseActive == null) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.unavailable,
        root: root,
        confidence: _confidence(TrustAnchorState.unavailable, root),
        evidence: const [TrustEvidence(TrustEvidenceCode.licenseUnavailable)],
      );
    }

    if (inputs.licenseActive == false) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.mismatch,
        root: root,
        confidence: _confidence(TrustAnchorState.mismatch, root),
        evidence: const [TrustEvidence(TrustEvidenceCode.licenseNotActive)],
      );
    }

    final evidence = <TrustEvidence>[];

    final licenseApp = inputs.licenseApplicationId?.trim();
    final observedApp = inputs.observedApplicationId?.trim();
    if (licenseApp != null &&
        licenseApp.isNotEmpty &&
        observedApp != null &&
        observedApp.isNotEmpty &&
        licenseApp != observedApp) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.licenseAppMismatch,
        detail: 'licence was issued to a different application',
      ));
    }

    final licenseCert = inputs.licenseCertificate?.trim();
    final observedCert = inputs.observedCertificate?.trim();
    if (licenseCert != null &&
        licenseCert.isNotEmpty &&
        observedCert != null &&
        observedCert.isNotEmpty &&
        CertificateTrustStore.normalize(licenseCert) !=
            CertificateTrustStore.normalize(observedCert)) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.licenseCertificateMismatch,
        detail: 'licence was issued against a different signing identity',
      ));
    }

    final licenseDevice = inputs.licenseDeviceId?.trim();
    final observedDevice = inputs.observedDeviceId?.trim();
    if (licenseDevice != null &&
        licenseDevice.isNotEmpty &&
        observedDevice != null &&
        observedDevice.isNotEmpty &&
        licenseDevice != observedDevice) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.licenseDeviceMismatch,
        detail: 'licence seat belongs to a different device',
      ));
    }

    if (evidence.isNotEmpty) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.mismatch,
        root: root,
        confidence: _confidence(
          TrustAnchorState.mismatch,
          root,
          corroboratingSignals: evidence.length,
        ),
        evidence: List.unmodifiable(evidence),
      );
    }

    return TrustAnchorResult(
      anchor: anchor,
      state: TrustAnchorState.valid,
      root: root,
      confidence: _confidence(TrustAnchorState.valid, root),
    );
  }

  /// The cryptographic half of device binding, or `null` when there is no
  /// verdict to report and the legacy signals should decide.
  ///
  /// `null` is returned for `notBound` — a token that asserts no key proves
  /// nothing either way — so a build predating this milestone behaves
  /// exactly as it did before, and so does every existing test.
  static TrustAnchorResult? _deviceKeyAnchor(
    TrustInputs inputs,
    TrustAnchor anchor,
  ) {
    final verdict = inputs.deviceKeyVerdict;
    if (verdict == null || verdict == DeviceBindingVerdict.notBound) {
      return null;
    }

    // Honest authority, and the one thing this milestone is forbidden from
    // overclaiming: a key the platform confirmed lives in a TEE is
    // `hardware`; a software-backed key is still OS-managed and
    // non-exportable through this API, which is `platform`; anything else
    // is a claim the app makes about itself, which is `local`. None of
    // these is attestation — see docs/LICENSE_DEVICE_BINDING.md §9.
    final root = switch (inputs.deviceKeyBacking) {
      DeviceKeyBacking.hardwareBacked => TrustRoot.hardware,
      DeviceKeyBacking.softwareBacked => TrustRoot.platform,
      _ => TrustRoot.local,
    };

    final code = switch (verdict) {
      DeviceBindingVerdict.valid => TrustEvidenceCode.deviceKeyValid,
      DeviceBindingVerdict.keyMismatch => TrustEvidenceCode.deviceKeyMismatch,
      DeviceBindingVerdict.keyMissing => TrustEvidenceCode.deviceKeyMissing,
      DeviceBindingVerdict.keyRevoked => TrustEvidenceCode.deviceKeyRevoked,
      DeviceBindingVerdict.proofInvalid => TrustEvidenceCode.deviceProofInvalid,
      DeviceBindingVerdict.keyUnavailable =>
        TrustEvidenceCode.deviceKeyUnavailable,
      DeviceBindingVerdict.keyError => TrustEvidenceCode.deviceKeyError,
      DeviceBindingVerdict.notBound => TrustEvidenceCode.deviceKeyUnavailable,
    };

    // UNAVAILABLE and ERROR map to their own states, never to `valid` and
    // never to `mismatch` — Phase 12's rule that an absence of information
    // may not manufacture a TRUSTED state, nor a threat.
    final state = switch (verdict) {
      DeviceBindingVerdict.valid => TrustAnchorState.valid,
      DeviceBindingVerdict.keyUnavailable => TrustAnchorState.unavailable,
      DeviceBindingVerdict.keyError => TrustAnchorState.error,
      _ => TrustAnchorState.mismatch,
    };

    // Cross-Platform Device Binding, Phase 10: no IOS_/ANDROID_-prefixed
    // evidence codes were added here. `DeviceKeyBacking` (HARDWARE_BACKED /
    // SOFTWARE_BACKED / UNAVAILABLE / ERROR) is already the platform-neutral
    // vocabulary for "Secure Enclave vs Keychain" and "StrongBox/TEE vs
    // software Keystore" — the exact distinction a second, iOS-specific set
    // of codes would have duplicated. Minting DEVICE_KEY_VALID a second time
    // as IOS_DEVICE_KEY_VALID would be the "second trust hierarchy" this
    // milestone (and the Android one before it) explicitly forbids — see
    // docs/ANDROID_IOS_DEVICE_BINDING_PARITY.md "Trust evidence". The backing
    // tier is surfaced instead as human-readable detail on the SAME codes
    // every platform already emits, so a SOC console reads "bound (Secure
    // Enclave)" / "bound (Android Keystore, hardware-backed)" without a
    // second enum to keep in sync.
    final detail = _deviceKeyDetail(verdict.reason, inputs.deviceKeyBacking);
    return TrustAnchorResult(
      anchor: anchor,
      state: state,
      root: root,
      confidence: _confidence(state, root),
      evidence: [TrustEvidence(code, detail: detail)],
    );
  }

  /// Backing-tier detail for device-key evidence, platform-neutral by
  /// construction (see the caller's comment). Never claims a backing tier
  /// the platform did not itself confirm — mirrors `DeviceKeyBacking`'s own
  /// no-overclaiming rule.
  static String? _deviceKeyDetail(String? reason, DeviceKeyBacking backing) {
    final tier = switch (backing) {
      DeviceKeyBacking.hardwareBacked => 'hardware-backed key',
      DeviceKeyBacking.softwareBacked => 'software-backed key',
      DeviceKeyBacking.unavailable => null,
      DeviceKeyBacking.error => null,
    };
    if (reason == null) return tier;
    if (tier == null) return reason;
    return '$reason ($tier)';
  }

  /// Device binding is deliberately reported at lower authority than identity.
  ///
  /// A persisted UUID is `local` trust — trivially copyable. The Keystore
  /// alias is closer to `hardware`, but the check only proves an alias
  /// resolves, and benign causes for it failing are common (reinstall,
  /// factory reset, lock-screen credential change). Both facts are reported;
  /// neither is allowed to masquerade as an identity contradiction.
  static TrustAnchorResult _deviceBindingAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.deviceBinding;

    // A cryptographic verdict, when one exists, decides this anchor on its
    // own. It is strictly stronger evidence than either legacy signal: the
    // UUID comparison is copyable and the alias probe cannot see a
    // transferred install at all (audit §3.3), whereas a key-id mismatch
    // means this handset does not hold the non-exportable private key the
    // seat was issued to. Letting the weaker signals soften it would be the
    // fail-open this milestone exists to remove.
    final keyResult = _deviceKeyAnchor(inputs, anchor);
    if (keyResult != null) return keyResult;

    final keystore = inputs.keystoreBindingIntact;
    final licenseDevice = inputs.licenseDeviceId?.trim();
    final observedDevice = inputs.observedDeviceId?.trim();

    final hasDeviceComparison = licenseDevice != null &&
        licenseDevice.isNotEmpty &&
        observedDevice != null &&
        observedDevice.isNotEmpty;

    if (keystore == null && !hasDeviceComparison) {
      return const TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.unavailable,
        root: TrustRoot.local,
        confidence: DetectionConfidence.low,
        evidence: [TrustEvidence(TrustEvidenceCode.deviceBindingUnavailable)],
      );
    }

    final evidence = <TrustEvidence>[];
    // The strongest root available in this anchor's path decides the reported
    // authority: a Keystore observation outranks a persisted UUID comparison.
    final root = keystore != null ? TrustRoot.hardware : TrustRoot.local;

    if (keystore == false) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.deviceBindingMismatch,
        detail: 'the hardware-backed binding key no longer resolves',
      ));
    }
    if (hasDeviceComparison && licenseDevice != observedDevice) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.deviceIdentityChanged,
        detail: 'device identity differs from the one this seat was issued to',
      ));
    }

    if (evidence.isNotEmpty) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.mismatch,
        root: root,
        confidence: _confidence(
          TrustAnchorState.mismatch,
          root,
          corroboratingSignals: evidence.length,
        ),
        evidence: List.unmodifiable(evidence),
      );
    }

    return TrustAnchorResult(
      anchor: anchor,
      state: TrustAnchorState.valid,
      root: root,
      confidence: _confidence(TrustAnchorState.valid, root),
    );
  }

  TrustAnchorResult _sdkVersionAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.sdkVersion;
    // A self-reported version is `local` trust: a repackager can claim any
    // version. Capped at `medium` confidence by _confidence(), which is the
    // honest weighting for an operational signal rather than an adversarial
    // one.
    const root = TrustRoot.local;
    final verdict = sdkVersionEvaluator.evaluate(
      reportedVersion: inputs.reportedSdkVersion,
      policy: inputs.sdkVersionPolicy,
    );
    return TrustAnchorResult(
      anchor: anchor,
      state: verdict.state,
      root: root,
      confidence: _confidence(verdict.state, root),
      evidence: verdict.evidence,
    );
  }

  TrustAnchorResult _securityConfigurationAnchor(
    TrustInputs inputs,
    DateTime now,
  ) {
    const anchor = TrustAnchor.securityConfiguration;
    // Server-delivered. Where `inputs.configVerification` is present, the
    // configuration was cryptographically verified against the SDK's pinned
    // Ed25519 trust root (see docs/SIGNED_SECURITY_CONFIGURATION.md) before
    // this method ever runs — TrustEngine stays synchronous and pure, so the
    // (necessarily async) signature check happens once, in the collector, and
    // arrives here as plain data. The mutation check still compares the
    // config against its own earlier fingerprint regardless of signing,
    // because a signature does not cover what happened to the values after
    // they were applied. Reported as `server` authority for contradictions it
    // finds; its `valid` state confers no trust, because it is in
    // `selfReferentialAnchors`.
    const root = TrustRoot.server;
    final verdict = configurationEvaluator.evaluate(
      envelope: inputs.configEnvelope,
      now: now,
      heldVersion: inputs.heldConfigVersion,
      heldConfigId: inputs.heldConfigId,
      liveFingerprint: inputs.liveConfigFingerprint,
      verification: inputs.configVerification,
    );
    return TrustAnchorResult(
      anchor: anchor,
      state: verdict.state,
      root: root,
      confidence: _confidence(
        verdict.state,
        root,
        corroboratingSignals:
            verdict.evidence.isEmpty ? 1 : verdict.evidence.length,
      ),
      evidence: verdict.evidence,
    );
  }

  TrustAnchorResult _releaseEnvironmentAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.releaseEnvironment;
    const root = TrustRoot.local;
    final verdict = releaseEnvironmentEvaluator.evaluate(
      environment: inputs.releaseEnvironment,
      policy: inputs.releaseEnvironmentPolicy,
      compiledInDebugMode: inputs.compiledInDebugMode,
    );
    return TrustAnchorResult(
      anchor: anchor,
      state: verdict.state,
      root: root,
      confidence: _confidence(verdict.state, root),
      evidence: verdict.evidence,
    );
  }

  /// Post-activation identity re-verification — the gap the audit named.
  ///
  /// Compares what is observed *now* against what this install observed when
  /// its seat was established. Nothing legitimate changes an application id or
  /// a signing certificate under a running install; a change here therefore
  /// has no benign reading, which is why it is an identity anchor.
  ///
  /// A certificate that has moved to a fingerprint the trust store still
  /// accepts is **not** a mismatch — that is a legitimate upgrade during a
  /// rotation window, and failing it would break exactly the customer upgrades
  /// the brief requires be preserved.
  static TrustAnchorResult _runtimeIdentityAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.runtimeApplicationIdentity;
    const root = TrustRoot.platform;

    final activationApp = inputs.activationApplicationId?.trim();
    final activationCert = inputs.activationCertificate?.trim();
    final observedApp = inputs.observedApplicationId?.trim();
    final observedCert = inputs.observedCertificate?.trim();

    final canCompareApp = activationApp != null &&
        activationApp.isNotEmpty &&
        observedApp != null &&
        observedApp.isNotEmpty;
    final canCompareCert = activationCert != null &&
        activationCert.isNotEmpty &&
        observedCert != null &&
        observedCert.isNotEmpty;

    if (!canCompareApp && !canCompareCert) {
      // No baseline captured yet — the very first run. Unavailable, never a
      // pass: this anchor may only withdraw trust, never confer it.
      return const TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.unavailable,
        root: root,
        confidence: DetectionConfidence.low,
      );
    }

    final evidence = <TrustEvidence>[];
    if (canCompareApp && activationApp != observedApp) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.runtimeIdentityMismatch,
        detail: 'application identity changed after activation',
      ));
    }
    if (canCompareCert &&
        CertificateTrustStore.normalize(activationCert) !=
            CertificateTrustStore.normalize(observedCert)) {
      // A move to another *trusted* fingerprint is a legitimate upgrade
      // during a rotation window, not a compromise.
      final role = inputs.certificateStore.roleOf(observedCert);
      final legitimateRotation =
          role == CertificateRole.current || role == CertificateRole.next;
      if (!legitimateRotation) {
        evidence.add(const TrustEvidence(
          TrustEvidenceCode.runtimeIdentityMismatch,
          detail: 'signing identity changed to an untrusted certificate',
        ));
      }
    }

    if (evidence.isNotEmpty) {
      return TrustAnchorResult(
        anchor: anchor,
        state: TrustAnchorState.mismatch,
        root: root,
        confidence: _confidence(
          TrustAnchorState.mismatch,
          root,
          corroboratingSignals: evidence.length,
        ),
        evidence: List.unmodifiable(evidence),
      );
    }

    return TrustAnchorResult(
      anchor: anchor,
      state: TrustAnchorState.valid,
      root: root,
      confidence: _confidence(TrustAnchorState.valid, root),
    );
  }

  /// Hardware/platform attestation (Play Integrity / App Attest).
  ///
  /// Rooted at [TrustRoot.hardware] when genuinely valid — the slot that
  /// trust root was reserved for since the Trust Anchor Engine's first
  /// milestone. Deliberately **not** in [identityAnchors]: a contradicted
  /// attestation is reported as `SUSPICIOUS`-tier, not automatically
  /// `COMPROMISED`, because this parser's accuracy against genuine
  /// Google/Apple output has never been physically validated (no device is
  /// available) — see `docs/ATTESTATION_ARCHITECTURE.md` §4 for the decision
  /// record. Also **not** in [requiredForTrusted]: a device with no
  /// attestation support (older hardware, no Play Services, no Secure
  /// Enclave) must still be able to reach `TRUSTED` through the other
  /// anchors, per this milestone's explicit "do not block merely because
  /// attestation is unavailable" instruction.
  TrustAnchorResult _attestationAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.attestation;
    const root = TrustRoot.hardware;
    final verdict = attestationEvaluator.evaluate(inputs.attestationResult);
    return TrustAnchorResult(
      anchor: anchor,
      state: verdict.state,
      root: root,
      confidence: _confidence(verdict.state, root),
      evidence: verdict.evidence,
    );
  }

  /// SDK Self-Integrity — behavioral canaries against a signed manifest.
  ///
  /// Rooted at [TrustRoot.server], for exactly the reason
  /// [_securityConfigurationAnchor] is: the *expected* values this anchor
  /// judges against are delivered inside the operator's Ed25519-signed
  /// configuration and cannot be forged without the backend's private key,
  /// even though the comparison itself necessarily runs in-process. The
  /// authority of a **contradiction** it finds therefore comes from the
  /// server, not from the app's own say-so.
  ///
  /// Its `valid` state still confers no trust — it is in
  /// [selfReferentialAnchors] — because a passing canary only proves this
  /// run was not observed to be tampered, and the same process could in
  /// principle have patched the comparison too.
  ///
  /// **Why not [TrustRoot.local]:** that was the first implementation, and
  /// it was wrong in a way this milestone's own attack-simulation tests
  /// caught. `_confidence` caps a `local`-rooted verdict at `low`, which is
  /// below [CorrelationRule.minimumConfidence]'s `medium` floor — so the
  /// `RUNTIME_TAMPERING` / `SECURITY_ENGINE_TAMPER` chains could never fire
  /// from a real assessment, silently. See `docs/SDK_SELF_INTEGRITY.md` §5.
  TrustAnchorResult _sdkIntegrityAnchor(TrustInputs inputs) {
    const anchor = TrustAnchor.sdkIntegrity;
    const root = TrustRoot.server;
    final verdict = sdkIntegrityEvaluator.evaluate(
      inputs.sdkIntegrityManifest,
      observedBuildIdentity: inputs.buildIdentity,
    );
    return TrustAnchorResult(
      anchor: anchor,
      state: verdict.state,
      root: root,
      confidence: _confidence(verdict.state, root),
      evidence: verdict.evidence,
    );
  }
}
