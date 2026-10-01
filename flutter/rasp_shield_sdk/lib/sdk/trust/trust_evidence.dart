import '../core/core.dart';
import 'trust_anchor.dart';

/// Machine-readable reasons a trust anchor reached its verdict.
///
/// These are the codes a SOC console, a stored `threat_history` row, or a
/// customer's own policy engine can branch on months later — which is why they
/// are an enum with stable wire names rather than free-text strings.
///
/// **No code carries a secret.** A certificate fingerprint, licence key,
/// entitlement token, device id or keystore alias never appears in a code or
/// in the detail attached to one. `TrustEvidence.detail` is restricted to
/// *categories* ("observed certificate does not match any trusted fingerprint")
/// rather than values — see `TrustEvidence`'s own doc and the no-secret-leak
/// tests.
enum TrustEvidenceCode {
  // ── Application identity ────────────────────────────────────────────────
  applicationIdMismatch,
  applicationIdUnavailable,
  applicationIdMalformed,
  runtimeIdentityMismatch,

  // ── Signing identity ────────────────────────────────────────────────────
  certificateMismatch,
  certificateRevoked,
  certificateRotationPending,
  certificateNotConfigured,
  certificateUnavailable,

  // ── Licence binding ─────────────────────────────────────────────────────
  licenseAppMismatch,
  licenseCertificateMismatch,
  licenseDeviceMismatch,
  licenseNotActive,
  licenseUnavailable,

  // ── Device binding ──────────────────────────────────────────────────────
  deviceBindingMismatch,
  deviceBindingUnavailable,
  deviceIdentityChanged,

  // ── Cryptographic device key (per-device licence binding) ───────────────
  // Distinct from the three above on purpose. Those describe the *legacy*
  // signals — a persisted UUID comparison and "does an alias resolve" —
  // which `LICENSE_DEVICE_BINDING_AUDIT.md` §3.3 shows cannot detect a
  // transferred install. These describe proof of possession of a
  // non-exportable key, which can. Keeping both means a console can tell
  // which evidence a verdict actually rests on.
  deviceKeyValid,
  deviceKeyMismatch,
  deviceKeyMissing,
  deviceKeyRevoked,
  deviceProofInvalid,
  deviceKeyUnavailable,
  deviceKeyError,

  // ── Security configuration ──────────────────────────────────────────────
  configInvalid,
  configExpired,
  configReplay,
  configDowngrade,
  configMalformed,
  configMutation,
  configUnavailable,
  configSignatureValid,
  configSignatureInvalid,
  configUnknownKey,
  configUnsupportedAlgorithm,
  configNotYetValid,
  configLegacyUnsigned,
  configKeyRotationPending,

  // ── SDK version ─────────────────────────────────────────────────────────
  sdkVersionDeprecated,
  sdkVersionUnsupported,
  sdkVersionBlocked,
  sdkVersionUnknown,

  // ── Release environment ─────────────────────────────────────────────────
  debugBuildInProductionPolicy,
  stagingBuildInProductionPolicy,
  releaseEnvironmentUnknown,

  // ── Attestation ──────────────────────────────────────────────────────────
  attestationInvalid,
  attestationExpired,
  attestationReplayed,
  attestationUnknown,
  attestationUnavailable,
  attestationError,
  attestationPackageMismatch,
  attestationCertificateMismatch,
  attestationChallengeMismatch,

  // ── SDK self-integrity ─────────────────────────────────────────────────
  sdkIntegrityMismatch,
  sdkIntegrityUnavailable,
  sdkIntegrityNoCanaries,

  // ── Build identity / release obfuscation (Release Obfuscation +
  // Self-Integrity Verification milestone) — reported through the SAME
  // `sdkIntegrity` anchor, not a second trust hierarchy, because both are
  // "does this running build match what a signed, backend-authenticated
  // source says it should be" questions. See `build_identity.dart` and
  // `docs/BUILD_SELF_INTEGRITY.md`.
  buildIdentityValid,
  buildIdentityMismatch,
  releaseObfuscationMissing,
  buildSecurityUnknown,
  buildSecurityError,
}

/// Wire form and classification for [TrustEvidenceCode].
extension TrustEvidenceCodeX on TrustEvidenceCode {
  /// Stable `SCREAMING_SNAKE_CASE` identifier, e.g. `APPLICATION_ID_MISMATCH`.
  ///
  /// Derived from the enum name rather than hand-written per case so a new
  /// code cannot ship with a typo'd or duplicated wire name.
  String get wireName => name
      .replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}')
      .toUpperCase();

  /// Which anchor emits this code.
  TrustAnchor get anchor {
    switch (this) {
      case TrustEvidenceCode.applicationIdMismatch:
      case TrustEvidenceCode.applicationIdUnavailable:
      case TrustEvidenceCode.applicationIdMalformed:
        return TrustAnchor.applicationId;
      case TrustEvidenceCode.runtimeIdentityMismatch:
        return TrustAnchor.runtimeApplicationIdentity;
      case TrustEvidenceCode.certificateMismatch:
      case TrustEvidenceCode.certificateRevoked:
      case TrustEvidenceCode.certificateRotationPending:
      case TrustEvidenceCode.certificateNotConfigured:
      case TrustEvidenceCode.certificateUnavailable:
        return TrustAnchor.signingCertificate;
      case TrustEvidenceCode.licenseAppMismatch:
      case TrustEvidenceCode.licenseCertificateMismatch:
      case TrustEvidenceCode.licenseDeviceMismatch:
      case TrustEvidenceCode.licenseNotActive:
      case TrustEvidenceCode.licenseUnavailable:
        return TrustAnchor.licenseBinding;
      case TrustEvidenceCode.deviceBindingMismatch:
      case TrustEvidenceCode.deviceBindingUnavailable:
      case TrustEvidenceCode.deviceIdentityChanged:
      case TrustEvidenceCode.deviceKeyValid:
      case TrustEvidenceCode.deviceKeyMismatch:
      case TrustEvidenceCode.deviceKeyMissing:
      case TrustEvidenceCode.deviceKeyRevoked:
      case TrustEvidenceCode.deviceProofInvalid:
      case TrustEvidenceCode.deviceKeyUnavailable:
      case TrustEvidenceCode.deviceKeyError:
        return TrustAnchor.deviceBinding;
      case TrustEvidenceCode.configInvalid:
      case TrustEvidenceCode.configExpired:
      case TrustEvidenceCode.configReplay:
      case TrustEvidenceCode.configDowngrade:
      case TrustEvidenceCode.configMalformed:
      case TrustEvidenceCode.configMutation:
      case TrustEvidenceCode.configUnavailable:
      case TrustEvidenceCode.configSignatureValid:
      case TrustEvidenceCode.configSignatureInvalid:
      case TrustEvidenceCode.configUnknownKey:
      case TrustEvidenceCode.configUnsupportedAlgorithm:
      case TrustEvidenceCode.configNotYetValid:
      case TrustEvidenceCode.configLegacyUnsigned:
      case TrustEvidenceCode.configKeyRotationPending:
        return TrustAnchor.securityConfiguration;
      case TrustEvidenceCode.sdkVersionDeprecated:
      case TrustEvidenceCode.sdkVersionUnsupported:
      case TrustEvidenceCode.sdkVersionBlocked:
      case TrustEvidenceCode.sdkVersionUnknown:
        return TrustAnchor.sdkVersion;
      case TrustEvidenceCode.debugBuildInProductionPolicy:
      case TrustEvidenceCode.stagingBuildInProductionPolicy:
      case TrustEvidenceCode.releaseEnvironmentUnknown:
        return TrustAnchor.releaseEnvironment;
      case TrustEvidenceCode.attestationInvalid:
      case TrustEvidenceCode.attestationExpired:
      case TrustEvidenceCode.attestationReplayed:
      case TrustEvidenceCode.attestationUnknown:
      case TrustEvidenceCode.attestationUnavailable:
      case TrustEvidenceCode.attestationError:
      case TrustEvidenceCode.attestationPackageMismatch:
      case TrustEvidenceCode.attestationCertificateMismatch:
      case TrustEvidenceCode.attestationChallengeMismatch:
        return TrustAnchor.attestation;
      case TrustEvidenceCode.sdkIntegrityMismatch:
      case TrustEvidenceCode.sdkIntegrityUnavailable:
      case TrustEvidenceCode.sdkIntegrityNoCanaries:
      case TrustEvidenceCode.buildIdentityValid:
      case TrustEvidenceCode.buildIdentityMismatch:
      case TrustEvidenceCode.releaseObfuscationMissing:
      case TrustEvidenceCode.buildSecurityUnknown:
      case TrustEvidenceCode.buildSecurityError:
        return TrustAnchor.sdkIntegrity;
    }
  }
}

/// One machine-readable finding from a trust anchor.
///
/// [detail] is optional, human-readable, and deliberately narrow: it may
/// describe *what kind of* mismatch occurred, never the values involved. The
/// engine never puts a fingerprint, key, token, id or alias into it, and a
/// dedicated test asserts that no evidence produced from a fully-populated
/// input set contains any of the values that were fed in.
class TrustEvidence {
  final TrustEvidenceCode code;
  final String? detail;

  const TrustEvidence(this.code, {this.detail});

  /// Renders as the core model's own evidence type, so a trust finding travels
  /// through the existing pipeline as an ordinary [DetectionEvidence] rather
  /// than a parallel structure the risk engine would have to learn about.
  DetectionEvidence toDetectionEvidence() =>
      DetectionEvidence(key: 'trust_evidence', value: code.wireName);

  Map<String, Object?> toMap() => {
        'code': code.wireName,
        'anchor': code.anchor.name,
        if (detail != null) 'detail': detail,
      };

  @override
  String toString() => code.wireName;

  @override
  bool operator ==(Object other) =>
      other is TrustEvidence && other.code == code && other.detail == detail;

  @override
  int get hashCode => Object.hash(code, detail);
}
