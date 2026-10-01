import '../core/core.dart';
import 'trust_anchor.dart';
import 'trust_evidence.dart';

/// The overall standing of this application instance.
///
/// Deliberately *not* a risk score: `RiskEngine` owns scoring, and this
/// milestone does not replace it. A trust level answers a different question —
/// "can this instance's claimed identity be believed?" — and feeds the risk
/// pipeline as one more input.
enum TrustLevel {
  /// Every anchor that matters is explicitly valid.
  trusted,

  /// Nothing is contradicted, but coverage is incomplete — an anchor is
  /// unknown, unavailable, or errored. **Not** trusted: the fail-safe rule
  /// `UNKNOWN != TRUSTED` lives here.
  degraded,

  /// At least one anchor is contradicted, but not one of the identity anchors.
  suspicious,

  /// An identity anchor is contradicted: the application id, the signing
  /// certificate, the licence's binding to them, or a runtime identity change.
  /// There is no benign reading of this.
  compromised,

  /// Nothing could be established at all.
  unknown,
}

/// Ordering helper. Higher means less trustworthy.
extension TrustLevelX on TrustLevel {
  /// `trusted` < `degraded` < `suspicious` < `compromised`; `unknown` sits
  /// beside `degraded` in severity but is kept distinct so "we learned
  /// nothing" is never reported as "we checked and it was partly fine".
  int get severityRank {
    switch (this) {
      case TrustLevel.trusted:
        return 0;
      case TrustLevel.unknown:
        return 1;
      case TrustLevel.degraded:
        return 2;
      case TrustLevel.suspicious:
        return 3;
      case TrustLevel.compromised:
        return 4;
    }
  }

  String get wireName => name.toUpperCase();
}

/// The verdict for one anchor, with everything needed to explain it later.
class TrustAnchorResult {
  final TrustAnchor anchor;
  final TrustAnchorState state;

  /// The weakest trust class in this anchor's verification path. Caps the
  /// confidence the engine will report — see `TrustEngine`.
  final TrustRoot root;

  final DetectionConfidence confidence;
  final List<TrustEvidence> evidence;

  const TrustAnchorResult({
    required this.anchor,
    required this.state,
    required this.root,
    required this.confidence,
    this.evidence = const [],
  });

  Map<String, Object?> toMap() => {
        'anchor': anchor.name,
        'state': state.wireName,
        'root': root.name,
        'confidence': confidence.wireName,
        'evidence': evidence.map((e) => e.toMap()).toList(),
      };

  @override
  String toString() => '${anchor.name}=${state.wireName}';
}

/// A complete, deterministic trust evaluation.
///
/// Pure data. It recommends no action and blocks nothing — the existing
/// `ProtectionEngine` and the customer's `ProtectionPolicy` decide that, which
/// is what keeps an unreadable Keystore from locking a paying customer out of
/// their bank app.
class TrustAssessment {
  final TrustLevel level;
  final List<TrustAnchorResult> anchors;

  /// Every evidence code produced, in anchor order. Deduplicated: the same
  /// code never appears twice, so a consumer counting evidence counts facts.
  final List<TrustEvidence> evidence;

  /// Human-readable explanation, strongest finding first.
  final List<String> reasons;

  final DateTime evaluatedAt;

  const TrustAssessment({
    required this.level,
    required this.anchors,
    required this.evidence,
    required this.reasons,
    required this.evaluatedAt,
  });

  /// The verdict for one anchor, or `null` when it was not evaluated.
  TrustAnchorResult? anchorResult(TrustAnchor anchor) {
    for (final result in anchors) {
      if (result.anchor == anchor) return result;
    }
    return null;
  }

  bool get hasContradiction =>
      anchors.any((a) => a.state.isContradicted);

  /// `true` when any evidence code of [code] was produced.
  bool has(TrustEvidenceCode code) => evidence.any((e) => e.code == code);

  Map<String, Object?> toMap() => {
        'level': level.wireName,
        'anchors': anchors.map((a) => a.toMap()).toList(),
        'evidence': evidence.map((e) => e.code.wireName).toList(),
        'reasons': reasons,
        'evaluated_at': evaluatedAt.toIso8601String(),
      };

  /// Renders the assessment as ordinary [DetectionResult]s for the existing
  /// risk pipeline.
  ///
  /// ## Why one result per anchor, and not one per evidence code
  ///
  /// `RiskEngine` deduplicates by `detectorId`: several results sharing an id
  /// fold into **one** contribution with raised confidence. Emitting one
  /// result per anchor therefore means a single anchor firing three evidence
  /// codes cannot inflate the score three times, while two genuinely
  /// independent anchors still contribute independently. That is the
  /// "multiple evidence sources must not create uncontrolled duplicate risk
  /// contributions" requirement, satisfied by the pipeline's existing
  /// mechanism rather than a new one.
  ///
  /// Only **contradicted** anchors become threat results. An indeterminate
  /// anchor becomes a non-threat result carrying its own status, so it lands
  /// in `RiskAssessment.indeterminateCount` (contributing zero score) exactly
  /// like an indeterminate detector — a check that did not run is neither a
  /// threat nor reassurance.
  List<DetectionResult> toDetectionResults() {
    final results = <DetectionResult>[];
    for (final anchor in anchors) {
      if (anchor.state.isSatisfied && anchor.evidence.isEmpty) continue;
      results.add(DetectionResult(
        detectorId: _detectorIdFor(anchor.anchor),
        detectorType: _detectorTypeFor(anchor.anchor),
        category: ThreatCategory.appIntegrity,
        status: _statusFor(anchor.state),
        severity: _severityFor(anchor.anchor, anchor.state),
        confidence: anchor.confidence,
        title: _titleFor(anchor.anchor),
        description: _descriptionFor(anchor),
        evidence: [
          for (final item in anchor.evidence) item.toDetectionEvidence(),
        ],
        unavailableReason: anchor.state.isIndeterminate
            ? '${anchor.anchor.name} could not be verified '
                '(${anchor.state.wireName})'
            : null,
        observedAt: evaluatedAt,
        detectorVersion: '1.0.0',
      ));
    }
    return List.unmodifiable(results);
  }

  static DetectionStatus _statusFor(TrustAnchorState state) {
    switch (state) {
      case TrustAnchorState.valid:
        return DetectionStatus.secure;
      case TrustAnchorState.mismatch:
      case TrustAnchorState.expired:
        return DetectionStatus.detected;
      case TrustAnchorState.unknown:
        return DetectionStatus.unknown;
      case TrustAnchorState.unavailable:
        return DetectionStatus.unavailable;
      case TrustAnchorState.error:
        return DetectionStatus.error;
    }
  }

  /// Detector ids are `trust_`-prefixed and deliberately absent from
  /// `RiskEngine.detectorWeights` — they fall through to the existing
  /// severity-based fallback weight. No weight, threshold or ladder entry is
  /// modified by this milestone; the trust anchors simply use the fallback
  /// path the engine already provides for unlisted detectors.
  static String _detectorIdFor(TrustAnchor anchor) => 'trust_${anchor.name}';

  static DetectorType _detectorTypeFor(TrustAnchor anchor) {
    switch (anchor) {
      case TrustAnchor.applicationId:
      case TrustAnchor.runtimeApplicationIdentity:
        return DetectorType.repackage;
      case TrustAnchor.signingCertificate:
        return DetectorType.signatureMismatch;
      case TrustAnchor.deviceBinding:
        return DetectorType.root;
      case TrustAnchor.licenseBinding:
      case TrustAnchor.sdkVersion:
      case TrustAnchor.securityConfiguration:
      case TrustAnchor.releaseEnvironment:
      case TrustAnchor.attestation:
      case TrustAnchor.sdkIntegrity:
        return DetectorType.custom;
    }
  }

  /// Severity by anchor, not by state: an identity contradiction is a
  /// different class of problem from a deprecated SDK version, and flattening
  /// them would make the risk pipeline unable to tell them apart.
  static DetectionSeverity _severityFor(
    TrustAnchor anchor,
    TrustAnchorState state,
  ) {
    if (!state.isContradicted) return DetectionSeverity.low;
    switch (anchor) {
      case TrustAnchor.applicationId:
      case TrustAnchor.signingCertificate:
      case TrustAnchor.runtimeApplicationIdentity:
      case TrustAnchor.sdkIntegrity:
        return DetectionSeverity.critical;
      case TrustAnchor.licenseBinding:
      case TrustAnchor.securityConfiguration:
      case TrustAnchor.attestation:
        // `high`, not `critical`: attestation is not in `identityAnchors` —
        // a contradiction here is treated as suspicious, not automatically
        // compromised, because this parser's accuracy against genuine
        // Google/Apple output has never been physically validated. See
        // `TrustEngine._attestationAnchor`'s doc comment.
        return DetectionSeverity.high;
      case TrustAnchor.deviceBinding:
      case TrustAnchor.sdkVersion:
        return DetectionSeverity.medium;
      case TrustAnchor.releaseEnvironment:
        return DetectionSeverity.low;
    }
  }

  static String _titleFor(TrustAnchor anchor) {
    switch (anchor) {
      case TrustAnchor.applicationId:
        return 'Application Identity';
      case TrustAnchor.signingCertificate:
        return 'Signing Identity';
      case TrustAnchor.licenseBinding:
        return 'Licence Binding';
      case TrustAnchor.deviceBinding:
        return 'Device Binding';
      case TrustAnchor.sdkVersion:
        return 'SDK Version';
      case TrustAnchor.securityConfiguration:
        return 'Security Configuration';
      case TrustAnchor.releaseEnvironment:
        return 'Release Environment';
      case TrustAnchor.runtimeApplicationIdentity:
        return 'Runtime Application Identity';
      case TrustAnchor.attestation:
        return 'Platform Attestation';
      case TrustAnchor.sdkIntegrity:
        return 'SDK Self-Integrity';
    }
  }

  static String _descriptionFor(TrustAnchorResult anchor) {
    if (anchor.evidence.isEmpty) {
      return '${_titleFor(anchor.anchor)}: ${anchor.state.wireName}';
    }
    final codes = anchor.evidence.map((e) => e.code.wireName).join(', ');
    return '${_titleFor(anchor.anchor)}: ${anchor.state.wireName} ($codes)';
  }
}
