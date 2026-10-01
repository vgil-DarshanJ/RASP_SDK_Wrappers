/// Structured evidence for the risky-app / risky-environment capability
/// (Phase C of the gap-closure-3 milestone).
///
/// This is deliberately **not** a malware scanner: it never claims to
/// identify malicious software, never enumerates arbitrary installed
/// packages, and never inspects personal data. It answers one narrower
/// question — "is a specific, curated, publicly-documented risk indicator
/// present on this device right now" — using only evidence Android already
/// lets an app observe about itself and its own accessibility-service
/// environment (see `docs/RISKY_APP_DETECTION.md` for the platform audit
/// this design is based on).
library;

/// Outcome of one evidence check. Mirrors the fail-safe vocabulary used
/// across every other detector in this SDK — never collapses a check that
/// didn't run into "safe".
enum RiskyAppEvidenceStatus {
  /// The signal fired — [RiskyAppEvidence.detected] is `true`.
  detected,

  /// The check ran and found nothing — a genuine, positive "clean" result,
  /// not the absence of a result.
  notDetected,

  /// The check ran but could not reach a confident verdict (e.g. a
  /// malformed native response).
  unknown,

  /// The check could not run at all (wrong platform, no native handler).
  unavailable,

  /// The check itself threw.
  error,
}

extension RiskyAppEvidenceStatusX on RiskyAppEvidenceStatus {
  String get wireName => switch (this) {
        RiskyAppEvidenceStatus.detected => 'DETECTED',
        RiskyAppEvidenceStatus.notDetected => 'NOT_DETECTED',
        RiskyAppEvidenceStatus.unknown => 'UNKNOWN',
        RiskyAppEvidenceStatus.unavailable => 'UNAVAILABLE',
        RiskyAppEvidenceStatus.error => 'ERROR',
      };

  /// Only [RiskyAppEvidenceStatus.detected] is ever a threat signal.
  bool get isThreat => this == RiskyAppEvidenceStatus.detected;
}

/// Which class of signal this evidence represents. Kept as two genuinely
/// distinct categories per the milestone's explicit instruction — a known,
/// named risk-tool package is materially stronger evidence than "some
/// third-party accessibility service is active", and the two must never be
/// merged into one confidence number.
enum RiskyAppEvidenceCategory {
  /// A specific, curated package (remote-access tool, instrumentation
  /// framework) known by name and confirmed present via `PackageManager`.
  knownRiskyPackage,

  /// A weaker, capability-based signal — e.g. an active third-party
  /// accessibility service that is *not* itself a known-risky package.
  /// Ordinary, legitimate accessibility apps produce this same signal, so
  /// it is never treated as equivalent to [knownRiskyPackage].
  suspiciousBehavior,
}

/// One piece of evidence. Immutable, plain data — no platform types leak
/// through this model, matching every other detector's `DetectionEvidence`.
class RiskyAppEvidence {
  /// The package identifier involved, or `null` when the evidence is not
  /// package-specific (e.g. an accessibility-query failure).
  ///
  /// Deliberately the only "package intelligence" exposed to the host
  /// app — no version, installer, permissions, or other package metadata
  /// is collected or surfaced (Phase C2's "do not expose unnecessary
  /// package intelligence").
  final String? package;

  final RiskyAppEvidenceCategory category;

  /// Short machine-readable reason code, e.g. `'remote_access'`,
  /// `'instrumentation_framework'`, `'active_third_party_accessibility_service'`.
  final String reason;

  final RiskyAppEvidenceStatus status;

  /// Convenience — `status == detected`. Kept alongside `status` (rather
  /// than replacing it) because "not a threat" and "could not be
  /// determined" are both `detected == false` but must never be reported
  /// identically.
  bool get detected => status.isThreat;

  /// Where this evidence came from, e.g. `'package_manager'`,
  /// `'accessibility_manager'`.
  final String source;

  /// How much this single piece of evidence should be trusted in
  /// isolation — combined with others by [RiskyAppConfidence], never
  /// invented per-evidence beyond this coarse split.
  final RiskyAppEvidenceConfidence confidence;

  const RiskyAppEvidence({
    required this.package,
    required this.category,
    required this.reason,
    required this.status,
    required this.source,
    required this.confidence,
  });

  Map<String, Object?> toMap() => {
        'package': package,
        'category': category.name,
        'reason': reason,
        'status': status.wireName,
        'detected': detected,
        'source': source,
        'confidence': confidence.name,
      };
}

/// Coarse per-evidence confidence — [knownRiskyPackage] evidence is always
/// [strong] (a specific named package was definitively found via a real
/// system API); [suspiciousBehavior] evidence is always [weak] (capability
/// alone, shared by many legitimate apps). Multiple [weak] pieces of
/// evidence for the *same* underlying signal do not compound into
/// [strong] — see `RiskyAppDetector`'s aggregation rule.
enum RiskyAppEvidenceConfidence { weak, strong }
