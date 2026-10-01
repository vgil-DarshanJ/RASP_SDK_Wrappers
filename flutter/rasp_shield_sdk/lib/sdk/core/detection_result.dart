import 'detection_confidence.dart';
import 'detection_evidence.dart';
import 'detection_severity.dart';
import 'detection_status.dart';
import 'detector_type.dart';
import 'threat_category.dart';

/// A single security finding, in a shape that has no opinion about how it
/// will be consumed.
///
/// This is the SDK Core replacement for mixing a detector's outcome with its
/// display (`rasp/security_feature.dart`'s `FeatureOutcome`/`SecurityFeature`
/// carry `Color`/`IconData` fields today). `DetectionResult` carries only
/// plain Dart data, so the same instance can be:
///
/// * uploaded as telemetry (mapped to the backend's boolean flag schema),
/// * rendered on a dashboard (mapped to color/icon by the *caller*, not by
///   this class),
/// * handed to an AI narrative/risk-card pipeline as structured input,
/// * produced by a detector that does not exist yet, without this class
///   needing to change.
///
/// Nothing here imports Flutter. A pure-Dart unit test can construct and
/// assert on a `DetectionResult` with no widget tree, no platform channel,
/// and no device.
class DetectionResult {
  /// Stable identifier for the detector that produced this result, e.g.
  /// `'root_jailbreak'` or `'frida'`. Kept as a free-form string (in
  /// addition to [detectorType]) so today's `SecurityCatalog` feature ids
  /// can be carried through unchanged during a future migration.
  final String detectorId;

  /// Which mechanism this detector represents.
  final DetectorType detectorType;

  /// Which logical area of the app/device this finding belongs to.
  final ThreatCategory category;

  /// What this detector concluded — the single source of truth for the
  /// outcome. See [DetectionStatus] for why this is four states and not a
  /// boolean.
  final DetectionStatus status;

  /// Whether this detector found a threat. Derived from [status]: only
  /// [DetectionStatus.detected] is a threat, so an unavailable or errored
  /// check can never be read as one.
  bool get threatDetected => status.isThreat;

  /// How serious this finding is. Meaningful even when [threatDetected] is
  /// `false` (e.g. `low` for an informational check).
  final DetectionSeverity severity;

  /// How much this verdict should be trusted.
  ///
  /// Severity says how bad the finding is; confidence says how sure the
  /// detector is. The risk engine multiplies the two, so a doubtful critical
  /// finding cannot outweigh a certain one. Defaults to
  /// [DetectionConfidence.high] so every existing detector keeps its current
  /// weight until it opts into reporting confidence explicitly.
  final DetectionConfidence confidence;

  /// Platform this observation came from — `'android'`, `'ios'`, `'unknown'`.
  ///
  /// Carried on the result rather than inferred by the consumer, because a
  /// stored finding outlives the process that produced it and an analyst
  /// reading `threat_history` cannot otherwise tell which platform's
  /// limitations applied.
  final String platform;

  /// Version of the detector implementation that produced this result.
  ///
  /// Lets a fleet-wide report distinguish "the detector changed" from "the
  /// devices changed" after an SDK rollout.
  final String detectorVersion;

  /// Short human-readable label, e.g. `'Root / Jailbreak Detected'`.
  final String title;

  /// Longer explanation of what was checked and what was found.
  final String description;

  /// Supporting facts behind this result. Empty when the detector has
  /// nothing beyond the boolean outcome to report.
  final List<DetectionEvidence> evidence;

  /// Why this check produced no verdict, or `null` when it ran normally.
  ///
  /// Set for both [DetectionStatus.unavailable] and [DetectionStatus.error];
  /// [status] says which. Never a passing result either way — `ScanRunner`
  /// keeps these out of the evaluated population and the Protection Engine
  /// ignores them entirely.
  final String? unavailableReason;

  /// `true` when this check actually executed and produced a verdict.
  bool get isConclusive => status.isConclusive;

  /// When this detector ran, in UTC. Distinct from any server-assigned
  /// timestamp — this is the on-device observation time.
  final DateTime observedAt;

  /// Creates a single detection finding.
  const DetectionResult({
    required this.detectorId,
    required this.detectorType,
    required this.category,
    required this.status,
    required this.severity,
    required this.title,
    required this.description,
    this.evidence = const [],
    required this.observedAt,
    this.unavailableReason,
    this.confidence = DetectionConfidence.high,
    this.platform = 'unknown',
    this.detectorVersion = '1.0.0',
  });

  /// Plain-map form suitable for JSON encoding, logging, or as a stepping
  /// stone toward the backend's telemetry payload shape.
  Map<String, Object?> toMap() => {
        'detector_id': detectorId,
        'detector_type': detectorType.name,
        'category': category.name,
        'status': status.wireName,
        'threat_detected': threatDetected,
        'severity': severity.name,
        'confidence': confidence.wireName,
        'platform': platform,
        'detector_version': detectorVersion,
        'title': title,
        'description': description,
        'evidence': evidence.map((e) => e.toMap()).toList(),
        'observed_at': observedAt.toIso8601String(),
        if (unavailableReason != null) 'unavailable_reason': unavailableReason,
      };

  /// Copy with selected fields replaced. Used by the risk engine to fold
  /// duplicate findings into one result with raised confidence, without
  /// mutating the original.
  DetectionResult copyWith({
    DetectionStatus? status,
    DetectionSeverity? severity,
    DetectionConfidence? confidence,
    List<DetectionEvidence>? evidence,
  }) =>
      DetectionResult(
        detectorId: detectorId,
        detectorType: detectorType,
        category: category,
        status: status ?? this.status,
        severity: severity ?? this.severity,
        title: title,
        description: description,
        evidence: evidence ?? this.evidence,
        observedAt: observedAt,
        unavailableReason: unavailableReason,
        confidence: confidence ?? this.confidence,
        platform: platform,
        detectorVersion: detectorVersion,
      );

  @override
  String toString() =>
      'DetectionResult($detectorId, ${status.name}, ${severity.name}, '
      '${confidence.name})';
}
