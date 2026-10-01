import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../core/core.dart';
import '../protection/protection_action.dart';
import '../risk/risk_posture.dart';
import '../security/request_signer.dart';
import 'security_event_privacy.dart';
import 'security_event_type.dart';

/// Phase 2 — the one structured security event this SDK produces.
///
/// ## Why one model rather than shipping each producer's own shape
///
/// Before this model existed, the SDK had fifteen distinct security-fact
/// producers and six outbound paths, three of which dropped their payload
/// silently on any failure, none of which carried an event identity or an
/// ordering — a series of unrelated payload shapes that happened to describe
/// security facts, not events.
///
/// This is that missing type. Every producer maps onto it (see
/// `SecurityEventFactory`), so integrity, sequencing, deduplication, queuing
/// and privacy are implemented **once** rather than fifteen times — which is
/// also why the milestone forbids a second telemetry system: there is one
/// event, and it rides the transport that already exists.
///
/// ## Immutable, and validated at construction
///
/// Every field is final and every evidence map passes through
/// [SecurityEventPrivacy.redact] inside the constructor. An event cannot be
/// mutated after it is sealed into the hash chain, and there is no path that
/// puts unredacted evidence into one. Both properties are what make the
/// integrity chain meaningful: a digest over a mutable object proves nothing.
///
/// ## What is deliberately absent
///
/// No licence key, no activation token, no device private key, no raw
/// attestation token, no API key, no password, no user content. The model
/// **cannot carry them** — the only free-form field is [evidenceSummary],
/// which is a redacted `Map<String, String>`, not an arbitrary object graph.
/// See Phase 10 in `docs/SECURITY_EVENT_PRIVACY.md`.
class SecurityEvent {
  /// Unique per **occurrence**, not per detector or per rule.
  ///
  /// 128 bits of `Random.secure()` entropy, hex-encoded — the same
  /// construction `RequestSigner.randomNonce()` already uses for request
  /// nonces, reused rather than reinvented. Two devices minting the same id
  /// is not a practical concern, which is what lets the backend treat it as a
  /// replay key (Phase 8) as well as an identity.
  final String eventId;

  final SecurityEventType eventType;

  /// When the event was produced on-device, UTC.
  ///
  /// Device time, and honestly labelled as such. The SDK has a
  /// rollback-resistant `TrustedClock`, but it is anchored to a server
  /// `issued_at` that an offline device may not have refreshed — so this is
  /// evidence, never proof. The [sequence] is what actually orders events;
  /// this is what makes them human-readable. A backend that needs
  /// authoritative time uses its own receipt timestamp.
  final DateTime timestamp;

  /// Strictly increasing within this device+application context. See
  /// `SecurityEventSequencer` for the persistence and rollback model.
  final int sequence;

  /// The producing detector, when the event came from one.
  final String? detectorId;

  final DetectionStatus? status;
  final DetectionSeverity? severity;
  final DetectionConfidence? confidence;

  /// `0`–`100`, when a risk evaluation produced one.
  final int? riskScore;

  final RiskPosture? posture;

  /// The action actually taken, when this event records a decision.
  final ProtectionAction? action;

  /// Redacted, bounded, key-sorted evidence. Never arbitrary user data.
  final Map<String, String> evidenceSummary;

  final String sdkVersion;
  final String platform;
  final String applicationId;

  /// The `key_id` of the device binding key this event was produced under.
  ///
  /// `null` on an unbound (legacy) device — deliberately distinct from an
  /// empty string, because "this device has no binding key" and "this device
  /// has a key whose id is blank" are different facts and the backend treats
  /// them differently (see `docs/LICENSE_DEVICE_BINDING.md`).
  final String? deviceBindingId;

  /// Phase 9. Governs queue eviction only — never ordering, never severity.
  final SecurityEventPriority priority;

  /// The attack chain this event belongs to (Phase 11), when any.
  final String? chainId;

  SecurityEvent({
    required this.eventId,
    required this.eventType,
    required this.timestamp,
    required this.sequence,
    required this.sdkVersion,
    required this.platform,
    required this.applicationId,
    this.detectorId,
    this.status,
    this.severity,
    this.confidence,
    this.riskScore,
    this.posture,
    this.action,
    this.deviceBindingId,
    this.chainId,
    this.priority = SecurityEventPriority.medium,
    Map<String, Object?>? evidence,
  }) : evidenceSummary = SecurityEventPrivacy.redact(evidence);

  /// Mints a fresh [eventId] and stamps [timestamp] from the wall clock.
  ///
  /// The explicit constructor above stays available so a test — and the
  /// chain verifier — can reconstruct an event exactly.
  factory SecurityEvent.create({
    required SecurityEventType eventType,
    required int sequence,
    required String sdkVersion,
    required String platform,
    required String applicationId,
    DateTime? timestamp,
    String? detectorId,
    DetectionStatus? status,
    DetectionSeverity? severity,
    DetectionConfidence? confidence,
    int? riskScore,
    RiskPosture? posture,
    ProtectionAction? action,
    String? deviceBindingId,
    String? chainId,
    SecurityEventPriority priority = SecurityEventPriority.medium,
    Map<String, Object?>? evidence,
  }) =>
      SecurityEvent(
        eventId: RequestSigner.randomNonce(),
        eventType: eventType,
        timestamp: (timestamp ?? DateTime.now()).toUtc(),
        sequence: sequence,
        sdkVersion: sdkVersion,
        platform: platform,
        applicationId: applicationId,
        detectorId: detectorId,
        status: status,
        severity: severity,
        confidence: confidence,
        riskScore: riskScore,
        posture: posture,
        action: action,
        deviceBindingId: deviceBindingId,
        chainId: chainId,
        priority: priority,
        evidence: evidence,
      );

  /// A stable digest over [evidenceSummary] alone.
  ///
  /// Separated from the full canonical message for two reasons: it is what
  /// deduplication keys on (Phase 5 — "same evidence identity"), and it lets
  /// the canonical message include evidence without letting an evidence value
  /// containing the canonical delimiter shift field boundaries. The digest is
  /// hex-only by construction, so it can never contain `|` — exactly the
  /// argument `RequestSigner.canonicalMessage` already makes for its body
  /// hash.
  String get evidenceDigest {
    final keys = evidenceSummary.keys.toList()..sort();
    final canonical = keys.map((k) => '$k=${evidenceSummary[k]}').join('\n');
    return sha256.convert(utf8.encode(canonical)).toString();
  }

  /// Reconstructs an event from its own [toMap] output — the exact-fidelity
  /// round trip the durable offline-queue persistence store needs (see
  /// `SecurityEventQueueStore`). Returns `null` rather than throwing on a
  /// malformed/foreign map: a corrupted persisted entry must be treated as
  /// unrecoverable and dropped, never crash the app that is trying to
  /// recover its queue.
  static SecurityEvent? fromMap(Map<String, Object?> map) {
    try {
      final eventId = map['event_id'] as String;
      final eventType = securityEventTypeFromWire(map['event_type'] as String?);
      final timestamp = DateTime.parse(map['timestamp'] as String);
      final sequence = map['sequence'] as int;
      final sdkVersion = map['sdk_version'] as String;
      final platform = map['platform'] as String;
      final applicationId = map['application_id'] as String;
      if (eventType == null) return null;

      final evidenceRaw = map['evidence_summary'];
      final evidence = evidenceRaw is Map
          ? evidenceRaw.map((k, v) => MapEntry(k.toString(), v))
          : const <String, Object?>{};

      return SecurityEvent(
        eventId: eventId,
        eventType: eventType,
        timestamp: timestamp,
        sequence: sequence,
        sdkVersion: sdkVersion,
        platform: platform,
        applicationId: applicationId,
        detectorId: map['detector_id'] as String?,
        status: _firstWhereOrNull(
            DetectionStatus.values, (s) => s.wireName == map['status']),
        severity: _firstWhereOrNull(
            DetectionSeverity.values, (s) => s.name == map['severity']),
        confidence: _firstWhereOrNull(
            DetectionConfidence.values, (c) => c.wireName == map['confidence']),
        riskScore: map['risk_score'] as int?,
        posture: _firstWhereOrNull(
            RiskPosture.values, (p) => p.wireName == map['posture']),
        action: protectionActionFromName(map['action'] as String?),
        deviceBindingId: map['device_binding_id'] as String?,
        chainId: map['chain_id'] as String?,
        priority:
            securityEventPriorityFromWire(map['priority'] as String?) ??
                SecurityEventPriority.medium,
        evidence: evidence,
      );
    } catch (_) {
      return null;
    }
  }

  /// Wire form. `snake_case`, matching every other `toMap` in this SDK.
  ///
  /// Null fields are omitted rather than written as `null`, so a consumer can
  /// distinguish "this producer had nothing to say about severity" from "this
  /// producer said the severity was null" — a distinction this codebase makes
  /// everywhere else (`DetectionStatus.unknown` vs `false`).
  Map<String, Object?> toMap() => {
        'event_id': eventId,
        'event_type': eventType.wireName,
        'timestamp': timestamp.toIso8601String(),
        'sequence': sequence,
        'priority': priority.wireName,
        if (detectorId != null) 'detector_id': detectorId,
        if (status != null) 'status': status!.wireName,
        if (severity != null) 'severity': severity!.name,
        if (confidence != null) 'confidence': confidence!.wireName,
        if (riskScore != null) 'risk_score': riskScore,
        if (posture != null) 'posture': posture!.wireName,
        if (action != null) 'action': action!.wireName,
        if (chainId != null) 'chain_id': chainId,
        'evidence_summary': evidenceSummary,
        'sdk_version': sdkVersion,
        'platform': platform,
        'application_id': applicationId,
        if (deviceBindingId != null) 'device_binding_id': deviceBindingId,
      };

  @override
  String toString() => 'SecurityEvent(${eventType.wireName}, seq=$sequence, '
      'id=${eventId.substring(0, 8)}…)';
}

T? _firstWhereOrNull<T>(List<T> values, bool Function(T) test) {
  for (final v in values) {
    if (test(v)) return v;
  }
  return null;
}
