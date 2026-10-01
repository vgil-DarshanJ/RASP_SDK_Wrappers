/// Phase 3 — event integrity, and Phase 8 — replay/tamper detection.
///
/// ## The mechanism, and why this one
///
/// Every event is sealed into an **append-only hash chain**:
///
/// ```
/// digest(n) = SHA-256( DOMAIN | canonical(event n) | digest(n-1) )
/// digest(0) = SHA-256( DOMAIN | "GENESIS" )
/// ```
///
/// This is the minimum construction that detects all four things the
/// milestone requires — modification, reordering, duplication and deletion —
/// with one primitive:
///
/// | Attack | Why the chain catches it |
/// |---|---|
/// | **Modify** an event | Its canonical form changes, so its digest changes, so every later link fails to reproduce. |
/// | **Reorder** two events | Each digest commits to its predecessor's digest, so a swap breaks both links. |
/// | **Duplicate** an event | The duplicate's `previousDigest` cannot match both positions; and its `eventId`/`sequence` collide (Phase 5/8). |
/// | **Delete** an event | The successor's `previousDigest` names a digest no surviving event produces — gap **G7**, the one a per-event checksum cannot detect at all. |
///
/// ## What this is NOT
///
/// **It is not a client-only checksum standing in for authentication**, which
/// the milestone explicitly forbids. A hash chain computed on-device proves
/// *internal consistency* of a batch and nothing about its origin: an attacker
/// with code execution can compute a perfectly valid chain over fabricated
/// events. Authentication of the batch is a separate, existing mechanism —
/// `RequestSigner`'s HMAC over the request plus `DeviceProof`'s ECDSA
/// signature from the hardware-backed device key (Phase 7). The chain's job is
/// to make an *authenticated* batch also *internally verifiable*, so that a
/// batch which was authenticated once cannot have events quietly removed from
/// or shuffled within it afterwards.
///
/// That separation is the whole point of Phase 7 and is stated again in
/// `docs/SECURITY_EVENT_INTEGRITY.md`.
///
/// ## No new crypto was introduced
///
/// SHA-256 from `package:crypto` (already this SDK's only hash),
/// `|`-delimited canonical messages guarded by
/// [CanonicalField.assertSafe] (already the enforced rule for every signed
/// message here — see `docs/DEVICE_BINDING_CANONICALIZATION.md`), and a
/// versioned domain separator (already `DeviceProof.domain`'s pattern).
library;

import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../core/core.dart';
import '../device/canonical_field.dart';
import '../protection/protection_action.dart';
import '../risk/risk_posture.dart';
import 'security_event.dart';
import 'security_event_type.dart';


/// One event plus its position in the chain.
///
/// Separate from [SecurityEvent] on purpose: an event is a *fact*, a sealed
/// event is that fact *at a position*. Keeping them apart is what lets the
/// verifier reconstruct a digest from the event alone and compare, rather than
/// trusting a digest the object carries around with it.
class SealedSecurityEvent {
  final SecurityEvent event;

  /// The digest of the immediately preceding sealed event, or
  /// [SecurityEventChain.genesisDigest] for the first.
  final String previousDigest;

  /// `SHA-256` over this event's canonical form and [previousDigest].
  final String digest;

  const SealedSecurityEvent({
    required this.event,
    required this.previousDigest,
    required this.digest,
  });

  Map<String, Object?> toMap() => {
        ...event.toMap(),
        'previous_digest': previousDigest,
        'digest': digest,
      };

  /// Reconstructs a sealed event from its own [toMap] output — see
  /// `SecurityEvent.fromMap`'s identical contract: `null` on anything
  /// malformed, never a thrown exception.
  static SealedSecurityEvent? fromMap(Map<String, Object?> map) {
    final event = SecurityEvent.fromMap(map);
    final previousDigest = map['previous_digest'] as String?;
    final digest = map['digest'] as String?;
    if (event == null || previousDigest == null || digest == null) return null;
    return SealedSecurityEvent(
      event: event, previousDigest: previousDigest, digest: digest,
    );
  }

  @override
  String toString() =>
      'SealedSecurityEvent(seq=${event.sequence}, digest=${digest.substring(0, 8)}…)';
}

/// Builds and verifies the chain.
class SecurityEventChain {
  /// Versioned domain separator. A future change to what a digest covers is a
  /// new tag, never a silent reinterpretation of existing digests — the same
  /// discipline `DeviceProof.domain` already applies.
  static const String domain = 'RASP-SECURITY-EVENT-CHAIN-v1';

  /// The chain's anchor. A constant, so a fresh device and a restarted device
  /// agree on where the chain starts without exchanging anything.
  static final String genesisDigest =
      sha256.convert(utf8.encode('$domain|GENESIS')).toString();

  String _head;

  SecurityEventChain({String? head}) : _head = head ?? genesisDigest;

  /// The digest of the most recently sealed event.
  ///
  /// Sent alongside a batch so the backend can anchor it to the previous
  /// batch's tail and detect a whole batch having gone missing — the
  /// between-batch equivalent of the deletion detection above.
  String get head => _head;

  /// The exact string a digest is taken over.
  ///
  /// Every participating field is [CanonicalField.assertSafe]-checked, so a
  /// value containing `|` is **rejected**, never silently sanitised. Evidence
  /// enters as its SHA-256 digest (hex-only, so delimiter-free by
  /// construction) rather than inline — the same argument
  /// `RequestSigner.canonicalMessage` makes for its body hash.
  ///
  /// Absent optional fields are written as `-`, not omitted, so that
  /// "no detector" and "a detector named nothing" cannot canonicalise
  /// identically.
  static String canonicalMessage(
    SecurityEvent event, {
    required String previousDigest,
  }) {
    String field(String name, String? value) =>
        CanonicalField.assertSafe(name, value ?? '-');

    return [
      domain,
      field('event_id', event.eventId),
      field('sequence', event.sequence.toString()),
      field('event_type', event.eventType.wireName),
      field('timestamp', event.timestamp.toUtc().toIso8601String()),
      field('priority', event.priority.wireName),
      field('detector_id', event.detectorId),
      field('status', event.status?.wireName),
      field('severity', event.severity?.name),
      field('confidence', event.confidence?.wireName),
      field('risk_score', event.riskScore?.toString()),
      field('posture', event.posture?.wireName),
      field('action', event.action?.wireName),
      field('chain_id', event.chainId),
      field('sdk_version', event.sdkVersion),
      field('platform', event.platform),
      field('application_id', event.applicationId),
      field('device_binding_id', event.deviceBindingId),
      field('evidence_digest', event.evidenceDigest),
      field('previous_digest', previousDigest),
    ].join(canonicalDelimiter);
  }

  /// The digest [event] would have at [previousDigest].
  static String digestFor(
    SecurityEvent event, {
    required String previousDigest,
  }) =>
      sha256
          .convert(utf8
              .encode(canonicalMessage(event, previousDigest: previousDigest)))
          .toString();

  /// Appends [event] to the chain and advances [head].
  ///
  /// Throws [CanonicalFieldError] when any field contains the canonical
  /// delimiter. That is deliberate and matches every other canonical-message
  /// constructor in this SDK: an unrepresentable value is refused, never
  /// mangled into something that would sign or hash successfully as a
  /// different fact.
  SealedSecurityEvent seal(SecurityEvent event) {
    final previous = _head;
    final digest = digestFor(event, previousDigest: previous);
    _head = digest;
    return SealedSecurityEvent(
      event: event,
      previousDigest: previous,
      digest: digest,
    );
  }
}

/// Why a chain verification failed. Phase 8's rejection vocabulary.
enum SecurityEventChainFailure {
  /// A recomputed digest did not match the one carried — the event was
  /// modified after sealing.
  digestMismatch,

  /// An event's `previousDigest` did not name its predecessor's digest —
  /// something was reordered, inserted, or deleted.
  brokenLink,

  /// Two events carried the same `sequence`.
  duplicateSequence,

  /// A sequence went backwards.
  sequenceRollback,

  /// Two events carried the same `eventId` — a replayed event.
  duplicateEventId,

  /// An event's timestamp is older than the batch's permitted staleness
  /// window.
  staleEvent,

  /// An event carried a different `deviceBindingId` from the rest of the
  /// batch.
  deviceBindingMismatch,

  /// An event carried a different `applicationId` from the rest of the batch.
  applicationMismatch,
}

extension SecurityEventChainFailureX on SecurityEventChainFailure {
  String get wireName {
    final buffer = StringBuffer();
    for (var i = 0; i < name.length; i++) {
      final char = name[i];
      final isUpper = char.toUpperCase() == char && char.toLowerCase() != char;
      if (isUpper && i > 0) buffer.write('_');
      buffer.write(char.toUpperCase());
    }
    return buffer.toString();
  }
}

/// The outcome of verifying one batch.
class SecurityEventChainVerification {
  final bool valid;

  /// Every failure found, in the order encountered. Verification does not
  /// stop at the first problem: an operator investigating a tampered batch
  /// needs to know whether one event was edited or the whole batch was
  /// rebuilt, and stopping early hides that.
  final List<SecurityEventChainFailure> failures;

  /// The sequence numbers the failures attach to, index-aligned with
  /// [failures].
  final List<int> failedSequences;

  /// The digest the batch ends on, when it verified.
  final String? head;

  const SecurityEventChainVerification({
    required this.valid,
    required this.failures,
    required this.failedSequences,
    this.head,
  });

  bool contains(SecurityEventChainFailure failure) =>
      failures.contains(failure);

  @override
  String toString() => valid
      ? 'SecurityEventChainVerification(valid)'
      : 'SecurityEventChainVerification(${failures.map((f) => f.wireName).join(",")})';
}

/// Verifies a batch of sealed events.
///
/// Runs **locally as well as server-side**. Running it on-device before
/// sending is not security theatre: it turns a corrupted local queue into a
/// detected, reportable condition
/// ([SecurityEventType.sequenceIntegrityError]) instead of a batch the
/// backend silently rejects, which the device would otherwise retry forever.
class SecurityEventChainVerifier {
  /// How old an event may be and still be accepted. Events queue while
  /// offline, so this is generous by design — the milestone requires bounded
  /// retention, not fresh delivery.
  final Duration maxAge;

  const SecurityEventChainVerifier({this.maxAge = const Duration(days: 7)});

  /// Verifies [batch] starting from [expectedPreviousDigest].
  ///
  /// Pass [SecurityEventChain.genesisDigest] for a batch that begins the
  /// chain, or the previous batch's `head` to prove no batch went missing
  /// between them.
  SecurityEventChainVerification verify(
    List<SealedSecurityEvent> batch, {
    required String expectedPreviousDigest,
    DateTime? now,
    String? expectedDeviceBindingId,
    String? expectedApplicationId,
  }) {
    final failures = <SecurityEventChainFailure>[];
    final sequences = <int>[];
    final at = (now ?? DateTime.now()).toUtc();

    void fail(SecurityEventChainFailure failure, int sequence) {
      failures.add(failure);
      sequences.add(sequence);
    }

    var previous = expectedPreviousDigest;
    final seenSequences = <int>{};
    final seenEventIds = <String>{};
    int? lastSequence;

    for (final sealed in batch) {
      final event = sealed.event;

      if (sealed.previousDigest != previous) {
        fail(SecurityEventChainFailure.brokenLink, event.sequence);
      }

      final recomputed = SecurityEventChain.digestFor(
        event,
        previousDigest: sealed.previousDigest,
      );
      if (recomputed != sealed.digest) {
        fail(SecurityEventChainFailure.digestMismatch, event.sequence);
      }

      if (!seenSequences.add(event.sequence)) {
        fail(SecurityEventChainFailure.duplicateSequence, event.sequence);
      }
      if (lastSequence != null && event.sequence <= lastSequence) {
        fail(SecurityEventChainFailure.sequenceRollback, event.sequence);
      }
      lastSequence = event.sequence;

      if (!seenEventIds.add(event.eventId)) {
        fail(SecurityEventChainFailure.duplicateEventId, event.sequence);
      }

      if (at.difference(event.timestamp.toUtc()) > maxAge) {
        fail(SecurityEventChainFailure.staleEvent, event.sequence);
      }

      if (expectedDeviceBindingId != null &&
          event.deviceBindingId != expectedDeviceBindingId) {
        fail(SecurityEventChainFailure.deviceBindingMismatch, event.sequence);
      }
      if (expectedApplicationId != null &&
          event.applicationId != expectedApplicationId) {
        fail(SecurityEventChainFailure.applicationMismatch, event.sequence);
      }

      previous = sealed.digest;
    }

    return SecurityEventChainVerification(
      valid: failures.isEmpty,
      failures: List.unmodifiable(failures),
      failedSequences: List.unmodifiable(sequences),
      head: failures.isEmpty ? previous : null,
    );
  }
}
