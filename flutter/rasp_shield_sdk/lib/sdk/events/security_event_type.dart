/// The vocabulary of security events — Phase 2 and Phase 9 of the Security
/// Event Integrity milestone.
///
/// Deliberately a **closed enum**, not a free string. A free-text event type
/// is unqueryable six months later and un-deduplicatable today: two producers
/// spelling the same incident differently defeat both the dedup key
/// (`SecurityEventDeduplicator`) and any backend grouping. Adding a type is a
/// code change and a review, which is the correct cost.
library;

/// What a security event says happened.
///
/// The first five entries are the *pipeline* events — one per existing
/// security-fact producer (`DetectionResult`, `TrustAssessment`,
/// `RiskAssessment`, `AttackChain`, `CompatibilityDecision`). The next eight
/// are Phase 13's SDK self-integrity events. The last two are events the event
/// system emits *about itself*, so a failure of this subsystem is visible
/// rather than silent.
enum SecurityEventType {
  /// One detector reached a verdict. Wraps a `DetectionResult`.
  detection,

  /// The trust engine produced an assessment. Wraps a `TrustAssessment`.
  trustAssessment,

  /// The risk engine produced a score and posture.
  riskAssessment,

  /// A correlation rule fired — one event per attack chain (Phase 11).
  correlationChain,

  /// A protection decision was reached and acted on (Phase 12).
  protectionDecision,

  // ── Phase 13: SDK self-integrity ──────────────────────────────────────

  /// The SDK verified its own integrity successfully.
  sdkIntegrityValid,

  /// The SDK's own integrity check failed.
  sdkIntegrityFailed,

  /// A signed remote configuration failed signature verification.
  configSignatureFailed,

  /// A request or activation presented a device key that is not the one
  /// bound to this seat.
  deviceKeyMismatch,

  /// Trusted time reported a rollback or an uncredible clock.
  licenseTimeAnomaly,

  /// A signed request was rejected as a replay.
  requestReplay,

  /// A protected transaction's digest did not match its declared fields.
  transactionTamper,

  /// Hardware attestation could not be completed or was rejected.
  attestationFailure,

  // ── Sensitive Operation Protection Engine (Phase 14) ───────────────────

  /// A sensitive-operation policy decision resolved to ALLOW.
  sensitiveOperationAllowed,

  /// A sensitive-operation policy decision resolved to STEP_UP.
  sensitiveOperationStepUp,

  /// A sensitive-operation policy decision resolved to RESTRICT.
  sensitiveOperationRestricted,

  /// A sensitive-operation policy decision resolved to BLOCK.
  sensitiveOperationBlocked,

  /// An authorization's bound fields did not match what was presented at
  /// verification — a mutated operation, digest, device, or application.
  sensitiveOperationTampered,

  /// An authorization's nonce was already consumed.
  sensitiveOperationReplayed,

  // ── Backend-verified sensitive operations (end-to-end milestone) ───────

  /// The backend independently confirmed a
  /// `SensitiveOperationAuthorization` — `AUTHORIZED` from
  /// `/api/v1/sdk/protected-operations/verify`.
  sensitiveOperationBackendAllowed,

  /// The backend rejected an authorization outright (invalid signature,
  /// bad activation, device/application mismatch, or expired).
  sensitiveOperationBackendRejected,

  /// The backend reported the authorization's nonce as already consumed
  /// server-side — distinct from [sensitiveOperationReplayed], which is the
  /// *local* nonce-reuse detection.
  sensitiveOperationBackendReplayed,

  /// The backend could not be reached or returned an unrecognized response
  /// (timeout, malformed body, rate-limited, unexpected status) — not
  /// itself evidence of tampering, but recorded so an analyst can see when
  /// backend verification was unavailable for an operation that required
  /// it.
  sensitiveOperationBackendError,

  // ── Authoritative Protection Engine V1 ──────────────────────────────────

  /// `EnforcementController` transitioned the persisted enforcement state
  /// to `WARNED`.
  protectionWarned,

  /// `EnforcementController` transitioned the persisted enforcement state
  /// to `STEP_UP_REQUIRED`.
  protectionStepUp,

  /// `EnforcementController` transitioned the persisted enforcement state
  /// to `RESTRICTED`.
  protectionRestricted,

  /// `EnforcementController` transitioned the persisted enforcement state
  /// to `BLOCKED` via [ProtectionAction.lockApp].
  protectionBlocked,

  /// `EnforcementController` transitioned the persisted enforcement state
  /// to `BLOCKED` via [ProtectionAction.lockSession] — kept distinct from
  /// [protectionBlocked] so an analyst can tell "the app was locked" apart
  /// from "the session was ended" even though both persist as the same
  /// `EnforcementState.blocked`.
  protectionSessionLocked,

  // ── Persistent Remote Lock Enforcement ──────────────────────────────────

  /// A `LOCK_APP` remote command was received and passed de-duplication —
  /// a distinct, real command, before it is known whether applying it
  /// changes anything.
  remoteLockReceived,

  /// A `LOCK_APP` remote command actually transitioned the persisted
  /// enforcement state to `BLOCKED`.
  remoteLockApplied,

  /// A `LOCK_APP` remote command was processed but the device was already
  /// `BLOCKED` — idempotent no-op, not a new transition.
  remoteLockReplayed,

  /// A `LOCK_APP`/`UNLOCK_APP`-typed remote command could not be parsed
  /// into a valid command and was rejected before ever reaching
  /// `EnforcementController`.
  remoteLockRejected,

  /// An `UNLOCK_APP` remote command cleared the persisted enforcement
  /// state — the one documented recovery path for a remote lock.
  remoteUnlockApplied,

  /// Persisting a remote lock/unlock transition failed (storage
  /// unavailable). The in-session decision still enforces the stronger
  /// state regardless — see `EnforcementController.applyRemoteLock`.
  remoteLockPersistenceError,

  // ── Cryptographic Remote Command Integrity ──────────────────────────────
  // Generic, per-command-type events from the verification pipeline —
  // distinct from the Persistent Remote Lock Enforcement events above,
  // which describe the *enforcement-state* outcome (did BLOCKED actually
  // change) rather than the *verification* outcome (did the signature
  // check out). A LOCK_APP command that verifies produces both a
  // commandVerified event here AND, separately, a remoteLockApplied or
  // remoteLockReplayed event once EnforcementController acts on it — two
  // different questions, not duplicate telemetry for one.

  /// A command was successfully parsed from the heartbeat's
  /// `pending_commands` array — before verification.
  commandReceived,

  /// A command's cryptographic signature, device/application binding, and
  /// freshness all checked out — safe to execute.
  commandVerified,

  /// A command was rejected: malformed, an invalid signature, a
  /// device/application mismatch, or a verifier error. Never executed.
  commandRejected,

  /// A command's `issued_at`/`expires_at` window had already passed by the
  /// time this device checked it.
  commandExpired,

  /// A command's id was already present in
  /// `RemoteCommandExecutionLedger` — already executed once, not
  /// re-executed.
  commandReplayed,

  /// A verified command actually ran (its type-specific handler completed).
  commandExecuted,

  /// This device sent the command's acknowledgement back to the backend.
  commandAcknowledged,

  // ── Native security layer availability ──────────────────────────────────

  /// `RaspNativeChannel.isNativeLayerUnavailable` was true after a scan —
  /// every native call this app session has attempted came back
  /// `MissingPluginException`. The Dart-side gate (`RaspSdk.nativeLayerStatus`,
  /// `rasp_gate_screen.dart`) already refuses to render this device as safe;
  /// this event is what makes the SAME fact visible to the backend/SOC,
  /// which the gate screen alone cannot do. See the P0-1 final report and
  /// `RaspNativeChannel`'s own doc for why `MissingPluginException`
  /// specifically (not an ordinary detector negative) is the trigger.
  ///
  /// Distinct from an individual `detection` event with
  /// `DetectionStatus.unavailable`: that is `info` priority (same as a
  /// clean result — see `priorityForDetection`) and evictable under queue
  /// pressure. This aggregate signal is always `critical`
  /// (eviction-protected) — set directly in
  /// `SecurityEventFactory.fromNativeLayerUnavailable`, same as
  /// `queueOverflow`'s eviction-triggered branch.
  nativeLayerUnavailable,

  // ── Events about the event system itself ──────────────────────────────

  /// The bounded queue had to drop events. Emitted so a drop is never
  /// silent — see [SecurityEventPriority] and `SecurityEventQueue`.
  queueOverflow,

  /// The local sequence counter could not be trusted (unreadable storage,
  /// or a detected rollback). Phase 4's `UNKNOWN`/`INTEGRITY_ERROR` outcome.
  sequenceIntegrityError,

  // ── Continuous Security Telemetry milestone ─────────────────────────────

  /// This device successfully completed activation (or re-activation) —
  /// the "app launched, is now a recognised protected installation" fact
  /// the device timeline's very first row names. Deliberately not paired
  /// with a `DEACTIVATION` counterpart: this SDK has no such moment to
  /// observe locally (there is no "logout" concept below the host app),
  /// so inventing one would be exactly the fake-event-type this milestone
  /// warns against. A revoked/blocked seat is already fully covered by the
  /// existing `sdk_activations.status` transitions the Super Admin/Portal
  /// already show — not re-derived here as a second, competing signal.
  activationSucceeded,

  /// A scheduled heartbeat failed to reach the backend (network error, or
  /// a non-2xx the SDK could not interpret as a normal licence-state
  /// response). Reported at most once per consecutive-failure streak — see
  /// [heartbeatRecovered].
  heartbeatFailed,

  /// The first heartbeat to succeed after one or more [heartbeatFailed]
  /// events — closes the streak. Never emitted for an ordinary first-ever
  /// heartbeat (nothing to "recover" from).
  heartbeatRecovered,
}

extension SecurityEventTypeX on SecurityEventType {
  /// The on-the-wire name. SCREAMING_SNAKE_CASE, matching every other wire
  /// enum in this SDK (`DetectionStatus.wireName`, `TrustLevel.wireName`).
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

  /// `true` for the eight Phase 13 self-integrity types.
  bool get isSelfIntegrity =>
      index >= SecurityEventType.sdkIntegrityValid.index &&
      index <= SecurityEventType.attestationFailure.index;
}

/// Parses a [SecurityEventType] from its [SecurityEventTypeX.wireName].
///
/// Returns `null` for an unrecognised name rather than guessing — an unknown
/// type from a future SDK version must never be silently folded into an
/// existing one, because that would attribute one incident's evidence to a
/// different incident.
SecurityEventType? securityEventTypeFromWire(String? wire) {
  if (wire == null) return null;
  for (final type in SecurityEventType.values) {
    if (type.wireName == wire) return type;
  }
  return null;
}

/// Delivery priority — Phase 9.
///
/// Governs exactly one thing: **what the bounded queue is allowed to discard
/// under pressure.** It is not a severity (a `DetectionSeverity` describes the
/// threat; this describes the event's claim on limited storage), and it is not
/// an ordering (the chain's sequence is the only ordering).
enum SecurityEventPriority {
  /// Never dropped to make room for anything else. If the queue is full of
  /// nothing but critical events, a drop is still recorded and reported
  /// through a [SecurityEventType.queueOverflow] event — never silent.
  critical,

  /// Dropped only after every `medium`, `low` and `info` event is gone.
  high,

  /// The default for a pipeline event with no stronger claim.
  medium,

  /// Dropped before `medium`.
  low,

  /// Dropped first, and eligible for sampling.
  info,
}

extension SecurityEventPriorityX on SecurityEventPriority {
  String get wireName => name.toUpperCase();

  /// Lower means more important. Matches declaration order.
  int get rank => index;

  /// `true` when the queue must exhaust every other option before
  /// discarding this event.
  bool get isProtectedFromEviction => this == SecurityEventPriority.critical;
}

/// Parses a [SecurityEventPriority] from its wire name, or `null`.
SecurityEventPriority? securityEventPriorityFromWire(String? wire) {
  if (wire == null) return null;
  for (final priority in SecurityEventPriority.values) {
    if (priority.wireName == wire) return priority;
  }
  return null;
}
