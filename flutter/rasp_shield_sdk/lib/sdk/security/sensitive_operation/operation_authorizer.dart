import '../../device/canonical_field.dart';
import 'authentication_state.dart';
import 'operation_action.dart';
import 'operation_authorization.dart';
import 'operation_context.dart';
import 'operation_policy.dart';
import 'operation_sensitivity.dart';

/// The full explanation behind one policy evaluation — Phase 3's decision
/// output, with the evidence a security event or an analyst needs.
class SensitiveOperationDecision {
  final SensitiveOperationAction action;

  /// The action [SensitiveOperationPolicy.floorFor] produced, before
  /// step-up/authentication was folded in. Equal to [action] unless
  /// authentication state changed the outcome — kept separate so a caller
  /// can distinguish "this was always ALLOW" from "this was STEP_UP,
  /// satisfied, downgraded to ALLOW."
  final SensitiveOperationAction baselineFloor;

  final int policyVersion;

  final List<String> reasons;

  const SensitiveOperationDecision({
    required this.action,
    required this.baselineFloor,
    required this.policyVersion,
    required this.reasons,
  });

  @override
  String toString() =>
      'SensitiveOperationDecision(${action.wireName}, floor=${baselineFloor.wireName})';
}

/// Phase 6/7/8/11/13/16/17 — the engine: evaluate, issue, verify.
///
/// ## Concurrency (Phase 16)
///
/// [verify] is fully synchronous — no `await` inside the nonce-check-then-
/// consume critical section. Dart's single-threaded event-loop model means
/// a synchronous method body cannot be interleaved with another call to the
/// same method: two "simultaneous" callers are actually sequential at the
/// microtask level, so the second one always observes the first's
/// consumption. This is a **deliberate design choice**, not an incidental
/// property — introducing an `await` between the nonce lookup and the
/// nonce write would reopen exactly the race Phase 16 tests for.
class SensitiveOperationAuthorizer {
  SensitiveOperationAuthorizer({
    this.policy = const SensitiveOperationPolicy(),
    this.authorizationLifetime = const Duration(minutes: 2),
  });

  final SensitiveOperationPolicy policy;

  /// Phase 7: authorizations are short-lived by construction. Two minutes
  /// is long enough for a host app to complete one API round-trip after
  /// authorization, short enough that a leaked object is worthless quickly.
  final Duration authorizationLifetime;

  /// Consumed nonces, mapped to when they were consumed — bounded and
  /// pruned exactly like `TransactionOperationGuard._seenOperationNonces`,
  /// the same pattern for the same reason (a security review already found
  /// an unbounded version of this a storage-exhaustion risk in that class;
  /// not repeating that mistake here).
  final Map<String, DateTime> _consumedNonces = {};
  static const int _maxTrackedNonces = 4096;

  /// Phase 3/8/9/10 — decides an action from risk/trust/device/attestation/
  /// offline state plus the operation's own authentication state. Pure:
  /// no I/O, no mutation, safe to call repeatedly for the same context.
  SensitiveOperationDecision evaluate(
    SensitiveOperationContext context, {
    required bool isOffline,
  }) {
    final floor = policy.floorFor(context, isOffline: isOffline);
    final reasons = <String>[
      'Sensitivity ${context.sensitivity.wireName} floors at '
          '${(policy.sensitivityFloor[context.sensitivity] ?? SensitiveOperationAction.stepUp).wireName}',
    ];

    var action = floor;

    switch (context.authenticationState) {
      case OperationAuthenticationState.satisfied:
        // A satisfied step-up can only ever relieve the STEP_UP rung it was
        // requested for — never a RESTRICT or BLOCK floor raised by risk,
        // trust, device binding, or attestation. This is what stops
        // "the user re-authenticated" from being usable to launder a
        // compromised-device verdict into an allow.
        if (action == SensitiveOperationAction.stepUp) {
          action = SensitiveOperationAction.allow;
          reasons.add('Step-up satisfied — STEP_UP relieved to ALLOW');
        }
        break;
      case OperationAuthenticationState.failed:
        // A failed step-up attempt is evidence, not merely an unmet
        // requirement — never weaker than RESTRICT regardless of how low
        // risk/trust otherwise floor.
        if (action.rank < SensitiveOperationAction.restrict.rank) {
          action = SensitiveOperationAction.restrict;
        }
        reasons.add('Step-up attempt failed — floored at RESTRICT');
        break;
      case OperationAuthenticationState.expired:
        reasons.add('Step-up result expired — requirement unmet');
        break;
      case OperationAuthenticationState.required_:
      case OperationAuthenticationState.notRequired:
        break;
    }

    return SensitiveOperationDecision(
      action: action,
      baselineFloor: floor,
      policyVersion: policy.version,
      reasons: List.unmodifiable(reasons),
    );
  }

  /// Phase 6/7 — issues a short-lived, bound authorization. Returns `null`
  /// (never throws) when [evaluate] does not resolve to
  /// [SensitiveOperationAction.allow] for [context] — an authorization is
  /// never issued for an operation this policy has not fully cleared. The
  /// caller that wants a STEP_UP prompt reads [evaluate] directly; `issue`
  /// is only ever the last step, after step-up (if any) already succeeded.
  ///
  /// Also returns `null`, rather than propagating a [CanonicalFieldError],
  /// when a bound field (operation id/type, application id, or the caller-
  /// supplied device-binding id) contains the canonical delimiter — a
  /// Phase 23 finding: this is host-app-controlled data, and a malformed
  /// value must not be able to crash the authorization flow any more than a
  /// malformed field crashes `SecurityEventPipeline.submit`.
  SensitiveOperationAuthorization? issue({
    required SensitiveOperationContext context,
    required bool isOffline,
    required String activationToken,
    String? deviceBindingId,
    required String applicationId,
    DateTime? now,
  }) {
    final decision = evaluate(context, isOffline: isOffline);
    if (decision.action != SensitiveOperationAction.allow) return null;
    if (activationToken.isEmpty) return null;

    try {
      final issuedAt = (now ?? DateTime.now()).toUtc();
      final expiresAt = issuedAt.add(authorizationLifetime);
      final message = SensitiveOperationAuthorization.canonicalMessage(
        operationId: context.operationId,
        operationType: context.operationType,
        transactionDigest: context.transactionDigest,
        deviceBindingId: deviceBindingId,
        applicationId: applicationId,
        issuedAt: issuedAt,
        nonce: context.nonce,
      );
      final signature = SensitiveOperationAuthorization.sign(
        activationToken: activationToken,
        message: message,
      );

      return SensitiveOperationAuthorization(
        operationId: context.operationId,
        operationType: context.operationType,
        transactionDigest: context.transactionDigest,
        deviceBindingId: deviceBindingId,
        applicationId: applicationId,
        issuedAt: issuedAt,
        expiresAt: expiresAt,
        nonce: context.nonce,
        signature: signature,
      );
    } on CanonicalFieldError {
      return null;
    }
  }

  /// Phase 7/11/12/13/16/17 — verifies [authorization] against the fields
  /// actually being executed now, and consumes its nonce on success.
  ///
  /// Fail-safe throughout: every non-[AuthorizationState.authorized] result
  /// (`expired`, `revoked`, `invalid`) means execution must not proceed —
  /// there is no branch that returns anything else on missing/unavailable
  /// input. See `docs/SENSITIVE_OPERATION_SECURITY.md` §"Fail-safe" for the
  /// full enumeration this method is built against.
  AuthorizationState verify({
    required SensitiveOperationAuthorization authorization,
    required String candidateOperationId,
    required String candidateOperationType,
    required String candidateTransactionDigest,
    String? candidateDeviceBindingId,
    required String candidateApplicationId,
    required String activationToken,
    DateTime? now,
    void Function(AuthorizationState state, AuthorizationInvalidReason? reason)?
        onVerified,
  }) {
    AuthorizationState finish(
      AuthorizationState state, [
      AuthorizationInvalidReason? reason,
    ]) {
      if (onVerified != null) onVerified(state, reason);
      return state;
    }

    if (authorization.isRevoked) return finish(AuthorizationState.revoked);

    final clock = (now ?? DateTime.now()).toUtc();
    if (clock.isAfter(authorization.expiresAt.toUtc())) {
      return finish(AuthorizationState.expired);
    }

    // Recompute the signature from the authorization's OWN bound fields —
    // defence against an authorization object reconstructed with mismatched
    // fields (e.g. across a serialization boundary a host app might add
    // later). Never trusts the object's own claim about itself.
    final expectedMessage = SensitiveOperationAuthorization.canonicalMessage(
      operationId: authorization.operationId,
      operationType: authorization.operationType,
      transactionDigest: authorization.transactionDigest,
      deviceBindingId: authorization.deviceBindingId,
      applicationId: authorization.applicationId,
      issuedAt: authorization.issuedAt,
      nonce: authorization.nonce,
    );
    final expectedSignature = SensitiveOperationAuthorization.sign(
      activationToken: activationToken,
      message: expectedMessage,
    );
    if (expectedSignature != authorization.signature) {
      return finish(
          AuthorizationState.invalid, AuthorizationInvalidReason.signatureMismatch);
    }

    // Phase 13: every bound field must match exactly what is being executed
    // now. Any mutation — amount/recipient/currency (all folded into
    // transactionDigest by the caller), operation, operation type,
    // timestamp (folded into transactionDigest), device, or application —
    // fails here.
    final fieldsMatch = authorization.operationId == candidateOperationId &&
        authorization.operationType == candidateOperationType &&
        authorization.transactionDigest == candidateTransactionDigest &&
        authorization.deviceBindingId == candidateDeviceBindingId &&
        authorization.applicationId == candidateApplicationId;
    if (!fieldsMatch) {
      return finish(
          AuthorizationState.invalid, AuthorizationInvalidReason.fieldMismatch);
    }

    // Single-use (Phase 7/13/16): a nonce already consumed — whether by a
    // genuine prior execution or a replay attempt — must never authorize
    // again. Checked (and the eviction sweep run) before consumption so a
    // concurrent "second" call in the same synchronous turn cannot both
    // succeed — see the class doc on why this method has no `await` in this
    // section.
    if (_consumedNonces.containsKey(authorization.nonce)) {
      return finish(
          AuthorizationState.invalid, AuthorizationInvalidReason.nonceReused);
    }
    _pruneConsumedNonces(clock);
    _consumedNonces[authorization.nonce] = clock;

    return finish(AuthorizationState.authorized);
  }

  /// Explicitly revokes [authorization] — e.g. the host app cancels a flow
  /// after issuing but before executing. Idempotent.
  void revoke(SensitiveOperationAuthorization authorization) {
    authorization.markRevoked();
  }

  /// Number of consumed nonces currently tracked. Test-only visibility.
  int get trackedNonceCount => _consumedNonces.length;

  void _pruneConsumedNonces(DateTime clock) {
    _consumedNonces.removeWhere(
        (_, consumedAt) => clock.difference(consumedAt) > authorizationLifetime * 4);
    while (_consumedNonces.length >= _maxTrackedNonces) {
      _consumedNonces.remove(_consumedNonces.keys.first);
    }
  }
}
