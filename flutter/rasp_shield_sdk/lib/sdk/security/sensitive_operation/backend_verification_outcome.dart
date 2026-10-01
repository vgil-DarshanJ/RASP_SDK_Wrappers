import 'operation_authorization.dart';

/// Phase 2/5 — the possible results of asking the backend
/// `/api/v1/sdk/protected-operations/verify` to independently confirm a
/// [SensitiveOperationAuthorization]. Deliberately a **separate, narrower**
/// type from [AuthorizationState] rather than a widening of it — the exact
/// precedent [AuthorizationInvalidReason] already set for carrying
/// finer-grained detail without redesigning the 5-value state machine
/// itself (see `docs/PROTECTED_OPERATION_END_TO_END_AUDIT.md` §4).
enum BackendVerificationOutcome {
  /// The backend independently confirmed this authorization. HTTP 200.
  authorized,

  /// The backend rejected the authorization outright — a bad signature, a
  /// bad activation, or a non-writable device/seat status. Collapses
  /// several distinct backend error codes because, at the authorization
  /// level, they are all "this authorization is not good" — the underlying
  /// code is preserved separately (see [rawCode]) for event evidence.
  invalid,

  /// HTTP 409 `EXPIRED` — the backend's own clock says this authorization's
  /// lifetime has passed (independent of, and in addition to, the SDK's own
  /// local expiry check).
  expired,

  /// HTTP 409 `REPLAYED` — this authorization's nonce was already consumed
  /// server-side.
  replayed,

  /// HTTP 403 `DEVICE_MISMATCH` — the authorization is bound to a device
  /// key the backend does not recognize as the activation's current one.
  deviceMismatch,

  /// HTTP 403 `APPLICATION_MISMATCH`.
  applicationMismatch,

  /// HTTP 429 — the per-device rate budget for this endpoint is exhausted.
  /// **Not** evidence the authorization is bad; see
  /// `docs/PROTECTED_OPERATION_END_TO_END_AUDIT.md` §5 for why this is
  /// handled as "could not ask," never as "asked and was told no."
  rateLimited,

  /// The backend could not be asked at all: network failure, timeout,
  /// malformed/unexpected response body, or any HTTP status this mapping
  /// does not recognize. The fail-safe catch-all — deliberately the target
  /// of every unrecognized shape, never [authorized].
  unavailable,
}

extension BackendVerificationOutcomeX on BackendVerificationOutcome {
  /// `true` only for [BackendVerificationOutcome.authorized]. Mirrors
  /// [AuthorizationStateX.grantsExecution] — the same "cannot be got wrong
  /// by writing `==` in one place and something looser elsewhere"
  /// discipline.
  bool get grantsExecution => this == BackendVerificationOutcome.authorized;

  /// `true` when the backend gave a definitive answer (positive or
  /// negative) rather than merely failing to answer. [rateLimited] and
  /// [unavailable] are the only non-definitive outcomes — see
  /// `docs/PROTECTED_OPERATION_END_TO_END_AUDIT.md` §5: a definitive
  /// rejection hard-fails regardless of offline policy, while a
  /// non-definitive one is handled as "backend unreachable" and re-floored
  /// through the SDK's existing offline policy.
  bool get isDefinitive => this != BackendVerificationOutcome.rateLimited &&
      this != BackendVerificationOutcome.unavailable;

  /// Maps this outcome onto the existing [AuthorizationState] vocabulary,
  /// for a caller that wants to fold a backend result into the same state
  /// machine local verification already produces. `null` for
  /// [rateLimited]/[unavailable] — there is no [AuthorizationState] value
  /// that means "could not be determined," and inventing one would be
  /// exactly the enum-widening this design avoids; a caller must handle
  /// `null` explicitly (see [ProtectedOperationBackendClient] callers).
  AuthorizationState? get authorizationState {
    switch (this) {
      case BackendVerificationOutcome.authorized:
        return AuthorizationState.authorized;
      case BackendVerificationOutcome.expired:
        return AuthorizationState.expired;
      case BackendVerificationOutcome.invalid:
      case BackendVerificationOutcome.replayed:
      case BackendVerificationOutcome.deviceMismatch:
      case BackendVerificationOutcome.applicationMismatch:
        return AuthorizationState.invalid;
      case BackendVerificationOutcome.rateLimited:
      case BackendVerificationOutcome.unavailable:
        return null;
    }
  }

  /// The wire-format error code this outcome was derived from, when known
  /// — evidence for a security event, never used to make the decision
  /// itself (the decision is already made; this is just the label).
  String get wireName {
    switch (this) {
      case BackendVerificationOutcome.authorized:
        return 'AUTHORIZED';
      case BackendVerificationOutcome.invalid:
        return 'INVALID';
      case BackendVerificationOutcome.expired:
        return 'EXPIRED';
      case BackendVerificationOutcome.replayed:
        return 'REPLAYED';
      case BackendVerificationOutcome.deviceMismatch:
        return 'DEVICE_MISMATCH';
      case BackendVerificationOutcome.applicationMismatch:
        return 'APPLICATION_MISMATCH';
      case BackendVerificationOutcome.rateLimited:
        return 'RATE_LIMITED';
      case BackendVerificationOutcome.unavailable:
        return 'UNAVAILABLE';
    }
  }
}

/// Phase 2/12 — the pure, I/O-free core of response interpretation. Given
/// only an HTTP status code and a decoded JSON body (or `null` for a body
/// that failed to decode), this is a total function with **no** network
/// dependency — the exhaustive Phase-12 scenario matrix (valid/invalid/
/// expired/replayed/device-mismatch/application-mismatch/malformed-
/// response/rate-limited/unexpected-status) is tested directly against
/// this function, with no HTTP-mocking library required (none exists in
/// this project's `dev_dependencies` — see the audit doc).
///
/// [ProtectedOperationBackendClient] is the thin, separately-reasoned-about
/// wrapper that actually performs the HTTP call and hands its outcome to
/// this function; on any exception (timeout, connection refused, DNS
/// failure) it calls this with `statusCode: null, body: null`, which always
/// resolves to [BackendVerificationOutcome.unavailable].
BackendVerificationOutcome interpretBackendResponse({
  required int? statusCode,
  required Map<String, Object?>? body,
}) {
  if (statusCode == 200) {
    final status = body?['status'];
    return status == 'AUTHORIZED'
        ? BackendVerificationOutcome.authorized
        // A 200 that does not actually say AUTHORIZED is an unexpected
        // shape, not a pass — fail-safe, never authorized on a technicality.
        : BackendVerificationOutcome.unavailable;
  }

  if (statusCode == 429) return BackendVerificationOutcome.rateLimited;

  // FastAPI's HTTPException(detail={"code": ..., "message": ...}) wraps
  // the code under "detail"; be liberal in what is accepted (a bare
  // top-level "code" is also recognized) but never guess when neither
  // shape is present.
  final detail = body?['detail'];
  final codeSource = detail is Map ? detail : body;
  final code = codeSource is Map ? codeSource['code'] : null;
  if (code is! String) return BackendVerificationOutcome.unavailable;

  switch (code) {
    case 'EXPIRED':
      return BackendVerificationOutcome.expired;
    case 'REPLAYED':
      return BackendVerificationOutcome.replayed;
    case 'DEVICE_MISMATCH':
      return BackendVerificationOutcome.deviceMismatch;
    case 'APPLICATION_MISMATCH':
      return BackendVerificationOutcome.applicationMismatch;
    case 'RATE_LIMITED':
      return BackendVerificationOutcome.rateLimited;
    case 'INVALID':
    case 'INVALID_SIGNATURE':
    case 'BAD_ACTIVATION':
    case 'DEVICE_REVOKED':
    case 'DEVICE_BLOCKED':
    case 'PENDING_APPROVAL':
      return BackendVerificationOutcome.invalid;
    default:
      // An unrecognized code from a future backend version — fail-safe,
      // never authorized, never silently ignored.
      return BackendVerificationOutcome.unavailable;
  }
}
