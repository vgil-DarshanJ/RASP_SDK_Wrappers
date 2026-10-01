/// Secure Sensitive-Operation Protection Engine.
///
/// Turns the existing `TransactionIntegrity` digest/signature/replay
/// primitive into a reusable, policy-driven authorization mechanism: a host
/// app declares an operation's sensitivity, the SDK combines it with the
/// device's current risk/trust/binding/attestation/offline state and any
/// step-up result, and produces ALLOW/STEP_UP/RESTRICT/BLOCK plus (on
/// ALLOW) a short-lived, single-use, cryptographically bound authorization.
///
/// Import this single file to get the whole subsystem, matching
/// `sdk/events/events.dart`'s barrel pattern.
///
/// Design documents: `docs/SENSITIVE_OPERATION_SECURITY.md`,
/// `docs/SENSITIVE_OPERATION_POLICY.md`,
/// `docs/SENSITIVE_OPERATION_THREAT_MODEL.md`.
library;

export 'authentication_state.dart';
export 'backend_verification_outcome.dart';
export 'operation_action.dart';
export 'operation_authorization.dart';
export 'operation_authorizer.dart';
export 'operation_context.dart';
export 'operation_policy.dart';
export 'operation_sensitivity.dart';
export 'protected_operation_backend_client.dart';
export 'step_up.dart';
