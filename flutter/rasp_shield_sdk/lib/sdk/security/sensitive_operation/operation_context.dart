import '../../device/canonical_field.dart';
import '../../risk/risk_posture.dart';
import '../../trust/attestation/attestation_result.dart';
import '../../trust/trust_assessment.dart';
import '../../offline/offline_compliance.dart';
import '../../device/device_binding_state.dart';
import 'authentication_state.dart';
import 'operation_sensitivity.dart';

/// Phase 2 — the structured input a [SensitiveOperationPolicy] decides
/// from. Every field is something the SDK already computed elsewhere; this
/// type only assembles them into one snapshot for one decision.
///
/// ## What this deliberately cannot carry
///
/// No passwords, private keys, API keys, raw attestation tokens, or licence
/// secrets. This is structural, not a convention to remember: every field
/// below is a plain identifier, an enum, a digest (a SHA-256 hex string,
/// never the raw fields it was computed from), or a timestamp — there is no
/// field of type `String` that could hold a secret without obviously
/// misusing a differently-named field. Mirrors the same discipline
/// `SecurityEvent` already applies to its evidence.
class SensitiveOperationContext {
  /// The host app's identifier for this operation instance — a UUID or
  /// equivalent, not interpreted by the SDK.
  final String operationId;

  /// The host app's label for the *kind* of operation, e.g. `'transfer'`,
  /// `'add_beneficiary'`. Not interpreted — the SDK only uses it as one of
  /// the fields bound into the transaction digest.
  final String operationType;

  /// The SHA-256 hex digest of the operation's security-critical fields —
  /// `TransactionDigest.sha256Hex`, produced by the caller from a
  /// `SecureTransactionContext`. The raw fields (amount, recipient, ...)
  /// never appear on this type; only their digest does.
  final String transactionDigest;

  /// 0–100, from the same `RiskAssessment` the rest of the SDK already
  /// computed this scan cycle. `null` when no risk evaluation has run yet.
  final int? riskScore;

  final RiskPosture? riskPosture;

  final TrustLevel? trustLevel;

  /// The device-binding verdict for the seat this operation would execute
  /// under. `null` only when binding has never been evaluated (should not
  /// happen post-activation; treated as [DeviceBindingVerdict.keyUnavailable]
  /// by policy, never as an implicit pass).
  final DeviceBindingVerdict? deviceBindingState;

  final AttestationStatus? attestationState;

  final OfflineComplianceState? offlineState;

  /// Whether this operation's step-up requirement, if any, has been
  /// satisfied. Derived by `SensitiveOperationAuthorizer`, never set
  /// directly from a raw credential.
  final OperationAuthenticationState authenticationState;

  /// When this context was assembled, UTC.
  final DateTime timestamp;

  /// Single-use value for this evaluation. Distinct from the transaction's
  /// own nonce (`ProtectedOperationRequest.nonce`, covered by
  /// [transactionDigest] already) — this one scopes *this authorization
  /// attempt*, so two evaluations of the identical operation still produce
  /// distinguishable context nonces.
  final String nonce;

  /// The sensitivity the host app declared for this operation. See
  /// `operation_sensitivity.dart` for why this is not a threat severity.
  final OperationSensitivity sensitivity;

  const SensitiveOperationContext({
    required this.operationId,
    required this.operationType,
    required this.transactionDigest,
    required this.authenticationState,
    required this.timestamp,
    required this.nonce,
    required this.sensitivity,
    this.riskScore,
    this.riskPosture,
    this.trustLevel,
    this.deviceBindingState,
    this.attestationState,
    this.offlineState,
  });

  /// The canonical, delimiter-safe string this context's identity is bound
  /// by — used both as evidence and, by `SensitiveOperationAuthorizer`, as
  /// part of the signed authorization payload. Mirrors every other
  /// canonical-message constructor in this SDK
  /// (`DeviceProof`/`RequestSigner`): `|`-delimited, every field checked by
  /// [CanonicalField.assertSafe], absent optional fields written as `-`.
  String canonicalIdentity() {
    String f(String name, String? value) =>
        CanonicalField.assertSafe(name, value ?? '-');
    return [
      f('operation_id', operationId),
      f('operation_type', operationType),
      f('transaction_digest', transactionDigest),
      f('sensitivity', sensitivity.wireName),
      f('timestamp', timestamp.toUtc().toIso8601String()),
      f('nonce', nonce),
    ].join(canonicalDelimiter);
  }

  Map<String, Object?> toMap() => {
        'operation_id': operationId,
        'operation_type': operationType,
        'transaction_digest': transactionDigest,
        'risk_score': riskScore,
        'risk_posture': riskPosture?.wireName,
        'trust_level': trustLevel?.wireName,
        'device_binding_state': deviceBindingState?.name,
        'attestation_state': attestationState?.wireName,
        'offline_state': offlineState?.name,
        'authentication_state': authenticationState.wireName,
        'timestamp': timestamp.toUtc().toIso8601String(),
        'nonce': nonce,
        'sensitivity': sensitivity.wireName,
      };
}
