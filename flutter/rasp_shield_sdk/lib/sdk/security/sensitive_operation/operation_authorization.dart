import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../../device/canonical_field.dart';

/// Phase 7 — the lifetime states of one [SensitiveOperationAuthorization].
enum AuthorizationState {
  /// No authorization has been issued for this operation yet.
  notAuthorized,

  /// Issued, unexpired, unconsumed, and every bound field still matches.
  authorized,

  /// Issued, but [SensitiveOperationAuthorization.expiresAt] has passed.
  expired,

  /// Explicitly revoked before use (e.g. the host app cancelled the flow).
  revoked,

  /// Presented, but a bound field does not match what verification
  /// observes now (wrong device, wrong application, changed digest,
  /// mutated operation id/type, or a corrupt/forged signature) — or the
  /// single-use nonce was already consumed. **Distinct from `expired`**: an
  /// operator or an analyst reading a security event needs to know whether
  /// a legitimate authorization simply aged out, or whether someone tried
  /// to reuse or mutate one.
  invalid,
}

/// Why a [AuthorizationState.invalid] verdict was reached — finer-grained
/// than the five lifecycle states Phase 7 defines, and deliberately kept
/// out of [AuthorizationState] itself so that enum stays exactly the five
/// states the milestone specifies. Used only to let a caller (e.g.
/// `SecurityEventCenter`) distinguish `SENSITIVE_OPERATION_TAMPERED` from
/// `SENSITIVE_OPERATION_REPLAYED` for the security-event trail — the
/// authorization decision itself (never proceed) is identical either way.
enum AuthorizationInvalidReason {
  /// A bound field (operation id/type, digest, device, application) does
  /// not match what was presented at issue time.
  fieldMismatch,

  /// The recomputed signature does not match — the authorization object
  /// itself was reconstructed inconsistently.
  signatureMismatch,

  /// The nonce was already consumed by a prior verification.
  nonceReused,
}

extension AuthorizationStateX on AuthorizationState {
  String get wireName {
    switch (this) {
      case AuthorizationState.notAuthorized:
        return 'NOT_AUTHORIZED';
      case AuthorizationState.authorized:
        return 'AUTHORIZED';
      case AuthorizationState.expired:
        return 'EXPIRED';
      case AuthorizationState.revoked:
        return 'REVOKED';
      case AuthorizationState.invalid:
        return 'INVALID';
    }
  }

  /// `true` only for [AuthorizationState.authorized]. Written as an
  /// explicit getter, exactly like `SecurityEventSequenceState.isTrustworthy`
  /// in the events subsystem, so the fail-safe reading cannot be got wrong
  /// by a caller writing `== authorized` in one place and something looser
  /// elsewhere.
  bool get grantsExecution => this == AuthorizationState.authorized;
}

/// Phase 6/7 — a short-lived, single-use, cryptographically bound grant to
/// execute exactly one operation.
///
/// ## What binds it (Phase 6)
///
/// [operationId], [operationType], [transactionDigest], [deviceBindingId],
/// [applicationId], [issuedAt] and [nonce] are all covered by [signature].
/// Changing **any** covered field between issue and verification changes the
/// canonical message the signature was computed over, which
/// `SensitiveOperationAuthorizer.verify` detects as a signature mismatch —
/// [AuthorizationState.invalid], never a silent pass. This is the same
/// "the SDK never mutates covered fields, canonicalization proves it"
/// discipline `TransactionDigest`/`SecureTransactionContext` already use.
///
/// ## Why short-lived (Phase 7)
///
/// [expiresAt] is set by the authorizer from a policy-configured lifetime
/// (default 2 minutes — long enough for a host app to complete an API call,
/// short enough that a leaked authorization object is worthless within
/// minutes). There is no constructor path that produces a
/// permanently-valid authorization.
class SensitiveOperationAuthorization {
  /// Versioned domain separator, mirroring `DeviceProof.domain` — a future
  /// change to what this signature covers is a new tag, never a silent
  /// reinterpretation of an existing one.
  static const String domain = 'RASP-SENSITIVE-OP-AUTH-v1';

  final String operationId;
  final String operationType;
  final String transactionDigest;

  /// The device-key id (`DeviceKeyInfo.keyId`) this authorization was issued
  /// under, or `null` on an unbound device. Phase 11's binding: verification
  /// on a different device (a different `keyId`, or a bound authorization
  /// presented on an unbound device or vice versa) fails as
  /// [AuthorizationState.invalid].
  final String? deviceBindingId;

  final String applicationId;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final String nonce;
  final String signature;

  /// Set by `SensitiveOperationAuthorizer.revoke`. Checked before anything
  /// else at verification time.
  bool _revoked = false;
  bool get isRevoked => _revoked;
  void markRevoked() => _revoked = true;

  SensitiveOperationAuthorization({
    required this.operationId,
    required this.operationType,
    required this.transactionDigest,
    required this.deviceBindingId,
    required this.applicationId,
    required this.issuedAt,
    required this.expiresAt,
    required this.nonce,
    required this.signature,
  });

  /// The exact string [signature] is computed over. `|`-delimited,
  /// delimiter-checked via [CanonicalField.assertSafe] on every field —
  /// identical discipline to every other canonical message in this SDK.
  /// Absent [deviceBindingId] is written as `-`, so an authorization issued
  /// on an unbound device can never canonicalise identically to one bound to
  /// a device whose key id happens to be empty (which cannot occur — key ids
  /// are always 64 hex chars — but the sentinel discipline is applied
  /// uniformly regardless).
  static String canonicalMessage({
    required String operationId,
    required String operationType,
    required String transactionDigest,
    required String? deviceBindingId,
    required String applicationId,
    required DateTime issuedAt,
    required String nonce,
  }) {
    String f(String name, String? value) =>
        CanonicalField.assertSafe(name, value ?? '-');
    return [
      domain,
      f('operation_id', operationId),
      f('operation_type', operationType),
      f('transaction_digest', transactionDigest),
      f('device_binding_id', deviceBindingId),
      f('application_id', applicationId),
      f('issued_at', issuedAt.toUtc().toIso8601String()),
      f('nonce', nonce),
    ].join(canonicalDelimiter);
  }

  /// HMAC-SHA256(activationToken, canonicalMessage) — the same primitive
  /// `TransactionAuthenticator`/`RequestSigner` already use, keyed on the
  /// same device- and licence-bound `activationToken`. No new signing
  /// mechanism.
  static String sign({
    required String activationToken,
    required String message,
  }) =>
      Hmac(sha256, utf8.encode(activationToken))
          .convert(utf8.encode(message))
          .toString();

  Map<String, Object?> toMap() => {
        'operation_id': operationId,
        'operation_type': operationType,
        'transaction_digest': transactionDigest,
        'device_binding_id': deviceBindingId,
        'application_id': applicationId,
        'issued_at': issuedAt.toUtc().toIso8601String(),
        'expires_at': expiresAt.toUtc().toIso8601String(),
        'nonce': nonce,
        'revoked': _revoked,
      };
}
