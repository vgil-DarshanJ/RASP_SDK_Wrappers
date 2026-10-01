import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

/// Generic transaction-security primitives (Phase 7/8 of the API/transaction
/// integrity milestone).
///
/// These are host-app building blocks, not banking features: the SDK never
/// knows what "amount" or "recipient" mean, only that the host app has
/// declared certain fields security-critical and wants tamper-evidence over
/// them. No business logic (payments, transfers, banking rules) lives here.

/// A security-critical snapshot of one host-app operation, supplied
/// entirely by the caller.
///
/// The SDK never mutates [fields] — [TransactionDigest.of] only reads them.
/// "The SDK must not silently modify business data" is enforced by
/// construction: there is no setter anywhere in this file.
class SecureTransactionContext {
  /// Caller-chosen name for the operation, e.g. `"beneficiary_add"`,
  /// `"transfer"`, `"login"`. Not interpreted by the SDK.
  final String operation;

  /// Security-critical fields the caller wants covered by the digest —
  /// typically amount, currency, recipient, timestamp, nonce, or whatever
  /// else the host app decides is tamper-sensitive for this operation.
  /// Values must be JSON-encodable (String/num/bool/null/List/Map).
  final Map<String, Object?> fields;

  const SecureTransactionContext({required this.operation, required this.fields});
}

/// A deterministic, canonical digest over a [SecureTransactionContext].
///
/// Canonicalization: fields are sorted by key before encoding, so the same
/// logical transaction produces the same digest regardless of the map's
/// insertion order — construction order must never change the security
/// verdict.
class TransactionDigest {
  final String operation;
  final String canonicalJson;
  final String sha256Hex;

  const TransactionDigest._(this.operation, this.canonicalJson, this.sha256Hex);

  factory TransactionDigest.of(SecureTransactionContext context) {
    final sortedKeys = context.fields.keys.toList()..sort();
    final canonical = <String, Object?>{
      for (final k in sortedKeys) k: context.fields[k],
    };
    final canonicalJson = jsonEncode({'operation': context.operation, 'fields': canonical});
    final hash = sha256.convert(utf8.encode(canonicalJson)).toString();
    return TransactionDigest._(context.operation, canonicalJson, hash);
  }
}

/// Signs / verifies a [TransactionDigest] using the same device-bound
/// primitive as [RequestSigner] — HMAC-SHA256 keyed on the activation_token.
/// A hardened host app posts `{digest, signature}` (never the raw fields
/// separately) to *its own* backend, which re-derives the digest from the
/// values it already trusts and compares.
class TransactionAuthenticator {
  TransactionAuthenticator._();

  static String sign({
    required String activationToken,
    required TransactionDigest digest,
  }) {
    return Hmac(sha256, utf8.encode(activationToken))
        .convert(utf8.encode(digest.sha256Hex))
        .toString();
  }

  /// Verifies a previously-produced signature against a digest recomputed
  /// from (presumably server-trusted) field values. Returns
  /// [TransactionRiskState.verified] only when the digest's hash matches
  /// *and* the signature matches — either mismatch alone is
  /// [TransactionRiskState.tampered], never silently ignored.
  static TransactionRiskState verify({
    required String activationToken,
    required TransactionDigest expectedDigest,
    required String candidateSha256Hex,
    required String candidateSignature,
  }) {
    if (expectedDigest.sha256Hex != candidateSha256Hex) {
      return TransactionRiskState.tampered;
    }
    final expectedSig = sign(activationToken: activationToken, digest: expectedDigest);
    if (expectedSig != candidateSignature) {
      return TransactionRiskState.tampered;
    }
    return TransactionRiskState.verified;
  }
}

/// One caller-supplied "protected operation" request — the shape a demo
/// (or a real host app) collects from its UI before signing.
///
/// [timestamp] and [nonce] are ordinary caller-supplied fields as far as
/// [TransactionDigest] is concerned (they ride in [SecureTransactionContext.fields]
/// like everything else, so tampering with either is caught the same way
/// as tampering with `amount`); [TransactionOperationGuard] additionally
/// gives them operational meaning — freshness and single-use.
class ProtectedOperationRequest {
  final String operation;
  final num amount;
  final String currency;
  final String recipient;
  final DateTime timestamp;
  final String nonce;

  const ProtectedOperationRequest({
    required this.operation,
    required this.amount,
    required this.currency,
    required this.recipient,
    required this.timestamp,
    required this.nonce,
  });

  SecureTransactionContext toContext() => SecureTransactionContext(
        operation: operation,
        fields: {
          'amount': amount,
          'currency': currency,
          'recipient': recipient,
          'timestamp': timestamp.toIso8601String(),
          'nonce': nonce,
        },
      );
}

/// A signed, ready-to-submit protected operation — what
/// [TransactionOperationGuard.prepare] hands back to the caller.
class SignedOperation {
  final ProtectedOperationRequest request;
  final TransactionDigest digest;
  final String signature;

  const SignedOperation({
    required this.request,
    required this.digest,
    required this.signature,
  });
}

/// The real caller-facing verifier for a [ProtectedOperationRequest] —
/// adds freshness (Phase 9's `EXPIRED`) and single-use (`REPLAYED`) on top
/// of [TransactionAuthenticator]'s pure digest/signature check, exactly the
/// two properties [RequestSigner]/`request_integrity.py` already give
/// server-to-device requests. Same reasoning, applied to a host app's own
/// operation flow.
///
/// Replay tracking is in-memory and per-instance, matching this being a
/// **local reference-app demo caller** — a production host app would check
/// replay against its own backend, the same way `request_nonces` does for
/// SDK requests (see `docs/REQUEST_REPLAY_PROTECTION.md`); nothing here
/// invents a second server-side replay store.
class TransactionOperationGuard {
  TransactionOperationGuard({this.maxAge = const Duration(minutes: 5)});

  final Duration maxAge;

  /// Replay keys of verified operations, mapped to the request timestamp they
  /// were recorded under.
  ///
  /// **Bounded, unlike the plain `Set` this replaced** — a security review
  /// found the original unbounded `Set` was a storage-exhaustion risk.
  /// Entries are pruned once they age past
  /// [maxAge], which is safe for a precise reason: [verify] rejects a request
  /// older than [maxAge] as [TransactionRiskState.expired] *before* it ever
  /// consults this map, so forgetting an aged nonce cannot let a replay
  /// through — the freshness check already refuses it.
  final Map<String, DateTime> _seenOperationNonces = {};

  /// Backstop cap, in case a host app somehow performs more than this many
  /// distinct verified operations inside one [maxAge] window. Eviction here
  /// is oldest-first and is genuinely a trade-off rather than a free win, so
  /// the cap is set far above any plausible legitimate rate: a banking app
  /// doing 4096 verified transactions in five minutes is not a scenario this
  /// guard is designed for, and unbounded growth is the worse failure.
  static const int _maxTrackedNonces = 4096;

  /// **Debug-only fault injection**, for exercising
  /// [TransactionRiskState.error] — the one state nothing in the real
  /// verification logic naturally reaches (every input that could throw is
  /// already caught earlier as a more specific state; see the class doc on
  /// [error]). Deliberately not `@visibleForTesting`: a widget's "Simulate
  /// ERROR" demo button needs to set this from non-test code, gated by
  /// [kDebugMode] instead.
  ///
  /// [kDebugMode] is a compile-time constant, so `verify()`'s check below
  /// — `if (kDebugMode && debugForceInfrastructureError)` — is eliminated
  /// by the compiler in a release/AOT build: the flag can be set (it is a
  /// plain field, not itself guarded), but reading it inside `verify()` is
  /// dead code once `kDebugMode` folds to `false`, so it has **zero**
  /// effect in release regardless of who sets it or to what value. There is
  /// no path from this flag to a production transaction outcome.
  bool debugForceInfrastructureError = false;

  /// Builds and signs a request. Returns `null` (never throws) when
  /// [activationToken] is empty — the caller should treat that as
  /// [TransactionRiskState.unavailable].
  SignedOperation? prepare({
    required ProtectedOperationRequest request,
    required String activationToken,
  }) {
    if (activationToken.isEmpty) return null;
    final digest = TransactionDigest.of(request.toContext());
    final signature = TransactionAuthenticator.sign(
      activationToken: activationToken,
      digest: digest,
    );
    return SignedOperation(request: request, digest: digest, signature: signature);
  }

  /// Verifies a [SignedOperation] against the (possibly re-collected /
  /// possibly tampered) [candidateRequest] the caller is about to execute.
  ///
  /// Order of checks matters, mirroring `request_integrity.py`'s
  /// precedence: structural validity first, then freshness (cheap, no
  /// state mutation), then the cryptographic tamper check, and only once a
  /// request is genuinely [TransactionRiskState.verified] is its nonce
  /// recorded — so a rejected attempt never consumes the single-use budget
  /// a legitimate retry would need.
  /// [onVerified], when supplied, is called once with the outcome before
  /// this method returns it — the live wiring point Security Event
  /// Pipeline milestone Phase 15 uses to record a genuine
  /// `TRANSACTION_TAMPER` event (see `SecurityEventCenter.recordTransactionOutcome`).
  /// Optional and `null` by default so every existing caller and test is
  /// unaffected; this class remains what its own docs already say it is — a
  /// local reference-app demo caller with no live financial-transaction call
  /// site of its own in this codebase.
  TransactionRiskState verify({
    required SignedOperation signed,
    required ProtectedOperationRequest candidateRequest,
    required String activationToken,
    DateTime? now,
    void Function(TransactionRiskState state)? onVerified,
  }) {
    final result = _verifyInternal(
      signed: signed,
      candidateRequest: candidateRequest,
      activationToken: activationToken,
      now: now,
    );
    if (onVerified != null) onVerified(result);
    return result;
  }

  TransactionRiskState _verifyInternal({
    required SignedOperation signed,
    required ProtectedOperationRequest candidateRequest,
    required String activationToken,
    DateTime? now,
  }) {
    try {
      if (kDebugMode && debugForceInfrastructureError) {
        // A real infrastructure fault (a corrupted digest, a crypto library
        // failure) is not something this codebase can *cause* safely on
        // demand — this throws the same shape of error the catch clause
        // below is written to handle, so ERROR is reachable without ever
        // faking a VALID result. Debug-only; see the field doc.
        throw StateError('debugForceInfrastructureError: simulated verification fault');
      }
      if (activationToken.isEmpty) return TransactionRiskState.unavailable;
      if (candidateRequest.operation.isEmpty ||
          candidateRequest.currency.isEmpty ||
          candidateRequest.recipient.isEmpty ||
          candidateRequest.nonce.isEmpty ||
          candidateRequest.amount.isNaN) {
        return TransactionRiskState.invalid;
      }

      final clock = now ?? DateTime.now().toUtc();
      if (clock.difference(candidateRequest.timestamp) > maxAge) {
        return TransactionRiskState.expired;
      }

      final candidateDigest = TransactionDigest.of(candidateRequest.toContext());
      final tamperResult = TransactionAuthenticator.verify(
        activationToken: activationToken,
        expectedDigest: signed.digest,
        candidateSha256Hex: candidateDigest.sha256Hex,
        candidateSignature: signed.signature,
      );
      if (tamperResult != TransactionRiskState.verified) {
        return TransactionRiskState.tampered;
      }

      final replayKey = '${candidateRequest.operation}:${candidateRequest.nonce}';
      if (_seenOperationNonces.containsKey(replayKey)) {
        return TransactionRiskState.replayed;
      }
      _pruneSeenNonces(clock);
      _seenOperationNonces[replayKey] = candidateRequest.timestamp;
      return TransactionRiskState.verified;
    } catch (_) {
      return TransactionRiskState.error;
    }
  }

  /// Number of replay keys currently retained. Exposed so a test can assert
  /// the bound directly rather than inferring it.
  @visibleForTesting
  int get trackedNonceCount => _seenOperationNonces.length;

  void _pruneSeenNonces(DateTime clock) {
    _seenOperationNonces
        .removeWhere((_, recordedAt) => clock.difference(recordedAt) > maxAge);
    while (_seenOperationNonces.length >= _maxTrackedNonces) {
      _seenOperationNonces.remove(_seenOperationNonces.keys.first);
    }
  }
}

/// Outcome of a transaction-integrity check. Mirrors the fail-safe
/// vocabulary used across the trust/risk pipeline (Phase 9): no value here
/// means "probably fine" — a caller must handle every state explicitly.
enum TransactionRiskState {
  /// Digest and signature both verified.
  verified,

  /// Digest or signature mismatch — at least one covered field changed, or
  /// the signature was forged/copied from elsewhere.
  tampered,

  /// The request is structurally unusable (a required field is missing or
  /// the wrong type) — distinct from [tampered], which requires a digest to
  /// compare against in the first place.
  invalid,

  /// The transaction's own `timestamp` field is older than the caller's
  /// configured max age. See [TransactionOperationGuard].
  expired,

  /// This exact `(operation, nonce)` pair was already verified once. See
  /// [TransactionOperationGuard].
  replayed,

  /// Verification could not be attempted (e.g. no activation token yet).
  unavailable,

  /// Verification itself threw.
  error,
}
