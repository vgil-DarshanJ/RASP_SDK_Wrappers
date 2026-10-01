import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../api/api_protection.dart';
import '../api/api_protection_policy.dart';
import '../api/api_request_proof.dart';
import '../activation_manager.dart';
import '../device_identity.dart';
import '../license_manager.dart';
import 'rasp_transaction.dart';

/// A transaction that has been cryptographically bound to a request.
@immutable
class ProtectedTransaction {
  final RaspTransaction transaction;
  final TransactionState state;

  /// Headers to attach to the outbound banking request.
  final Map<String, String> headers;

  /// SHA-256 of the canonical transaction — the value the bank's backend
  /// recomputes from the fields it is about to act on.
  final String? digest;

  final String? requestId;

  /// Why no proof was produced, when [state] is not
  /// [TransactionState.proved].
  final String? reason;

  const ProtectedTransaction({
    required this.transaction,
    required this.state,
    this.headers = const {},
    this.digest,
    this.requestId,
    this.reason,
  });

  bool get isProtected => state == TransactionState.proved;

  /// The body to send to the bank, with the transaction included so their
  /// backend can forward it to verification. Provided as a convenience —
  /// integrators are free to shape their own payload, since verification
  /// takes the transaction fields from the *bank*, not from this body.
  Map<String, Object?> mergeIntoBody(Map<String, Object?> body) => {
        ...body,
        'rasp_transaction': transaction.toVerificationPayload(),
      };
}

/// **RASP Shield Transaction Protection** — proves the business intent, not
/// just the HTTP request.
///
/// ## What this adds over API Protection
///
/// [RaspShieldApi] proves a *request* is authentic: this method, this path,
/// these exact bytes, from this device. That already stops an attacker
/// editing a payload in flight.
///
/// What it cannot do alone is tie the request to what the **user actually
/// approved**. A compromised client could assemble a perfectly valid request
/// for a payment the user never saw. Transaction Protection closes that by
/// making the approved intent — ₹10,000 to beneficiary X — a signed field of
/// the request itself, and having the bank recompute that digest from the
/// fields *it* is about to execute. If the two disagree, the signature does
/// not verify. Nobody has to compare them by hand.
///
/// ## Usage
///
/// ```dart
/// final tx = RaspTransaction(
///   transactionId: 'TX-1001',
///   transactionType: 'transfer',
///   amount: '10000',
///   currency: 'INR',
///   beneficiaryRef: 'BEN-42',
/// );
///
/// final protected = await RaspShield.transactions.protect(
///   transaction: tx,
///   method: 'POST',
///   url: Uri.parse('https://api.bank.com/payments'),
///   bodyBytes: utf8.encode(jsonEncode(payload)),
/// );
///
/// if (protected.isProtected) {
///   await dio.post('/payments', data: payload,
///       options: Options(headers: protected.headers));
/// }
/// ```
///
/// ## What it does not promise
///
/// It cannot prove a human *intended* the transaction — only that the
/// legitimate app on the trusted device produced this exact intent, and that
/// it reached the bank unaltered. A fully compromised device can still be
/// driven to sign something its owner never approved. What disappears is the
/// cheap attack: altering an amount in flight, replaying an approval, or
/// moving a valid proof to another device.
class RaspShieldTransactions {
  const RaspShieldTransactions();

  /// Bind [transaction] to one outbound request and produce the headers.
  static Future<ProtectedTransaction> protectTransaction({
    required RaspTransaction transaction,
    required String method,
    required Uri url,
    List<int> bodyBytes = const [],
  }) async {
    String digest;
    try {
      digest = transaction.digest();
    } on TransactionPrivacyError catch (e) {
      // Surfaced loudly rather than stripped: a credential reaching this
      // layer means the integration has misunderstood what belongs in a
      // transaction, and silently dropping the field would hide that.
      return ProtectedTransaction(
        transaction: transaction,
        state: TransactionState.rejected,
        reason: e.message.toString(),
      );
    } catch (e) {
      return ProtectedTransaction(
        transaction: transaction,
        state: TransactionState.rejected,
        reason: 'transaction could not be canonicalized: $e',
      );
    }

    if (!ApiProtectionPolicy.enabled ||
        !ApiProtectionPolicy.covers(host: url.host, path: url.path)) {
      // Fail-closed and *say so*. Returning "protected" here would be the
      // worst outcome: an integrator would ship believing transactions were
      // covered when policy never enabled them.
      return ProtectedTransaction(
        transaction: transaction,
        state: TransactionState.created,
        digest: digest,
        reason: 'signed policy does not protect ${url.host}${url.path}',
      );
    }

    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) {
      return ProtectedTransaction(
        transaction: transaction,
        state: TransactionState.created,
        digest: digest,
        reason: 'device is not activated',
      );
    }

    final deviceId = await DeviceIdentity.get();
    final applicationId = await ActivationManager.bundleId();
    final timestamp =
        (DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = RaspShieldApi.randomHex(16);
    final requestId = RaspShieldApi.randomHex(16);

    final canonical = ApiRequestProof.canonicalRequest(
      method: method,
      host: url.host,
      path: url.path,
      query: url.query,
      bodyBytes: bodyBytes,
      timestamp: timestamp,
      nonce: nonce,
      requestId: requestId,
      sessionToken: RaspShieldApi.sessionToken,
      transactionDigest: digest,
    );

    final signature = ApiRequestProof.sign(
      activationToken: token,
      canonicalRequestString: canonical,
    );

    final headers = ApiRequestProof.headers(
      timestamp: timestamp,
      nonce: nonce,
      requestId: requestId,
      signature: signature,
      deviceId: deviceId,
      applicationId: applicationId,
      licenseKeyHash: ActivationManager.licenseKeyHash,
      transactionDigest: digest,
    );

    debugPrint('[RASP-TRACE] TX-PROOF bound tx=${transaction.transactionId} '
        'type=${transaction.transactionType} request_id=$requestId');

    return ProtectedTransaction(
      transaction: transaction,
      state: TransactionState.proved,
      headers: headers,
      digest: digest,
      requestId: requestId,
    );
  }

  /// Instance form so `RaspShield.transactions.protect(...)` reads naturally,
  /// mirroring `RaspShield.api` / `RaspShield.ai`.
  Future<ProtectedTransaction> protect({
    required RaspTransaction transaction,
    required String method,
    required Uri url,
    List<int> bodyBytes = const [],
  }) =>
      protectTransaction(
        transaction: transaction,
        method: method,
        url: url,
        bodyBytes: bodyBytes,
      );

  /// Convenience for the common case: a JSON body posted with Dio.
  ///
  /// Encodes the body exactly once and signs those bytes, which removes the
  /// single most common integration error — signing one serialization and
  /// sending a different one.
  Future<ProtectedTransaction> protectJson({
    required RaspTransaction transaction,
    required String method,
    required Uri url,
    required Map<String, Object?> body,
  }) =>
      protectTransaction(
        transaction: transaction,
        method: method,
        url: url,
        bodyBytes: utf8.encode(jsonEncode(body)),
      );
}

/// Sends a protected transaction with Dio, guaranteeing the signed bytes are
/// the sent bytes.
///
/// Provided because the alternative — encode, sign, then hand the *object*
/// to Dio and let it re-encode — is the error every integration makes once.
extension RaspTransactionDio on Dio {
  Future<Response<T>> postProtectedTransaction<T>(
    String path, {
    required RaspTransaction transaction,
    required Map<String, Object?> body,
    Options? options,
  }) async {
    final encoded = jsonEncode(body);
    final url = Uri.parse(options?.extra?['rasp_full_url'] as String? ??
        '${this.options.baseUrl}$path');

    final protected = await RaspShieldTransactions.protectTransaction(
      transaction: transaction,
      method: 'POST',
      url: url,
      bodyBytes: utf8.encode(encoded),
    );

    final merged = Options(
      headers: {
        ...?options?.headers,
        ...protected.headers,
        Headers.contentTypeHeader: Headers.jsonContentType,
      },
      extra: options?.extra,
      responseType: options?.responseType,
      validateStatus: options?.validateStatus,
    );
    // The already-encoded String is sent, not the Map — so Dio cannot
    // re-serialize it into different bytes than the ones that were signed.
    return post<T>(path, data: encoded, options: merged);
  }
}
