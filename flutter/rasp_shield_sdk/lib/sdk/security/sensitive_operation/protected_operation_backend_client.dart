import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../../activation_manager.dart';
import '../../sdk_config.dart';
import '../request_signer.dart';
import 'backend_verification_outcome.dart';
import 'operation_authorization.dart';

/// Phase 2 — the network half of backend authorization verification.
///
/// Deliberately shaped like `SecurityEventReporter`, the closest and most
/// recent precedent in this codebase: a hardcoded static [Dio] instance on
/// [SdkConfig.sdkApiBaseUrl] (never a hardcoded host), the same
/// [RequestSigner.sign] + [ActivationManager.deviceProofHeadersFor] header
/// assembly every authenticated SDK request already uses, the same
/// `validateStatus: (_) => true` (so an error response is read as data, not
/// thrown as an exception), and the same never-let-a-transport-detail-leak
/// contract — every failure mode collapses to
/// [BackendVerificationOutcome.unavailable], never a rethrown exception.
///
/// This class does not decide what an outcome means — [interpretResponse]
/// (in `backend_verification_outcome.dart`) is the pure function that does,
/// and is exhaustively unit-tested without any network involved. This class
/// is only responsible for constructing the one real HTTP call correctly.
class ProtectedOperationBackendClient {
  ProtectedOperationBackendClient({Dio? dio})
      : _dio = dio ??
            Dio(
              BaseOptions(
                baseUrl: SdkConfig.sdkApiBaseUrl,
                connectTimeout: SdkConfig.networkTimeout,
                receiveTimeout: SdkConfig.networkTimeout,
                sendTimeout: SdkConfig.networkTimeout,
                headers: {'Content-Type': 'application/json'},
                validateStatus: (_) => true,
              ),
            );

  final Dio _dio;

  /// Phase 3 — sends only the fields the backend contract requires: the
  /// standard auth trio plus [authorization]'s own nine bound fields.
  /// **No** client-computed risk score, trust level, or final action is
  /// ever included — there is no field here to put one in, by construction,
  /// mirroring the backend's own `ProtectedOperationVerifyRequest`, which
  /// has no such field either (see the audit doc §3).
  Future<BackendVerificationOutcome> verify({
    required SensitiveOperationAuthorization authorization,
    required String licenseKeyHash,
    required String deviceId,
    required String activationToken,
  }) async {
    try {
      final body = {
        'license_key_hash': licenseKeyHash,
        'device_id': deviceId,
        'activation_token': activationToken,
        'operation_id': authorization.operationId,
        'operation_type': authorization.operationType,
        'transaction_digest': authorization.transactionDigest,
        'device_binding_id': authorization.deviceBindingId,
        'application_id': authorization.applicationId,
        'issued_at': authorization.issuedAt.toUtc().toIso8601String(),
        'expires_at': authorization.expiresAt.toUtc().toIso8601String(),
        'nonce': authorization.nonce,
        'signature': authorization.signature,
      };
      final bodyJson = jsonEncode(body);
      final bodyBytes = utf8.encode(bodyJson);
      const path = '/protected-operations/verify';
      const signedPath = '/api/v1/sdk/protected-operations/verify';
      final signatureHeaders = RequestSigner.sign(
        activationToken: activationToken,
        method: 'POST',
        path: signedPath,
        bodyBytes: bodyBytes,
      );
      final proofHeaders = await ActivationManager.deviceProofHeadersFor(
        method: 'POST',
        path: signedPath,
        bodyBytes: bodyBytes,
        signatureHeaders: signatureHeaders,
      );

      final response = await _dio.post<dynamic>(
        path,
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: {...signatureHeaders, ...proofHeaders},
        ),
      );

      final decoded = response.data;
      final outcome = interpretBackendResponse(
        statusCode: response.statusCode,
        body: decoded is Map ? Map<String, Object?>.from(decoded) : null,
      );
      debugPrint('[RASP-TRACE] PROTECTED-OP-VERIFY '
          'status=${response.statusCode} outcome=${outcome.wireName}');
      return outcome;
    } catch (e) {
      // Timeout, connection failure, DNS failure, or any other transport
      // exception — never rethrown, never interpreted as authorized. See
      // `docs/PROTECTED_OPERATION_END_TO_END_AUDIT.md` §5 for the fail-safe
      // policy this feeds into.
      debugPrint('[RASP-TRACE] PROTECTED-OP-VERIFY FAIL error=${e.runtimeType}');
      return BackendVerificationOutcome.unavailable;
    }
  }
}
