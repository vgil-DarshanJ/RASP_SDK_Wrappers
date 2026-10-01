import 'dart:convert';

import 'package:dio/dio.dart';

import 'activation_manager.dart';
import 'device_identity.dart';
import 'license_manager.dart';
import 'sdk_config.dart';
import 'security/request_signer.dart';

/// Thin client for the **existing** remote-command acknowledgement endpoint,
/// `POST /api/v1/sdk/commands/{id}/ack`.
///
/// Reuses exactly the auth the rest of the SDK already sends — the license key
/// hash, the device id, and the activation token — over the same base URL as
/// activation and heartbeat. No new endpoint, no new auth scheme.
class RemoteCommandApi {
  static final Dio _dio = Dio(
    BaseOptions(
      baseUrl: SdkConfig.sdkApiBaseUrl,
      connectTimeout: SdkConfig.networkTimeout,
      receiveTimeout: SdkConfig.networkTimeout,
      headers: {'Content-Type': 'application/json'},
      validateStatus: (_) => true,
    ),
  );

  /// Record the outcome of a delivered command. Best-effort and never throws:
  /// an un-acknowledged command simply stays DELIVERED server-side (the backend
  /// does not re-issue it), so a failed ack never causes re-execution.
  Future<void> acknowledge({
    required int commandId,
    required bool succeeded,
    required String result,
  }) async {
    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) return; // never activated — nothing to prove
    try {
      final deviceId = await DeviceIdentity.get();
      final body = {
        'license_key_hash': ActivationManager.licenseKeyHash,
        'device_id': deviceId,
        'activation_token': token,
        'succeeded': succeeded,
        'result': result,
      };
      final bodyJson = jsonEncode(body);
      final path = '/api/v1/sdk/commands/$commandId/ack';
      await _dio.post<dynamic>(
        '/commands/$commandId/ack',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: RequestSigner.sign(
            activationToken: token,
            method: 'POST',
            path: path,
            bodyBytes: utf8.encode(bodyJson),
          ),
        ),
      );
    } catch (_) {
      // Swallow — see method doc.
    }
  }
}
