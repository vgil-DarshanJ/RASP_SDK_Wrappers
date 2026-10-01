import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../activation_manager.dart';
import '../device_identity.dart';
import '../license_manager.dart';
import '../sdk_config.dart';
import '../security/request_signer.dart';
import '../tls/tls_pinning_dio.dart';
import 'security_event_center.dart';

/// Phase 4/5 — the transport half of the live security-event path.
///
/// Deliberately shaped like `DeviceLogReporter`, not a new design: no timer
/// of its own (`RaspSdk.initialize`/`refresh`/the heartbeat tick call
/// [flush]), the same self-gating on license state and activation token, the
/// same never-throw contract, and the same authentication —
/// [RequestSigner.sign] for the HMAC headers every post-activation endpoint
/// already requires, plus [ActivationManager.deviceProofHeadersFor] for the
/// device-key signature when this device has one. No new signing mechanism.
///
/// `SecurityEventCenter.drainNextBatch()` already applied
/// [SecurityEventQueue]'s bounds, priority-aware eviction and expiry — this
/// class only has to ship what it is handed and report success/failure back.
class SecurityEventReporter {
  SecurityEventReporter._();

  static final SecurityEventReporter instance = SecurityEventReporter._();

  final Dio _dio = _buildDio();

  static Dio _buildDio() {
    final dio = Dio(
      BaseOptions(
        baseUrl: SdkConfig.sdkApiBaseUrl,
        connectTimeout: SdkConfig.networkTimeout,
        receiveTimeout: SdkConfig.networkTimeout,
        sendTimeout: SdkConfig.networkTimeout,
        headers: {'Content-Type': 'application/json'},
        validateStatus: (_) => true,
      ),
    );
    configureTlsPinning(dio);
    return dio;
  }

  /// Ships the next queued batch, if any and if the device may write.
  ///
  /// A no-op exactly when [DeviceLogReporter.flush] is: no activation token,
  /// or a license state that does not grant features (PENDING/BLOCKED/
  /// REVOKED devices may not write telemetry — see `/logs`'s own doc for
  /// why: an unapproved device must not be able to make itself look
  /// approved by appearing on the dashboards).
  Future<void> flush() async {
    if (!LicenseManager.status.value.grantsFeatures) return;
    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) return;

    final batch = await SecurityEventCenter.drainNextBatch();
    if (batch == null) return;

    try {
      final deviceId = await DeviceIdentity.get();
      final body = {
        'license_key_hash': ActivationManager.licenseKeyHash,
        'device_id': deviceId,
        'activation_token': token,
        'chain_head': batch.chainHead,
        'previous_chain_head':
            batch.entries.first.sealed.previousDigest,
        'events': batch.entries.map((e) => e.sealed.toMap()).toList(),
      };
      final bodyJson = jsonEncode(body);
      final bodyBytes = utf8.encode(bodyJson);
      final signatureHeaders = RequestSigner.sign(
        activationToken: token,
        method: 'POST',
        path: '/api/v1/sdk/security-events',
        bodyBytes: bodyBytes,
      );
      final proofHeaders = await ActivationManager.deviceProofHeadersFor(
        method: 'POST',
        path: '/api/v1/sdk/security-events',
        bodyBytes: bodyBytes,
        signatureHeaders: signatureHeaders,
      );

      final response = await _dio.post<dynamic>(
        '/security-events',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: {...signatureHeaders, ...proofHeaders},
        ),
      );

      if (response.statusCode == 200) {
        await SecurityEventCenter.acknowledge(batch);
        debugPrint('[RASP-TRACE] SECURITY-EVENTS PASS '
            'status=${response.statusCode} count=${batch.entries.length}');
      } else {
        await SecurityEventCenter.markFailed(batch);
        debugPrint('[RASP-TRACE] SECURITY-EVENTS FAIL '
            'status=${response.statusCode} count=${batch.entries.length}');
      }
    } catch (e) {
      // Offline, or the request itself failed — return the batch to the
      // queue rather than losing it. Never rethrow: telemetry must not be
      // able to surface as an app-visible failure. See Phase 14: telemetry
      // failure must never weaken local protection, which has already run
      // and already decided by the time this method is ever called.
      await SecurityEventCenter.markFailed(batch);
      debugPrint('[RASP-TRACE] SECURITY-EVENTS FAIL error=${e.runtimeType}');
    }
  }
}
