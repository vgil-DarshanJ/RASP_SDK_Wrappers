import 'dart:convert';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'activation_manager.dart';
import 'device_identity.dart';
import 'license_manager.dart';
import 'protection/protection.dart';
import 'security/request_signer.dart';
import 'sdk_config.dart';

/// Ships one [RolloutObservation] to
/// `POST /api/v1/sdk/risk-pipeline/observation`.
///
/// ## Observability only — never a decision input
///
/// Nothing this class sends is ever read back to change what the SDK does.
/// The device has already decided and already acted by the time this runs;
/// this exists so an operator can see whether a staged rollout is behaving
/// before promoting it further. See `docs/RISK_PIPELINE_MONITORING.md`.
///
/// ## What is sent
///
/// Exactly [RolloutObservation.toMap] plus the standard authentication pair
/// every other SDK endpoint already requires (`license_key_hash`,
/// `activation_token`) and the device id. **No licence key, no attestation
/// token, no fingerprint, no location** — the observation model itself
/// cannot carry them.
///
/// Self-gating and fire-and-forget: an unlicensed device, a device with no
/// activation token, a LEGACY-mode device (nothing to report), or any
/// network failure all resolve to a silent no-op. A monitoring call must
/// never be able to affect or interrupt the scan it is describing.
class RolloutReporter {
  static final Dio _dio = Dio(
    BaseOptions(
      baseUrl: SdkConfig.sdkApiBaseUrl,
      connectTimeout: SdkConfig.networkTimeout,
      receiveTimeout: SdkConfig.networkTimeout,
      sendTimeout: SdkConfig.networkTimeout,
      headers: {'Content-Type': 'application/json'},
      validateStatus: (_) => true,
    ),
  );

  /// Reports [observation], or does nothing when there is nothing to report.
  static Future<void> report(RolloutObservation? observation) async {
    if (observation == null) return;
    if (!LicenseManager.status.value.grantsFeatures) return;

    try {
      final activationToken = await LicenseManager.activationToken;
      if (activationToken == null || activationToken.isEmpty) return;

      final deviceId = await DeviceIdentity.get();
      final body = {
        'license_key_hash': ActivationManager.licenseKeyHash,
        'device_id': deviceId,
        'activation_token': activationToken,
        ...observation.toMap(),
      };
      final bodyJson = jsonEncode(body);
      final res = await _dio.post<dynamic>(
        '/risk-pipeline/observation',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: RequestSigner.sign(
            activationToken: activationToken,
            method: 'POST',
            path: '/api/v1/sdk/risk-pipeline/observation',
            bodyBytes: utf8.encode(bodyJson),
          ),
        ),
      );
      debugPrint(
        '[RASP-TRACE] ROLLOUT-OBS ${res.statusCode == 200 ? "PASS" : "FAIL"} '
        'status=${res.statusCode} mode=${observation.mode.wireName} '
        'disagreement=${observation.disagreement.wireName}',
      );
    } catch (e) {
      // Monitoring is best-effort by design.
      debugPrint('[RASP-TRACE] ROLLOUT-OBS FAIL error=${e.runtimeType}');
    }
  }
}
