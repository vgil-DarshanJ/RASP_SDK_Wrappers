import 'dart:convert';

import 'package:device_info_plus/device_info_plus.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';
import 'package:package_info_plus/package_info_plus.dart';

import 'activation_manager.dart';
import 'core/core.dart';
import 'device_identity.dart';
import 'license_manager.dart';
import 'license_models.dart';
import 'remote_config_manager.dart';
import 'scan_telemetry_mapper.dart';
import 'sdk_config.dart';
import 'security/request_signer.dart';

/// Server-side scoring of a reported threat payload.
class TelemetryResult {
  final int score;
  final String riskLevel;
  final String summary;
  final List<String> activeThreats;

  const TelemetryResult({
    required this.score,
    required this.riskLevel,
    this.summary = '',
    this.activeThreats = const [],
  });
}

/// Ships detection results to the backend for scoring, AI explanation, and
/// SOC-dashboard visibility.
///
/// Reporting is doubly gated: the license must grant the `telemetry`
/// entitlement, and the operator's remote config must have `report_telemetry`
/// switched on. Failures never propagate — telemetry must not break the app.
///
/// Depends only on SDK Core (`sdk/core/`) for detection data — no
/// `rasp_check_model.dart`, no demo-specific or UI-layer model. A caller
/// with SDK Core [DetectionResult]s goes through [reportDetections]; a
/// caller that already has the backend's flat boolean-flag shape (e.g.
/// [ScanTelemetryMapper]'s output) goes through [reportLiveScan] directly.
/// Both funnel into the same transport ([_analyze]), so the wire payload is
/// identical either way.
///
/// Three entry points:
///  * [reportDetections] — the **SDK-native** path. Takes plain
///    [DetectionResult]s and maps them to backend flags itself via
///    [ScanTelemetryMapper.threatFlagsFromDetections].
///  * [reportLiveScan] — the **live** path. Called by
///    [SecurityCenterController] when a real Security Center scan completes.
///    This is the code that actually feeds the dashboards today.
///  * [reportLegacyFlags] — the **legacy/dead** path, retained only for the
///    orphaned `RaspService` detector via `LegacyTelemetryAdapter` (see
///    `rasp/legacy_telemetry_adapter.dart`), which converts the orphaned
///    `RaspCheckResult` into the same flag shape so this file never needs to
///    import `rasp_check_model.dart`.
class TelemetryManager {
  /// Receive budget for `/security/analyze`.
  ///
  /// Deliberately longer than [SdkConfig.networkTimeout], which is tuned for
  /// licensing calls that return in milliseconds. Ingesting a scan also runs the
  /// server's AI narration, which legitimately takes longer than that budget —
  /// at the licensing timeout the device logged `ANALYZE FAIL [receive timeout]`
  /// and treated the scan as lost even though the server had already scored and
  /// stored it. Connect timeout stays short: an unreachable host should still
  /// fail fast.
  static const Duration _analyzeReceiveTimeout = Duration(seconds: 45);

  static final Dio _dio = Dio(
    BaseOptions(
      baseUrl: SdkConfig.securityApiBaseUrl,
      connectTimeout: SdkConfig.networkTimeout,
      receiveTimeout: _analyzeReceiveTimeout,
      headers: {'Content-Type': 'application/json'},
      validateStatus: (_) => true,
    ),
  );

  static bool get isEnabled =>
      LicenseManager.allows(Entitlement.telemetry) &&
      RemoteConfigManager.reportTelemetry;

  /// Report a completed **live** Security Center scan — the source of truth
  /// ([SecurityCenterController] / [SecurityCatalog]).
  ///
  /// [threatFlags] is the backend flag map produced by [ScanTelemetryMapper]
  /// from the scan's per-feature outcomes. Device metadata (model, OS, app
  /// version) is attached when it can be read, satisfying the backend's
  /// optional profiling fields without changing the schema. Best-effort:
  /// returns the server's assessment, or `null` when reporting is disabled,
  /// the device is not activated, the backend is unreachable, or the call is
  /// rejected.
  ///
  /// Signature is `Future<void>`-compatible so it can be used directly as the
  /// default `ScanReporter` on [SecurityCenterController]; the return value is
  /// still available to any caller that wants the server score.
  static Future<TelemetryResult?> reportLiveScan(
    Map<String, bool> threatFlags,
  ) async {
    // Gate BEFORE touching secure storage / platform channels / the network, so
    // an unlicensed or not-yet-activated device (the common case at launch, and
    // every unit test) is a cheap no-op.
    if (!isEnabled) return null;

    final activationToken = await LicenseManager.activationToken;
    if (activationToken == null || activationToken.isEmpty) return null;

    final deviceId = await DeviceIdentity.get();
    final meta = await _deviceMetadata();

    return _analyze({
      'device_id': deviceId,
      'license_key_hash': ActivationManager.licenseKeyHash,
      'activation_token': activationToken,
      ...threatFlags,
      // Device metadata is optional on the backend; only include what we could
      // actually read so a value never lies.
      if (meta['device_model'] != null) 'device_model': meta['device_model'],
      if (meta['os_version'] != null) 'os_version': meta['os_version'],
      if (meta['app_version'] != null) 'app_version': meta['app_version'],
    });
  }

  /// SDK-native entry point: report a scan already expressed as SDK Core
  /// [DetectionResult]s, keyed by `detectorId` via
  /// [ScanTelemetryMapper.threatFlagsFromDetections], then shipped through the
  /// exact same transport as [reportLiveScan] — the backend payload produced
  /// is byte-for-byte identical to passing the equivalent flag map directly.
  ///
  /// This is the path future detectors should use once they are migrated to
  /// return [DetectionResult] instead of the UI-shaped `FeatureOutcome`.
  static Future<TelemetryResult?> reportDetections(
    List<DetectionResult> detections,
  ) {
    _traceDetections(detections);
    final byDetectorId = {for (final d in detections) d.detectorId: d};
    return reportLiveScan(
      ScanTelemetryMapper.threatFlagsFromDetections(byDetectorId),
    );
  }

  /// Debug-only visibility into a [reportDetections] call: how many findings
  /// came in, how many were real threats, the worst [DetectionSeverity]
  /// among them, which [ThreatCategory]/[DetectorType] fired, and their
  /// [DetectionEvidence]. Never affects the payload — purely diagnostic,
  /// matching the `[RASP-TRACE]` convention already used by [_analyze] and
  /// `activation_manager.dart`.
  static void _traceDetections(List<DetectionResult> detections) {
    final threats = detections.where((d) => d.threatDetected).toList();
    final DetectionSeverity? highest = threats.isEmpty
        ? null
        : threats
            .map((d) => d.severity)
            .reduce((a, b) => a.index > b.index ? a : b);
    debugPrint('[RASP-TRACE] ANALYZE detections=${detections.length} '
        'threats=${threats.length} highestSeverity=${highest?.name} '
        'categories=${threats.map((d) => d.category.name).toSet()} '
        'types=${threats.map((d) => d.detectorType.name).toSet()} '
        'evidence=${threats.expand((d) => d.evidence).toList()}');
  }

  /// LEGACY / DEAD PATH — do not extend.
  ///
  /// Accepts a pre-computed backend flag map instead of the orphaned
  /// `RaspCheckResult` (the model produced by `RaspService.runChecks()` in
  /// `lib/rasp/rasp_service.dart`), so this file has no dependency on
  /// `rasp_check_model.dart`. `RaspCheckResult` → flag-map conversion lives in
  /// `LegacyTelemetryAdapter` (`rasp/legacy_telemetry_adapter.dart`), which is
  /// the only caller. The live app reports through [reportLiveScan] /
  /// [reportDetections]. When `RaspService` is deleted in a later cleanup,
  /// delete this method and its adapter too.
  /// [supplementary] carries non-boolean, additive fields (currently
  /// `unconfirmed_checks`) that the backend schema does not declare.
  /// `ThreatAnalysisRequest` does not set `extra="forbid"`, so Pydantic
  /// ignores them and an older backend behaves exactly as before.
  static Future<TelemetryResult?> reportLegacyFlags(
    Map<String, bool> flags, {
    Map<String, dynamic> supplementary = const {},
  }) async {
    if (!isEnabled) return null;

    final activationToken = await LicenseManager.activationToken;
    if (activationToken == null || activationToken.isEmpty) return null;

    final deviceId = await DeviceIdentity.get();
    return _analyze({
      'device_id': deviceId,
      'license_key_hash': ActivationManager.licenseKeyHash,
      'activation_token': activationToken,
      ...flags,
      ...supplementary,
    });
  }

  /// Shared transport: POST the assembled payload to `/security/analyze` and
  /// parse the server's risk assessment. Never throws — offline or a backend
  /// error simply yields `null` (detection already happened on-device).
  static Future<TelemetryResult?> _analyze(Map<String, dynamic> payload) async {
    final sw = Stopwatch()..start();
    try {
      final activationToken = payload['activation_token'] as String?;
      final bodyJson = jsonEncode(payload);
      final options = activationToken == null || activationToken.isEmpty
          ? null
          : Options(
              contentType: 'application/json',
              headers: RequestSigner.sign(
                activationToken: activationToken,
                method: 'POST',
                path: '/api/v1/security/analyze',
                bodyBytes: utf8.encode(bodyJson),
              ),
            );
      final res = await _dio.post<dynamic>(
        '/security/analyze',
        data: options == null ? payload : bodyJson,
        options: options,
      );
      sw.stop();
      final ok = res.statusCode == 200;
      // payload/response carry license_key_hash/activation_token — debug-only.
      if (kDebugMode) {
        debugPrint('[RASP-TRACE] ANALYZE ${ok ? "PASS" : "FAIL"} '
            'url=${_dio.options.baseUrl}/security/analyze status=${res.statusCode} '
            'time=${sw.elapsedMilliseconds}ms');
        debugPrint('[RASP-TRACE] ANALYZE request=$payload');
        debugPrint('[RASP-TRACE] ANALYZE response=${res.data}');
      }
      if (res.statusCode != 200 || res.data is! Map) return null;

      final body = Map<String, dynamic>.from(res.data as Map);
      return TelemetryResult(
        score: (body['score'] as num?)?.toInt() ?? 0,
        riskLevel: (body['risk'] as String?) ?? 'LOW',
        summary: (body['summary'] as String?) ?? '',
        activeThreats: (body['active_threats'] as List?)
                ?.map((e) => e.toString())
                .toList() ??
            const [],
      );
    } catch (e) {
      sw.stop();
      // TEMPORARY — see the matching note in activation_manager.dart.
      if (kDebugMode) {
        debugPrint('[RASP-TRACE] ANALYZE FAIL url=${_dio.options.baseUrl}/security/analyze '
            'error=$e time=${sw.elapsedMilliseconds}ms');
      }
      // Offline or backend down — detection already happened on-device.
      return null;
    }
  }

  /// Best-effort device descriptors for the telemetry payload, in the same
  /// format activation already sends (manufacturer folded into `device_model`).
  /// Never throws: any value that cannot be read (non-Android, or platform
  /// channels unavailable e.g. in a unit test) is returned as `null`, so
  /// telemetry degrades to flags-only rather than failing.
  static Future<Map<String, String?>> _deviceMetadata() async {
    String? deviceModel;
    String? osVersion;
    String? appVersion;

    try {
      if (!kIsWeb && defaultTargetPlatform == TargetPlatform.android) {
        final info = await DeviceInfoPlugin().androidInfo;
        deviceModel = '${info.manufacturer} ${info.model}'.trim();
        osVersion =
            'Android ${info.version.release} (API ${info.version.sdkInt})';
      }
    } catch (_) {
      // Leave device_model / os_version null.
    }

    try {
      final pkg = await PackageInfo.fromPlatform();
      appVersion = pkg.version;
    } catch (_) {
      // Leave app_version null.
    }

    return {
      'device_model': deviceModel,
      'os_version': osVersion,
      'app_version': appVersion,
    };
  }
}
