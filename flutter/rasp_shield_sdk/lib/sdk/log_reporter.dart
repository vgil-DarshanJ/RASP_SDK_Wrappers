import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import 'device_identity.dart';
import 'license_manager.dart';
import 'security/request_signer.dart';
// LicenseStateX.grantsFeatures — the active/grace test [flush] gates on.
import 'license_models.dart';
import 'sdk_config.dart';

/// Severity of one buffered log line. Mirrors the levels the backend's
/// `device_logs` table accepts (`Ai/backend/app/api/sdk_router.py`) — an
/// unrecognised value on the wire simply folds to INFO server-side, so this
/// enum can grow without a breaking change on either end.
enum RaspLogLevel { debug, info, warning, error, fatal }

extension _RaspLogLevelWire on RaspLogLevel {
  String get wire => switch (this) {
        RaspLogLevel.debug => 'DEBUG',
        RaspLogLevel.info => 'INFO',
        RaspLogLevel.warning => 'WARNING',
        RaspLogLevel.error => 'ERROR',
        RaspLogLevel.fatal => 'FATAL',
      };
}

class _BufferedLogEntry {
  final RaspLogLevel level;
  final String tag;
  final String message;
  final Map<String, dynamic>? metadata;
  final DateTime capturedAt;
  const _BufferedLogEntry(
    this.level,
    this.tag,
    this.message,
    this.metadata,
    this.capturedAt,
  );
}

/// Buffers structured log lines from the SDK — and, optionally, the host
/// app via `RaspSdk.log` — and ships them to `POST /api/v1/sdk/logs` on the
/// **existing** heartbeat cadence (see `RaspSdk._scheduleHeartbeat`). No
/// second timer: this mirrors how remote commands already ride the
/// heartbeat instead of polling separately.
///
/// Never throws: a logging call must never be the thing that crashes the
/// host app, and a failed flush silently keeps entries buffered for the
/// next attempt. The buffer is capped so a long offline stretch — or a host
/// app that logs in a tight loop — cannot grow it without bound; the oldest
/// entries are dropped first, since the most recent context around an
/// incident matters most.
class DeviceLogReporter {
  DeviceLogReporter._();

  /// Single app-wide instance, matching [LicenseManager]/
  /// `RemoteCommandDispatcher`'s own singleton pattern.
  static final DeviceLogReporter instance = DeviceLogReporter._();

  static const int _maxBufferSize = 200;
  static const int _maxBatchSize = 50;

  final List<_BufferedLogEntry> _buffer = [];

  final Dio _dio = Dio(
    BaseOptions(
      baseUrl: SdkConfig.sdkApiBaseUrl,
      connectTimeout: SdkConfig.networkTimeout,
      receiveTimeout: SdkConfig.networkTimeout,
      sendTimeout: SdkConfig.networkTimeout,
      headers: {'Content-Type': 'application/json'},
      validateStatus: (_) => true,
    ),
  );

  // Computed locally rather than reusing `ActivationManager.licenseKeyHash`
  // to avoid a circular import — `activation_manager.dart`'s own
  // `[RASP-TRACE]` points feed this reporter (see `RaspSdk`/
  // `ActivationManager`), so this file must not import that one back.
  String get _licenseKeyHash =>
      sha256.convert(utf8.encode(SdkConfig.licenseKey.trim())).toString();

  /// Record one log line. Safe to call from anywhere in the SDK, or from the
  /// host app via `RaspSdk.log`/`logInfo`/`logWarning`/`logError` — buffered
  /// in memory until the next heartbeat-triggered [flush].
  void log(RaspLogLevel level, String tag, String message,
      {Map<String, dynamic>? metadata}) {
    _buffer.add(
      _BufferedLogEntry(level, tag, message, metadata, DateTime.now().toUtc()),
    );
    while (_buffer.length > _maxBufferSize) {
      _buffer.removeAt(0);
    }
  }

  void debug(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.debug, tag, message, metadata: metadata);

  void info(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.info, tag, message, metadata: metadata);

  void warning(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.warning, tag, message, metadata: metadata);

  void error(String tag, String message, {Map<String, dynamic>? metadata}) =>
      log(RaspLogLevel.error, tag, message, metadata: metadata);

  /// Ship up to [_maxBatchSize] buffered entries. Called after every
  /// successful heartbeat cycle — never a standalone timer. A no-op with
  /// nothing buffered, or before the device has ever activated (no
  /// activation token exists yet to authenticate the batch with).
  ///
  /// Also a no-op while the license does not grant features. `POST /sdk/logs`
  /// accepts writes only from an ACTIVE seat — the same rule `/security/analyze`
  /// and location capture enforce — so a PENDING device awaiting approval would
  /// otherwise earn a guaranteed 403 on every heartbeat. Checking the state the
  /// SDK already tracks turns that into no request at all. Nothing is dropped:
  /// entries stay buffered (subject to [_maxBufferSize]) and ship on the first
  /// heartbeat after an administrator approves the device.
  Future<void> flush() async {
    if (_buffer.isEmpty) return;
    if (!LicenseManager.status.value.state.grantsFeatures) return;
    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) return;

    final batch = _buffer.take(_maxBatchSize).toList();
    try {
      final deviceId = await DeviceIdentity.get();
      final body = {
        'license_key_hash': _licenseKeyHash,
        'device_id': deviceId,
        'activation_token': token,
        'logs': batch
            .map((e) => {
                  'level': e.level.wire,
                  'tag': e.tag,
                  'message': e.message,
                  if (e.metadata != null) 'metadata': e.metadata,
                  'device_timestamp': e.capturedAt.toIso8601String(),
                })
            .toList(),
      };
      final bodyJson = jsonEncode(body);
      final response = await _dio.post<dynamic>(
        '/logs',
        data: bodyJson,
        options: Options(
          contentType: 'application/json',
          headers: RequestSigner.sign(
            activationToken: token,
            method: 'POST',
            path: '/api/v1/sdk/logs',
            bodyBytes: utf8.encode(bodyJson),
          ),
        ),
      );
      if (response.statusCode == 200) {
        _buffer.removeRange(0, batch.length);
      }
      // Any other status (auth rejected, server error): leave the batch
      // buffered. A device that lost its license stops accumulating new
      // entries once REVOKED (the endpoint refuses those outright), but
      // whatever is already buffered simply ages out via the size cap.
    } catch (_) {
      // Offline, or the request itself failed — leave the batch buffered
      // for the next flush attempt. Never rethrow: logging must not surface
      // as an app-visible failure.
    }
  }

  @visibleForTesting
  void resetForTests() => _buffer.clear();

  @visibleForTesting
  int get bufferedCount => _buffer.length;
}
