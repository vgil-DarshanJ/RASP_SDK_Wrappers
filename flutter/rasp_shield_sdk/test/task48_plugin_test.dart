import 'dart:io';

import 'package:flutter/foundation.dart' show kDebugMode;
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart';
import 'package:rasp_shield/services/geo_filter_service.dart';

/// Task 4.8 plugin side: the mitm pin config fields, the SIM baseline reset,
/// and GeoFilterService asking the native engine (which asks the backend's
/// /v1/ip-risk) instead of a third-party API.
///
/// Real: RaspLeanConfig.toNativeMap, RaspLeanSession.resetSimBaseline,
/// GeoFilterService.checkHighRiskIp and the source files scanned below.
/// Fake: the native method channel (RaspNativeChannel.testInvokeHandler).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  tearDown(() => RaspNativeChannel.testInvokeHandler = null);

  test('mitm pin fields default to none and reach the native map', () {
    final none = const RaspLeanConfig().toNativeMap();
    expect(none['certificatePinHost'], isNull);
    expect(none['certificatePins'], isEmpty);

    final pinned = const RaspLeanConfig(
      mitmDetection: true,
      certificatePinHost: 'api.example.com',
      certificatePins: ['sha256/AAAA', 'sha256/BBBB'],
    ).toNativeMap();
    expect(pinned['certificatePinHost'], 'api.example.com');
    expect(pinned['certificatePins'], ['sha256/AAAA', 'sha256/BBBB']);
  });

  test('resetSimBaseline calls the native method and returns its answer', () async {
    final calls = <String>[];
    RaspNativeChannel.testInvokeHandler = (method, arguments) async {
      calls.add(method);
      return method == 'resetSimBaseline';
    };
    expect(await RaspLeanSession.resetSimBaseline(), isTrue);
    RaspNativeChannel.testInvokeHandler = (method, arguments) async => null;
    expect(await RaspLeanSession.resetSimBaseline(), isFalse, reason: 'no answer = not reset');
    expect(calls, ['resetSimBaseline']);
  });

  Map<String, Object?> nativeResult(String status, [List<String> signals = const []]) => {
        'detectorId': 'high_risk_ip',
        'status': status,
        'reason': null,
        'evidence': [for (final s in signals) {'key': 'high_risk_ip_signal', 'value': s, 'note': null}],
      };

  test('GeoFilterService asks the native engine, also in a debug build (no debug skip)', () async {
    expect(kDebugMode, isTrue, reason: 'flutter test runs in debug mode');
    final calls = <String>[];
    RaspNativeChannel.testInvokeHandler = (method, arguments) async {
      calls.add(method);
      return nativeResult('DETECTED', ['blocked_country']);
    };
    final result = await GeoFilterService.checkHighRiskIp();
    expect(calls, ['checkHighRiskIp']);
    expect(result.isRisk, isTrue);
    expect(result.matchedBlockedCountry, isTrue);
    expect(result.isProxy, isFalse);
    expect(result.checkFailed, isFalse);
  });

  test('GeoFilterService maps SECURE to clean and anything undecided to checkFailed', () async {
    RaspNativeChannel.testInvokeHandler = (method, arguments) async => nativeResult('DETECTED', ['proxy_flag']);
    expect((await GeoFilterService.checkHighRiskIp()).isProxy, isTrue);

    RaspNativeChannel.testInvokeHandler = (method, arguments) async => nativeResult('SECURE');
    final clean = await GeoFilterService.checkHighRiskIp();
    expect(clean.isRisk, isFalse);
    expect(clean.checkFailed, isFalse);

    for (final status in ['UNKNOWN', 'UNAVAILABLE', 'ERROR']) {
      RaspNativeChannel.testInvokeHandler = (method, arguments) async => nativeResult(status);
      final undecided = await GeoFilterService.checkHighRiskIp();
      expect(undecided.checkFailed, isTrue, reason: status);
      expect(undecided.isRisk, isFalse, reason: status);
    }
    RaspNativeChannel.testInvokeHandler = (method, arguments) async => null;
    expect((await GeoFilterService.checkHighRiskIp()).checkFailed, isTrue, reason: 'no native answer');
  });

  test('no direct third-party IP lookup is left in the plugin or the engine', () {
    final engineSrc = Platform.environment['RASP_ENGINE_SRC'] ??
        '../../../rashield-sdk-publish/src/main/kotlin/com/shieldsdk/rasp';
    final files = [
      ...Directory('lib').listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.dart')),
      ...Directory('android/src').listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.kt')),
      ...Directory(engineSrc).listSync(recursive: true).whereType<File>().where((f) => f.path.endsWith('.kt')),
    ];
    expect(files.length, greaterThan(50), reason: 'scanned the plugin and engine sources');
    final offenders = [
      for (final f in files)
        if (f.readAsStringSync().contains('ipapi.co')) f.path,
    ];
    expect(offenders, isEmpty);
  });
}
