import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// Config contract for the detectors added in Tasks 3a-3c: every flag is off
/// by default and reaches the native map under the key the Kotlin plugin
/// reads (RaspSecurityChannelHandler.leanConfig).
void main() {
  test('Task 3a flags default off and map to native keys', () {
    const off = RaspLeanConfig();
    final offMap = off.toNativeMap();
    for (final key in const [
      'mockLocationDetection',
      'timeSpoofingDetection',
      'unsafeWifiDetection',
      'screenRecordingDetection',
    ]) {
      expect(offMap[key], isFalse, reason: key);
    }
    expect(offMap['serverTimeMillis'], isNull);

    final on = RaspLeanConfig(
      mockLocationDetection: true,
      timeSpoofingDetection: true,
      unsafeWifiDetection: true,
      screenRecordingDetection: true,
      serverTime: DateTime.fromMillisecondsSinceEpoch(1790000000000, isUtc: true),
    ).toNativeMap();
    expect(on['mockLocationDetection'], isTrue);
    expect(on['timeSpoofingDetection'], isTrue);
    expect(on['unsafeWifiDetection'], isTrue);
    expect(on['screenRecordingDetection'], isTrue);
    expect(on['serverTimeMillis'], 1790000000000);
  });

  test('Task 3b flags default off and map to native keys', () {
    final offMap = const RaspLeanConfig().toNativeMap();
    for (final key in const [
      'vishingCallDetection',
      'simChangeDetection',
      'thirdPartyKeyboardDetection',
      'taskHijackDetection',
    ]) {
      expect(offMap[key], isFalse, reason: key);
    }
    expect(offMap['trustedKeyboardPackages'], isEmpty);

    final on = const RaspLeanConfig(
      vishingCallDetection: true,
      simChangeDetection: true,
      thirdPartyKeyboardDetection: true,
      taskHijackDetection: true,
      trustedKeyboardPackages: ['com.vendor.keyboard'],
    ).toNativeMap();
    expect(on['vishingCallDetection'], isTrue);
    expect(on['simChangeDetection'], isTrue);
    expect(on['thirdPartyKeyboardDetection'], isTrue);
    expect(on['taskHijackDetection'], isTrue);
    expect(on['trustedKeyboardPackages'], ['com.vendor.keyboard']);
  });

  test('Task 3c flags default off and map to native keys', () {
    final offMap = const RaspLeanConfig().toNativeMap();
    expect(offMap['deviceStateAttestationDetection'], isFalse);
    expect(offMap['malwareReputationDetection'], isFalse);
    expect(offMap['maxSecurityPatchAgeDays'], isNull);
    expect(offMap['malwareReputationListJson'], isNull);
    expect(offMap['malwareReputationPublicKey'], isNull);

    final on = const RaspLeanConfig(
      deviceStateAttestationDetection: true,
      maxSecurityPatchAgeDays: 120,
      malwareReputationDetection: true,
      malwareReputationListJson: '{"payload":"{}","signature":"x"}',
      malwareReputationPublicKey: 'MCowBQYDK2VwAyEA',
    ).toNativeMap();
    expect(on['deviceStateAttestationDetection'], isTrue);
    expect(on['maxSecurityPatchAgeDays'], 120);
    expect(on['malwareReputationDetection'], isTrue);
    expect(on['malwareReputationListJson'], '{"payload":"{}","signature":"x"}');
    expect(on['malwareReputationPublicKey'], 'MCowBQYDK2VwAyEA');
  });

  test('isCallActive and acknowledgeSimChange call the native methods', () async {
    TestWidgetsFlutterBinding.ensureInitialized();
    final calls = <String>[];
    RaspNativeChannel.testInvokeHandler = (method, arguments) async {
      calls.add(method);
      return method == 'isCallActive' ? true : false;
    };
    addTearDown(() => RaspNativeChannel.testInvokeHandler = null);

    expect(await RaspLeanSession.isCallActive(), isTrue);
    expect(await RaspLeanSession.acknowledgeSimChange(), isFalse);
    expect(calls, ['isCallActive', 'acknowledgeSimChange']);
  });

  test('location snapshot carries the mock flag', () {
    final snapshot = RaspLocationSnapshot(
      latitude: 1, longitude: 2, capturedAt: DateTime.utc(2026), isMock: true,
    );
    expect(snapshot.isMock, isTrue);
    expect(
      RaspLocationSnapshot(latitude: 1, longitude: 2, capturedAt: DateTime.utc(2026)).isMock,
      isNull,
    );
  });
}
