import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// Task 6.0 plugin side: the tamper config fields reach the native map, and
/// the location snapshot carries provider + the user's opt-in; clearing the
/// location reaches the native side.
///
/// Real: RaspLeanConfig.toNativeMap, RaspLeanSession.start / currentLocation.
/// Fake: the native method channel and the lean-state event stream.
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const stateChannel = EventChannel('com.shieldsdk.security/lean_state');

  test('tamper fields default to nothing configured and reach the native map', () {
    final none = const RaspLeanConfig().toNativeMap();
    expect(none['expectedInstallers'], isEmpty);
    expect(none['expectedClassesDexSha256'], isNull);
    expect(none['expectedResourcesArscSha256'], isNull);

    final set = const RaspLeanConfig(
      tamperDetection: true,
      expectedSigningCertSha256: 'AB',
      expectedInstallers: ['com.android.vending'],
      expectedClassesDexSha256: '11',
      expectedResourcesArscSha256: '22',
    ).toNativeMap();
    expect(set['expectedInstallers'], ['com.android.vending']);
    expect(set['expectedClassesDexSha256'], '11');
    expect(set['expectedResourcesArscSha256'], '22');
  });

  test('location carries provider and the opt-in; null clears it natively', () async {
    final calls = <(String, Object?)>[];
    RaspNativeChannel.testInvokeHandler = (method, arguments) async {
      calls.add((method, arguments));
      return true;
    };
    final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
    messenger.setMockStreamHandler(stateChannel, MockStreamHandler.inline(onListen: (arguments, sink) {}));
    addTearDown(() {
      RaspNativeChannel.testInvokeHandler = null;
      messenger.setMockStreamHandler(stateChannel, null);
    });

    final session = await RaspLeanSession.start(const RaspLeanConfig(mockLocationDetection: true));
    session.currentLocation = RaspLocationSnapshot(
      latitude: 28.6, longitude: 77.2, accuracyMeters: 10, capturedAt: DateTime.utc(2026, 10, 5),
      isMock: false, provider: 'fused', shareWithBackend: true,
    );
    session.currentLocation = null;
    await pumpEventQueue();

    final set = calls.firstWhere((c) => c.$1 == 'setLeanSessionLocation').$2 as Map;
    expect(set['provider'], 'fused');
    expect(set['shareWithBackend'], isTrue);
    expect(set['isMock'], isFalse);
    expect(calls.map((c) => c.$1), contains('clearLeanSessionLocation'));
    expect(
      RaspLocationSnapshot(latitude: 1, longitude: 2, capturedAt: DateTime.utc(2026)).shareWithBackend,
      isFalse,
      reason: 'not shared unless the user opted in',
    );
    await session.dispose();
  });
}
