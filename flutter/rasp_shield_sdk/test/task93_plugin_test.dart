import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// Task 9.3 plugin side: the location-heartbeat interval reaches the native
/// config map (60 s by default), the delivery result of the last heartbeat
/// in a native state is decoded (anything unreadable → null), and sharing a
/// fix / turning sharing off reach the native side as before.
///
/// Real: RaspLeanConfig.toNativeMap, RaspLeanSession (start, state decoding,
/// currentLocation), RaspLocationHeartbeatStatus.fromWire.
/// Fake: the native method channel and the lean-state event stream (the
/// state maps are what the Android handler's emitLeanState sends; sending
/// the heartbeat itself is covered by the engine's RaspLocationHeartbeatTest).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const stateChannel = EventChannel('com.shieldsdk.security/lean_state');
  const atMillis = 1791374400000; // 2026-10-07 12:00 UTC

  test('location heartbeat interval: 60 s by default, configurable', () {
    expect(const RaspLeanConfig().toNativeMap()['locationHeartbeatIntervalMillis'], 60000);
    expect(
      const RaspLeanConfig(locationHeartbeatInterval: Duration(seconds: 45)).toNativeMap()['locationHeartbeatIntervalMillis'],
      45000,
    );
  });

  test('heartbeat status from the native wire; unreadable → null', () {
    const outcomes = {
      'DELIVERED': RaspLocationHeartbeatOutcome.delivered,
      'NOT_DELIVERED': RaspLocationHeartbeatOutcome.notDelivered,
      'REJECTED': RaspLocationHeartbeatOutcome.rejected,
      'NOT_CONFIGURED': RaspLocationHeartbeatOutcome.notConfigured,
    };
    outcomes.forEach((wire, outcome) {
      final status = RaspLocationHeartbeatStatus.fromWire({'atMillis': atMillis, 'outcome': wire, 'detail': 'x', 'cleared': false});
      expect(status?.outcome, outcome, reason: wire);
    });
    final missingDetail = RaspLocationHeartbeatStatus.fromWire({'atMillis': atMillis, 'outcome': 'REJECTED'});
    expect(missingDetail?.detail, 'rejected');
    expect(missingDetail?.cleared, isFalse);
    expect(RaspLocationHeartbeatStatus.fromWire(null), isNull);
    expect(RaspLocationHeartbeatStatus.fromWire('DELIVERED'), isNull);
    expect(RaspLocationHeartbeatStatus.fromWire({'atMillis': atMillis, 'outcome': 'MAYBE'}), isNull);
    expect(RaspLocationHeartbeatStatus.fromWire({'atMillis': '1791374400000', 'outcome': 'DELIVERED'}), isNull);
  });

  group('lean session', () {
    late List<(String, Object?)> calls;
    late MockStreamHandlerEventSink sink;

    setUp(() {
      calls = [];
      RaspNativeChannel.testInvokeHandler = (method, arguments) async {
        calls.add((method, arguments));
        return true;
      };
      final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      messenger.setMockStreamHandler(stateChannel, MockStreamHandler.inline(onListen: (arguments, events) {
        sink = events;
      }));
      addTearDown(() {
        RaspNativeChannel.testInvokeHandler = null;
        messenger.setMockStreamHandler(stateChannel, null);
      });
    });

    test('the state carries the last heartbeat result', () async {
      final session = await RaspLeanSession.start(const RaspLeanConfig(locationHeartbeatInterval: Duration(seconds: 30)));
      final start = calls.firstWhere((c) => c.$1 == 'startLeanSession').$2 as Map;
      expect(start['locationHeartbeatIntervalMillis'], 30000);
      expect(session.current.locationHeartbeat, isNull, reason: 'no state yet');

      sink.success({
        'extendedDetectors': const {},
        'locationHeartbeat': {'atMillis': atMillis, 'outcome': 'DELIVERED', 'detail': 'delivered', 'cleared': false},
      });
      await pumpEventQueue();
      final delivered = session.current.locationHeartbeat!;
      expect(delivered.outcome, RaspLocationHeartbeatOutcome.delivered);
      expect(delivered.at, DateTime.fromMillisecondsSinceEpoch(atMillis));
      expect(delivered.detail, 'delivered');
      expect(delivered.cleared, isFalse);

      sink.success({
        'extendedDetectors': const {},
        'locationHeartbeat': {'atMillis': atMillis + 60000, 'outcome': 'REJECTED', 'detail': 'HTTP 401', 'cleared': true},
      });
      await pumpEventQueue();
      expect(session.current.locationHeartbeat?.outcome, RaspLocationHeartbeatOutcome.rejected);
      expect(session.current.locationHeartbeat?.detail, 'HTTP 401');
      expect(session.current.locationHeartbeat?.cleared, isTrue);

      sink.success({'extendedDetectors': const {}});
      await pumpEventQueue();
      expect(session.current.locationHeartbeat, isNull, reason: 'nothing sent yet in this process');
      await session.dispose();
    });

    test('a shared fix goes to the native side; turning sharing off clears it there', () async {
      final session = await RaspLeanSession.start(const RaspLeanConfig());
      session.currentLocation = RaspLocationSnapshot(
        latitude: 21.0453,
        longitude: 79.0381,
        accuracyMeters: 14,
        capturedAt: DateTime.fromMillisecondsSinceEpoch(atMillis),
        isMock: false,
        shareWithBackend: true,
      );
      await pumpEventQueue();
      final set = calls.lastWhere((c) => c.$1 == 'setLeanSessionLocation').$2 as Map;
      expect(set['shareWithBackend'], isTrue);
      expect(set['latitude'], 21.0453, reason: 'the engine coarsens it before sending');
      expect(set['capturedAtMillis'], atMillis);

      session.currentLocation = null;
      await pumpEventQueue();
      expect(calls.last.$1, 'clearLeanSessionLocation');
      await session.dispose();
    });
  });
}
