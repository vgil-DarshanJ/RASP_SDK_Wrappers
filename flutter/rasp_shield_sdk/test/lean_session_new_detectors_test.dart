import 'package:flutter_test/flutter_test.dart';
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
