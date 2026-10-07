import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/core/core.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// Task 8.1 plugin side: the fraud-signal and session-risk config reaches the
/// native map (all off by default), the five new detectors have descriptors,
/// the risk in a native state is decoded (anything unreadable → UNKNOWN), and
/// reportSession / reportTransaction / signTransaction /
/// setHighRiskTransactionMode send the right method and arguments and turn
/// native errors into [RaspFraudApiException].
///
/// Real: RaspLeanConfig.toNativeMap, RaspDetectorDescriptor, RaspLeanSession
/// (start, state decoding, the four calls), RaspSessionRisk.fromWire.
/// Fake: the native method channel and the lean-state event stream (the
/// replies are what the Android handler sends; hashing and signing are
/// covered by the engine's RaspTask81Test).
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const stateChannel = EventChannel('com.shieldsdk.security/lean_state');

  const riskWire = {
    'score': 40,
    'maxPossibleScore': 65,
    'verdict': 'MEDIUM',
    'stepUpRecommended': false,
    'firedGroups': ['device_compromise'],
    'undecidedGroups': ['sms_access'],
    'contributingDetectors': ['root_jailbreak'],
    'highRiskTransactionMode': false,
    'evaluatedAtMillis': 1790000000000,
  };

  test('new config fields default to off and reach the native map', () {
    final none = const RaspLeanConfig().toNativeMap();
    for (final key in [
      'otpInterceptionDetection',
      'smsReaderAbuseDetection',
      'otpForwardingDetection',
      'remoteControlAppDetection',
      'screenSharingDetection',
      'sessionRiskScoring',
      'highRiskTransactionMode',
    ]) {
      expect(none[key], isFalse, reason: key);
    }
    expect(none['riskMediumThreshold'], 30);
    expect(none['riskHighThreshold'], 60);
    expect(none['stepUpThreshold'], isNull);
    expect(none['accountHashSalt'], isNull);
    expect(none['remoteControlListJson'], isNull);

    final set = const RaspLeanConfig(
      otpInterceptionDetection: true,
      smsReaderAbuseDetection: true,
      otpForwardingDetection: true,
      remoteControlAppDetection: true,
      screenSharingDetection: true,
      notificationListenerAllowlist: ['com.watch.companion'],
      smsAppAllowlist: ['com.sms.allowed'],
      autoForwardPackages: ['com.forward.app'],
      remoteControlListJson: '{"payload":"{}","signature":""}',
      remoteControlListPublicKey: 'KEY',
      sessionRiskScoring: true,
      riskMediumThreshold: 25,
      riskHighThreshold: 55,
      stepUpThreshold: 45,
      highRiskTransactionMode: true,
    ).toNativeMap();
    expect(set['notificationListenerAllowlist'], ['com.watch.companion']);
    expect(set['smsAppAllowlist'], ['com.sms.allowed']);
    expect(set['autoForwardPackages'], ['com.forward.app']);
    expect(set['remoteControlListPublicKey'], 'KEY');
    expect(set['sessionRiskScoring'], isTrue);
    expect(set['riskMediumThreshold'], 25);
    expect(set['riskHighThreshold'], 55);
    expect(set['stepUpThreshold'], 45);
    expect(set['highRiskTransactionMode'], isTrue);
  });

  test('the five fraud detectors have dashboard titles under Privacy & Screen', () {
    const expected = {
      'otp_interception_risk': ('OTP Interception Risk', DetectionSeverity.high),
      'sms_reader_abuse': ('SMS Reader Apps', DetectionSeverity.high),
      'otp_forwarding_risk': ('OTP Forwarding Risk (hint)', DetectionSeverity.medium),
      'remote_control_app': ('Remote Control App', DetectionSeverity.high),
      'screen_sharing_risk': ('Screen Sharing During App Use', DetectionSeverity.high),
    };
    expected.forEach((id, value) {
      final d = RaspDetectorDescriptor.forId(id);
      expect(d.isGeneric, isFalse, reason: id);
      expect(d.title, value.$1);
      expect(d.severity, value.$2);
      expect(d.category, ThreatCategory.privacyScreen);
    });
  });

  test('risk decoding: unreadable input is UNKNOWN, never LOW', () {
    final risk = RaspSessionRisk.fromWire(riskWire);
    expect(risk.score, 40);
    expect(risk.maxPossibleScore, 65);
    expect(risk.verdict, RaspRiskVerdict.medium);
    expect(risk.undecidedGroups, ['sms_access']);
    expect(risk.evaluatedAt, DateTime.fromMillisecondsSinceEpoch(1790000000000, isUtc: true));

    expect(RaspSessionRisk.fromWire(null).verdict, RaspRiskVerdict.unknown);
    expect(RaspSessionRisk.fromWire('LOW').verdict, RaspRiskVerdict.unknown);
    expect(RaspSessionRisk.fromWire({'verdict': 'SAFE', 'score': 0}).verdict, RaspRiskVerdict.unknown);
    expect(RaspSessionRisk.fromWire({'verdict': 'LOW', 'score': 0}).verdict, RaspRiskVerdict.low);
  });

  group('session and transaction calls', () {
    late List<(String, Object?)> calls;
    late MockStreamHandlerEventSink sink;
    late Object? Function(String method, Object? arguments) reply;

    setUp(() {
      calls = [];
      reply = (_, _) => true;
      RaspNativeChannel.testInvokeHandler = (method, arguments) async {
        calls.add((method, arguments));
        return reply(method, arguments);
      };
      final messenger = TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
      // Block body: the value onListen returns is sent back as the reply.
      messenger.setMockStreamHandler(stateChannel, MockStreamHandler.inline(onListen: (arguments, events) {
        sink = events;
      }));
      addTearDown(() {
        RaspNativeChannel.testInvokeHandler = null;
        messenger.setMockStreamHandler(stateChannel, null);
      });
    });

    test('the session-risk flag reaches startLeanSession and the state carries the risk', () async {
      final session = await RaspLeanSession.start(const RaspLeanConfig(sessionRiskScoring: true, rootDetection: true));
      final start = calls.firstWhere((c) => c.$1 == 'startLeanSession').$2 as Map;
      expect(start['sessionRiskScoring'], isTrue);
      expect(session.risk, isNull, reason: 'no tick yet');

      sink.success({'extendedDetectors': const {}, 'risk': riskWire});
      await pumpEventQueue();
      expect(session.risk?.verdict, RaspRiskVerdict.medium);
      expect(session.risk?.score, 40);

      sink.success({'extendedDetectors': const {}});
      await pumpEventQueue();
      expect(session.risk, isNull, reason: 'scoring off natively: no risk in the state');
      await session.dispose();
    });

    test('reportSession sends the ids to the native side only and returns hashes', () async {
      reply = (method, arguments) => method == 'reportLeanSession'
          ? {
              'accountHash': 'a' * 64,
              'sessionHash': 'b' * 64,
              'event': 'login',
              'risk': riskWire,
              'sentToBackend': true,
            }
          : true;
      final session = await RaspLeanSession.start(const RaspLeanConfig(sessionRiskScoring: true));
      final report = await session.reportSession(accountId: 'acct-42', sessionId: 's-1', event: RaspSessionEvent.login);
      final sent = calls.firstWhere((c) => c.$1 == 'reportLeanSession').$2 as Map;
      expect(sent, {'accountId': 'acct-42', 'sessionId': 's-1', 'event': 'login'});
      expect(report.accountHash, 'a' * 64);
      expect(report.event, RaspSessionEvent.login);
      expect(report.risk.verdict, RaspRiskVerdict.medium);
      expect(report.sentToBackend, isTrue);
      await session.dispose();
    });

    test('reportTransaction and signTransaction decode the signed binding', () async {
      final signed = {
        'canonical': 'rasp-txn-v1|100.5|INR|${'c' * 64}|${'d' * 32}|1790000000000|7',
        'signature': 'MEUCIQ==',
        'counter': 7,
        'nonce': 'd' * 32,
        'timestampMillis': 1790000000000,
        'beneficiaryHash': 'c' * 64,
        'bindingSha256': 'e' * 64,
        'deviceKeyId': 'KEYID=',
        'risk': riskWire,
      };
      reply = (method, arguments) => switch (method) {
            'reportLeanTransaction' => {'transaction': signed, 'channel': 'upi', 'sentToBackend': false},
            'signLeanTransaction' => signed,
            _ => true,
          };
      final session = await RaspLeanSession.start(const RaspLeanConfig(sessionRiskScoring: true));
      final report = await session.reportTransaction(amount: '100.50', currency: 'INR', beneficiaryId: 'benef-1', channel: 'upi');
      expect(calls.firstWhere((c) => c.$1 == 'reportLeanTransaction').$2,
          {'amount': '100.50', 'currency': 'INR', 'beneficiaryId': 'benef-1', 'channel': 'upi'});
      expect(report.transaction.counter, 7);
      expect(report.transaction.bindingSha256, 'e' * 64);
      expect(report.transaction.timestamp, DateTime.fromMillisecondsSinceEpoch(1790000000000, isUtc: true));
      expect(report.channel, 'upi');
      expect(report.sentToBackend, isFalse);

      final only = await session.signTransaction(amount: '100.50', currency: 'INR', beneficiaryId: 'benef-1');
      expect(only.signatureBase64, 'MEUCIQ==');
      expect(calls.where((c) => c.$1 == 'signLeanTransaction'), hasLength(1));
      await session.dispose();
    });

    test('native errors become RaspFraudApiException with the native code', () async {
      reply = (method, arguments) => method == 'reportLeanTransaction'
          ? throw PlatformException(code: 'INVALID_ARGUMENT', message: 'currency must be 3 uppercase letters (ISO 4217)')
          : method == 'reportLeanSession'
              ? throw PlatformException(code: 'UNAVAILABLE', message: 'Session risk is off')
              : true;
      final session = await RaspLeanSession.start(const RaspLeanConfig());
      await expectLater(
        session.reportTransaction(amount: '1', currency: 'inr', beneficiaryId: 'b', channel: 'upi'),
        throwsA(isA<RaspFraudApiException>().having((e) => e.code, 'code', 'INVALID_ARGUMENT')),
      );
      await expectLater(
        session.reportSession(accountId: 'a', sessionId: 's', event: RaspSessionEvent.login),
        throwsA(isA<RaspFraudApiException>().having((e) => e.code, 'code', 'UNAVAILABLE')),
      );
      await session.dispose();
    });

    test('no native answer, or a disposed session, is UNAVAILABLE', () async {
      reply = (method, arguments) => method == 'signLeanTransaction' ? null : true;
      final session = await RaspLeanSession.start(const RaspLeanConfig(sessionRiskScoring: true));
      await expectLater(
        session.signTransaction(amount: '1', currency: 'INR', beneficiaryId: 'b'),
        throwsA(isA<RaspFraudApiException>().having((e) => e.code, 'code', 'UNAVAILABLE')),
      );
      await session.dispose();
      await expectLater(
        session.setHighRiskTransactionMode(true),
        throwsA(isA<RaspFraudApiException>().having((e) => e.code, 'code', 'UNAVAILABLE')),
      );
    });

    test('setHighRiskTransactionMode sends the flag and returns the recomputed risk', () async {
      reply = (method, arguments) =>
          method == 'setLeanHighRiskTransactionMode' ? {...riskWire, 'stepUpRecommended': true, 'highRiskTransactionMode': true} : true;
      final session = await RaspLeanSession.start(const RaspLeanConfig(sessionRiskScoring: true));
      final risk = await session.setHighRiskTransactionMode(true);
      expect(calls.firstWhere((c) => c.$1 == 'setLeanHighRiskTransactionMode').$2, isTrue);
      expect(risk.stepUpRecommended, isTrue);
      expect(risk.highRiskTransactionMode, isTrue);
      await session.dispose();
    });
  });
}
