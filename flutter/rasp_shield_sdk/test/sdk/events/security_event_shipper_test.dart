import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/detectors/rasp_native_channel.dart';
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';

void main() {
  const validCredential = '''{
    "organization_id":"org_test",
    "application_id":"app_test",
    "api_key":"key_test",
    "api_secret":"secret_test",
    "ingestion_url":"https://ingestion.example.test/v1/events"
  }''';

  tearDown(() {
    RaspNativeChannel.testInvokeHandler = null;
    RaspSecurityEventShipper.onShipError = null;
    RaspSecurityEventShipper.resetForTests();
  });

  test('configuredBackendHost names only the host the events go to', () async {
    expect(RaspSecurityEventShipper.configuredBackendHost, isNull);
    RaspNativeChannel.testInvokeHandler = (method, arguments) async => true;
    expect(await RaspSecurityEventShipper.configure(validCredential), isTrue);
    expect(RaspSecurityEventShipper.configuredBackendHost, 'ingestion.example.test');
    final host = RaspSecurityEventShipper.configuredBackendHost!;
    expect(host.contains('key_test') || host.contains('secret_test') || host.contains('/v1'), isFalse);

    expect(
      await RaspSecurityEventShipper.configure(
        validCredential.replaceFirst('https://ingestion.example.test/v1/events', 'http://192.168.2.208:4000/v1/events'),
      ),
      isTrue,
    );
    expect(RaspSecurityEventShipper.configuredBackendHost, '192.168.2.208:4000');
  });

  test('awaits and reports a failed native lean shipping configuration',
      () async {
    final nativeReply = Completer<Object?>();
    String? reportedError;
    RaspNativeChannel.testInvokeHandler = (method, arguments) {
      expect(method, 'configureLeanEventShipping');
      expect(arguments, validCredential);
      return nativeReply.future;
    };
    RaspSecurityEventShipper.onShipError = (reason) => reportedError = reason;

    var completed = false;
    final configured = RaspSecurityEventShipper.configure(validCredential)
        .then((value) {
      completed = true;
      return value;
    });
    await Future<void>.delayed(Duration.zero);
    expect(completed, isFalse, reason: 'configure must await the native reply');

    nativeReply.complete(false);
    expect(await configured, isFalse);
    expect(RaspSecurityEventShipper.isConfigured, isFalse);
    expect(reportedError, contains('could not be configured'));
  });

  group('RaspSecurityEventShipper.computeSignatureForTesting', () {
    test('is deterministic for identical inputs', () {
      final a = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1234567890', 'body');
      final b = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1234567890', 'body');
      expect(a, equals(b));
    });

    test('produces lowercase hex of the expected SHA-256 digest length', () {
      final signature = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1234567890', 'body');
      expect(signature.length, 64); // 32-byte digest = 64 hex chars
      expect(signature, equals(signature.toLowerCase()));
      expect(RegExp(r'^[0-9a-f]+$').hasMatch(signature), isTrue);
    });

    test('differs when the body differs', () {
      final a = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1234567890', 'body-a');
      final b = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1234567890', 'body-b');
      expect(a, isNot(equals(b)));
    });

    test('differs when the timestamp differs', () {
      final a = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1000', 'same-body');
      final b = RaspSecurityEventShipper.computeSignatureForTesting('secret', '2000', 'same-body');
      expect(a, isNot(equals(b)));
    });

    test('differs when the secret differs — a leaked api_key alone cannot forge a signature', () {
      final a = RaspSecurityEventShipper.computeSignatureForTesting('secret-one', '1234567890', 'same-body');
      final b = RaspSecurityEventShipper.computeSignatureForTesting('secret-two', '1234567890', 'same-body');
      expect(a, isNot(equals(b)));
    });

    test('matches the same cross-language vector as android_core\'s RaspHmacSignerTest and the '
        'backend\'s own Node runtime', () {
      // This exact value was computed independently via Node — the
      // backend's actual runtime — as:
      //   crypto.createHmac('sha256', 'secret').update('1000.hello').digest('hex')
      // and is asserted identically in android_core's RaspHmacSignerTest.
      // A three-way match (Dart, Kotlin, Node) proves the signing-string
      // format and digest encoding are byte-for-byte interoperable across
      // every consumption path this SDK ships, not just internally
      // self-consistent within one language.
      final signature = RaspSecurityEventShipper.computeSignatureForTesting('secret', '1000', 'hello');
      expect(
        signature,
        equals('68b4e0f3cbf572d8f2a61a0a26389c0880345705e6cbca10add63a2651feefb0'),
      );
    });
  });
}
