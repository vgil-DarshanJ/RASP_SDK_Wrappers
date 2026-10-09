// F-21: configureTlsPinning keeps the platform's certificate validation and
// applies the pin decision on top, before any request data is sent.
// Real: configureTlsPinning / pinnedHttpClient, Dio, dart:io TLS against a
// local TLS server. Test material: a throwaway CA and a localhost
// certificate in test/fixtures/tls. The pin decision is a test function.
import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/tls/tls_pinning_dio.dart';

const _dir = 'test/fixtures/tls';

List<int> _pemToDer(String pem) => base64Decode(
      pem.split(RegExp(r'\r?\n')).map((l) => l.trim()).where((l) => l.isNotEmpty && !l.startsWith('-----')).join(),
    );

void main() {
  late SecureServerSocket tlsServer;
  late ServerSocket plainServer;
  late String serverPin;
  var tlsRequests = 0;
  var plainRequests = 0;

  SecurityContext trustingTestCa() =>
      SecurityContext(withTrustedRoots: false)..setTrustedCertificates('$_dir/ca.cert.pem');

  setUpAll(() async {
    final serverContext = SecurityContext()
      ..useCertificateChain('$_dir/server.cert.pem')
      ..usePrivateKey('$_dir/server.key.pem');
    tlsServer = await SecureServerSocket.bind(
      InternetAddress.loopbackIPv4,
      0,
      serverContext,
      supportedProtocols: const ['http/1.1'],
    );
    tlsServer.listen(
      (socket) => socket.listen(
        (_) {
          tlsRequests++;
          socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
          socket.close();
        },
        onError: (_) {},
      ),
      onError: (_) {},
    );
    plainServer = await ServerSocket.bind(InternetAddress.loopbackIPv4, 0);
    plainServer.listen((socket) => socket.listen((_) {
          plainRequests++;
          socket.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok');
          socket.close();
        }, onError: (_) {}));
    serverPin = sha256.convert(_pemToDer(File('$_dir/server.cert.pem').readAsStringSync())).toString();
  });

  tearDownAll(() async {
    await tlsServer.close();
    await plainServer.close();
  });

  setUp(() {
    tlsRequests = 0;
    plainRequests = 0;
  });

  Dio dio({SecurityContext? context, required TlsPinDecision allow}) {
    final d = Dio(BaseOptions(connectTimeout: const Duration(seconds: 5), receiveTimeout: const Duration(seconds: 5)));
    configureTlsPinning(d, context: context, allow: allow);
    return d;
  }

  String tlsUrl() => 'https://localhost:${tlsServer.port}/x';

  test('a certificate the platform does not trust fails, even for a host without a pin', () async {
    final client = dio(allow: (_, _) => true); // default trust store: the test CA is not in it
    await expectLater(client.get<String>(tlsUrl()), throwsA(isA<DioException>()));
    expect(tlsRequests, 0);
  });

  test('a trusted certificate for an unpinned host goes through', () async {
    final client = dio(context: trustingTestCa(), allow: (_, _) => true);
    final res = await client.get<String>(tlsUrl());
    expect(res.data, 'ok');
    expect(tlsRequests, 1);
  });

  test('the decision gets the host and the leaf certificate SHA-256; a matching pin goes through', () async {
    final seen = <String>[];
    final client = dio(context: trustingTestCa(), allow: (host, pin) {
      seen.add('$host $pin');
      return pin == serverPin;
    });
    expect((await client.get<String>(tlsUrl())).data, 'ok');
    expect(seen, ['localhost $serverPin']);
  });

  test('a trusted certificate with the wrong pin is refused before any request data is sent', () async {
    final client = dio(context: trustingTestCa(), allow: (_, pin) => pin == 'f' * 64);
    await expectLater(client.get<String>(tlsUrl()), throwsA(isA<DioException>()));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    expect(tlsRequests, 0, reason: 'the server never received the HTTP request');
  });

  test('plain HTTP is refused when the decision requires a pin for the host', () async {
    final client = dio(allow: (_, pin) => pin.isNotEmpty);
    await expectLater(client.get<String>('http://localhost:${plainServer.port}/x'), throwsA(isA<DioException>()));
    expect(plainRequests, 0);

    final open = dio(allow: (_, _) => true);
    expect((await open.get<String>('http://localhost:${plainServer.port}/x')).data, 'ok');
  });
}
