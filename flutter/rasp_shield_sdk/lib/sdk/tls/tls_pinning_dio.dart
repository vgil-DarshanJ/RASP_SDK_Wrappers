import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter/foundation.dart' show visibleForTesting;

import 'tls_pinning_controller.dart';

/// Decides whether a connection to [host] that presented a certificate with
/// SHA-256 [pinSha256Hex] (lower-case hex of the DER; empty for a plain-HTTP
/// connection) may carry the request.
typedef TlsPinDecision = bool Function(String host, String pinSha256Hex);

/// Wires [TlsPinningController]'s enforcement decision into a real [Dio]
/// client's TLS handshake.
///
/// ## Order of checks (F-21)
///
/// 1. The platform's normal certificate validation (trusted roots, host
///    name, expiry) runs during the handshake, always. A certificate it
///    rejects fails the connection; there is no `badCertificateCallback`
///    that could accept it.
/// 2. After a successful handshake and before a single byte of the HTTP
///    request is written, the leaf certificate's SHA-256 goes to
///    [TlsPinningController.allowConnection] (match → go, mismatch in
///    enforce mode → the socket is closed and the request fails with a
///    [HandshakeException]; unpinned hosts → go).
///
/// The previous version used `SecurityContext(withTrustedRoots: false)` so a
/// `badCertificateCallback` saw every certificate, and that callback said
/// yes for every host without a pin — so for those hosts no certificate was
/// validated at all. Pinning is now only ever an extra check.
///
/// Connections are direct (`findProxy` → DIRECT): on Android, Dart's
/// [HttpClient] does not use the system proxy anyway.
///
/// [context] and [allow] exist for tests.
void configureTlsPinning(
  Dio dio, {
  @visibleForTesting SecurityContext? context,
  @visibleForTesting TlsPinDecision? allow,
}) {
  dio.httpClientAdapter = IOHttpClientAdapter(
    createHttpClient: () => pinnedHttpClient(context: context, allow: allow),
  );
}

/// An [HttpClient] that validates certificates normally and applies the pin
/// decision before any request data is sent. See [configureTlsPinning].
HttpClient pinnedHttpClient({SecurityContext? context, TlsPinDecision? allow}) {
  final decide = allow ?? TlsPinningController.instance.allowConnection;
  final client = HttpClient(context: context);
  client.findProxy = (_) => 'DIRECT';
  client.connectionFactory = (Uri uri, String? proxyHost, int? proxyPort) async {
    if (uri.scheme != 'https') {
      // A pinned host in enforce mode must not be reached in clear text.
      if (!decide(uri.host, '')) {
        throw HandshakeException('TLS pin required for ${uri.host}; refusing plain HTTP');
      }
      return Socket.startConnect(uri.host, uri.port);
    }
    // No onBadCertificate: anything the platform does not trust fails here.
    final task = await SecureSocket.startConnect(
      uri.host,
      uri.port,
      context: context,
      supportedProtocols: const ['http/1.1'],
    );
    final checked = task.socket.then((socket) {
      final cert = socket.peerCertificate;
      final pin = cert == null ? '' : sha256.convert(cert.der).toString();
      if (!decide(uri.host, pin)) {
        socket.destroy();
        throw HandshakeException('TLS pin mismatch for ${uri.host}');
      }
      return socket;
    });
    return ConnectionTask.fromSocket(checked, task.cancel);
  };
  return client;
}
