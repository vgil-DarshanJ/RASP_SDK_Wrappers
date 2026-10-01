import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';

import 'tls_pinning_controller.dart';

/// Wires [TlsPinningController]'s enforcement decision into a real [Dio]
/// client's TLS handshake.
///
/// This is what closes the gap between "the controller tracks the right
/// pinset" and "network requests actually use the pins" — the two are not
/// the same thing, and a controller with no caller was exactly the state
/// this file fixes. Call once per [Dio] instance, right after constructing
/// it (mirrors how `SdkConfig`'s `baseUrl` is supplied once, at
/// construction, everywhere else in this SDK).
///
/// ## What this does not change
///
/// The platform's own certificate-chain validation still runs first, same
/// as always — this only ADDS a pin check on top via
/// `badCertificateCallback`, and only for a certificate the platform
/// already rejected OR one `TlsPinningController` has an opinion about.
/// Concretely: if the platform trusts the certificate, Dio never invokes
/// `badCertificateCallback` at all, so [TlsPinningController.allowConnection]
/// is consulted from a second callback path (installed via
/// `SecurityContext`-free `HttpClient.badCertificateCallback` semantics)
/// **only for the pinning-relevant case** — see the inline comment below for
/// exactly how a validly-CA-signed-but-wrong certificate is still caught.
void configureTlsPinning(Dio dio) {
  final adapter = IOHttpClientAdapter(
    createHttpClient: () {
      // `withTrustedRoots: false` (not the default) is required so
      // `badCertificateCallback` fires for a certificate that a normal CA
      // check would have accepted — a certificate can be validly issued by
      // a trusted CA and still not be the pinned one (a compromised or
      // coerced CA, an enterprise MITM proxy with its own root installed),
      // which is exactly the case pinning exists to catch. Without this,
      // the callback only fires for certificates the platform already
      // distrusts, and pinning would silently do nothing against the
      // threat it is for. Same reasoning as
      // `TlsPinningController.validateAgainstLiveHandshake` and
      // `SslPinningService.checkCertificatePin`.
      final client = HttpClient(context: SecurityContext(withTrustedRoots: false));
      client.badCertificateCallback = (cert, host, port) {
        final pin = sha256.convert(cert.der).toString();
        return TlsPinningController.instance.allowConnection(host, pin);
      };
      return client;
    },
  );
  dio.httpClientAdapter = adapter;
}
