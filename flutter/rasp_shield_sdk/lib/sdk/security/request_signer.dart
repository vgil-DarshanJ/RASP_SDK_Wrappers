import 'dart:convert';

import '../device/canonical_field.dart';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

/// Client side of the per-request integrity layer.
///
/// Mirrors `app/licensing/request_integrity.py::compute_signature` exactly —
/// see that module's docstring for the design. Reuses the activation_token
/// (already device- and license-bound, already required on every
/// post-activation call) as HMAC key material; no new secret is introduced.
///
/// ```
/// REQUEST_AUTHENTICATOR =
///     HMAC-SHA256(activation_token, METHOD|path|timestamp|nonce|sha256(bodyBytes))
/// ```
class RequestSigner {
  RequestSigner._();

  /// Signs one request. [bodyBytes] must be the *exact* bytes that will be
  /// sent on the wire — sign the same encoded string you hand to the HTTP
  /// client, never a re-serialization of it, or the server's raw-body hash
  /// will not match.
  static Map<String, String> sign({
    required String activationToken,
    required String method,
    required String path,
    required List<int> bodyBytes,
  }) {
    final timestamp = currentTimestamp();
    final nonce = randomNonce();
    final message = canonicalMessage(
      method: method,
      path: path,
      timestamp: timestamp,
      nonce: nonce,
      bodyBytes: bodyBytes,
    );
    return {
      'X-Rasp-Timestamp': timestamp,
      'X-Rasp-Nonce': nonce,
      'X-Rasp-Signature': hmacOver(activationToken, message),
    };
  }

  /// The exact string this layer signs.
  ///
  /// Extracted from [sign] so the device-binding proof (`DeviceProof`) can
  /// cover the *same* request context without re-deriving it. Two
  /// independent constructions of the same canonical string is precisely
  /// how a client and a server drift apart — there is one here, and the
  /// backend's `request_integrity.compute_signature` mirrors it.
  ///
  /// Public for that reason, and for that reason only: it computes nothing
  /// secret and holds no key.
  ///
  /// Throws [CanonicalFieldError] when [method], [path], [timestamp] or
  /// [nonce] contains the canonical delimiter — see
  /// `docs/DEVICE_BINDING_CANONICALIZATION.md`. Mirrors
  /// `request_integrity.canonical_request_message`'s identical validation
  /// on the backend. `bodyHash` is never checked: it is a SHA-256 hex
  /// digest, hex-digit-only by construction, and can never contain `|`.
  static String canonicalMessage({
    required String method,
    required String path,
    required String timestamp,
    required String nonce,
    required List<int> bodyBytes,
  }) {
    CanonicalField.assertSafe('method', method);
    CanonicalField.assertSafe('path', path);
    CanonicalField.assertSafe('timestamp', timestamp);
    CanonicalField.assertSafe('nonce', nonce);
    final bodyHash = sha256.convert(bodyBytes).toString();
    return '${method.toUpperCase()}|$path|$timestamp|$nonce|$bodyHash';
  }

  /// HMAC-SHA256 of [message] keyed by [key], lowercase hex.
  static String hmacOver(String key, String message) =>
      Hmac(sha256, utf8.encode(key)).convert(utf8.encode(message)).toString();

  /// Seconds since the epoch, UTC, as the wire format expects.
  static String currentTimestamp() =>
      (DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000).toString();

  static final Random _rng = Random.secure();

  /// 128 bits of randomness, hex-encoded — large enough that two devices
  /// colliding by chance inside the server's replay window is not a
  /// practical concern.
  static String randomNonce() {
    final bytes = Uint8List(16);
    for (var i = 0; i < bytes.length; i++) {
      bytes[i] = _rng.nextInt(256);
    }
    return bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();
  }
}
