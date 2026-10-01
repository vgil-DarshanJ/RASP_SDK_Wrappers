import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../device/canonical_field.dart';
import '../security/request_signer.dart';

/// The canonical string a protected customer-API request is signed over.
///
/// Mirrors `app/licensing/api_protection.py::canonical_request` byte for
/// byte. Dart and Python cannot share source, so this is a deliberate
/// field-for-field mirror verified by cross-language test vectors — the
/// same approach `security_event_chain` and `sensitive_operation` already
/// established in this SDK, rather than each side inventing its own shape.
///
/// ## Why this is not `RequestSigner.canonicalMessage`
///
/// [RequestSigner] signs `METHOD|path|ts|nonce|body_hash`, which is exactly
/// right for RASP Shield's own backend: one known host, no meaningful query
/// strings, no end-user session. A customer's API is reached by host, does
/// take query strings, and its requests belong to an authenticated session.
/// Signing those requests with the shorter form would leave the host, the
/// query and the session unbound — so `?amount=1` and `?amount=9000` would
/// produce the same signature, and a proof minted for `api.bank.com` would
/// verify against `evil.example`.
///
/// The leading domain separator is what makes extending the form safe: a
/// proof built here can never be replayed against a RASP endpoint (that
/// layer's canonical string carries no tag), and a captured RASP request
/// signature can never be presented as an API proof. Same reasoning, and
/// same versioning discipline, as `DeviceProof.domain`.
class ApiRequestProof {
  ApiRequestProof._();

  /// Versioned so a future change to what a proof covers is a new tag
  /// rather than a silent reinterpretation of signatures already issued.
  ///
  /// v1 covers the request alone. v2 additionally binds a transaction digest
  /// as a trailing field (see `RaspShieldTransactions`). Because the tag sits
  /// at position 0 of the signed message, an attacker cannot strip a
  /// transaction binding by presenting the proof as v1 — that changes the
  /// message, and the signature stops verifying.
  static const String domain = 'RASP-API-PROOF-v1';
  static const String domainTx = 'RASP-API-PROOF-v2';

  /// Deterministic, order-independent encoding of a query string.
  ///
  /// `?b=2&a=1` and `?a=1&b=2` are the same request and must sign
  /// identically; `?a=2` is a different request and must not. Repeated keys
  /// keep every value (`?id=1&id=2` is meaningful) and are sorted by value,
  /// so their order on the wire does not change the signature either.
  ///
  /// Must match Python's `canonical_query`, which sorts `parse_qsl` pairs
  /// and re-encodes with `urlencode`.
  static String canonicalQuery(String? rawQuery) {
    if (rawQuery == null || rawQuery.isEmpty) return '';
    final pairs = <MapEntry<String, String>>[];
    for (final part in rawQuery.split('&')) {
      if (part.isEmpty) continue;
      final i = part.indexOf('=');
      final key = i < 0 ? part : part.substring(0, i);
      final value = i < 0 ? '' : part.substring(i + 1);
      pairs.add(MapEntry(Uri.decodeQueryComponent(key),
          Uri.decodeQueryComponent(value)));
    }
    pairs.sort((a, b) {
      final k = a.key.compareTo(b.key);
      return k != 0 ? k : a.value.compareTo(b.value);
    });
    return pairs
        .map((e) =>
            '${Uri.encodeQueryComponent(e.key)}=${Uri.encodeQueryComponent(e.value)}')
        .join('&');
  }

  /// SHA-256 of the customer's session token, or `''` when there is none.
  ///
  /// The digest — never the token — enters the canonical string, so binding
  /// a request to a session never requires handing the bank's session secret
  /// to this SDK's backend, and a captured proof reveals nothing about the
  /// session it was issued under.
  static String sessionBinding(String? sessionToken) {
    if (sessionToken == null || sessionToken.isEmpty) return '';
    return sha256.convert(utf8.encode(sessionToken)).toString();
  }

  /// Build the exact string to sign.
  ///
  /// [bodyBytes] must be the *exact* bytes that will go on the wire — sign
  /// the encoded body you hand to the HTTP client, never a re-serialization
  /// of it, or the server's own hash of the raw body will not match. This is
  /// the same rule [RequestSigner.sign] documents, and the same way it is
  /// broken in practice.
  ///
  /// Throws [CanonicalFieldError] if any field contains the `|` delimiter;
  /// without that guard `path: '/a|b'` and `path: '/a', query: 'b'` could
  /// canonicalize to the same string.
  static String canonicalRequest({
    required String method,
    required String host,
    required String path,
    String? query,
    required List<int> bodyBytes,
    required String timestamp,
    required String nonce,
    required String requestId,
    String? sessionToken,
    String? transactionDigest,
  }) {
    CanonicalField.assertSafe('method', method);
    CanonicalField.assertSafe('host', host);
    CanonicalField.assertSafe('path', path);
    CanonicalField.assertSafe('timestamp', timestamp);
    CanonicalField.assertSafe('nonce', nonce);
    CanonicalField.assertSafe('request_id', requestId);

    final cq = canonicalQuery(query);
    CanonicalField.assertSafe('query', cq);
    final bodyHash = sha256.convert(bodyBytes).toString();

    final hasTx = transactionDigest != null && transactionDigest.isNotEmpty;
    final fields = <String>[
      hasTx ? domainTx : domain,
      method.toUpperCase(),
      host.toLowerCase(),
      path,
      cq,
      bodyHash,
      timestamp,
      nonce,
      requestId,
      sessionBinding(sessionToken),
    ];
    if (hasTx) {
      CanonicalField.assertSafe('transaction_digest', transactionDigest);
      fields.add(transactionDigest);
    }
    return fields.join('|');
  }

  /// HMAC-SHA256 over the canonical string, keyed by the activation token.
  ///
  /// Reuses [RequestSigner.hmacOver] rather than re-deriving HMAC here —
  /// one implementation of the primitive, not two.
  static String sign({
    required String activationToken,
    required String canonicalRequestString,
  }) =>
      RequestSigner.hmacOver(activationToken, canonicalRequestString);

  /// Header names carrying a proof. Distinct from the `X-Rasp-*` headers
  /// [RequestSigner] uses, so a customer API gateway that already forwards
  /// or strips one set never silently affects the other.
  static const String headerTimestamp = 'X-Rasp-Api-Timestamp';
  static const String headerNonce = 'X-Rasp-Api-Nonce';
  static const String headerRequestId = 'X-Rasp-Api-Request-Id';
  static const String headerSignature = 'X-Rasp-Api-Signature';
  static const String headerDeviceId = 'X-Rasp-Api-Device-Id';
  static const String headerApplicationId = 'X-Rasp-Api-Application-Id';
  static const String headerLicenseKeyHash = 'X-Rasp-Api-License';
  static const String headerProofVersion = 'X-Rasp-Api-Proof-Version';

  /// Carries the transaction digest so a bank's gateway can log/route on it.
  /// It is NOT trusted as input: verification recomputes the digest from the
  /// bank's own transaction fields, and this header only has to match.
  static const String headerTransactionDigest = 'X-Rasp-Api-Transaction-Digest';

  /// The headers a protected request carries.
  ///
  /// `device_id` and `application_id` are sent so the verifying backend can
  /// look the seat up and *cross-check* them against its own rows — they are
  /// a claim to be refuted, never trusted. The backend rejects a mismatch
  /// with `API_PROOF_WRONG_DEVICE` / `API_PROOF_WRONG_APPLICATION` rather
  /// than believing what the client asserts about itself.
  static Map<String, String> headers({
    required String timestamp,
    required String nonce,
    required String requestId,
    required String signature,
    required String deviceId,
    required String applicationId,
    required String licenseKeyHash,
    String? transactionDigest,
  }) =>
      {
        headerProofVersion:
            (transactionDigest != null && transactionDigest.isNotEmpty)
                ? domainTx
                : domain,
        if (transactionDigest != null && transactionDigest.isNotEmpty)
          headerTransactionDigest: transactionDigest,
        headerTimestamp: timestamp,
        headerNonce: nonce,
        headerRequestId: requestId,
        headerSignature: signature,
        headerDeviceId: deviceId,
        headerApplicationId: applicationId,
        headerLicenseKeyHash: licenseKeyHash,
      };
}
