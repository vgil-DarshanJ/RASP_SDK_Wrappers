import '../security/request_signer.dart';
import 'canonical_field.dart';

/// The canonical strings a device signs with its binding key.
///
/// ## Two assertions, one message shape (Phase 10)
///
/// This SDK now makes two cryptographic assertions on a post-activation
/// request, and it is worth being exact about which does what, because they
/// look superficially similar and are not interchangeable:
///
/// | | Primitive | Key material | Answers |
/// |---|---|---|---|
/// | **REQUEST AUTHENTICATION** | HMAC-SHA256 | `activation_token` | *Is this request fresh, unmodified, and from someone holding this seat's token?* |
/// | **LICENSE BINDING** | ECDSA P-256 / SHA-256 | the device's non-exportable private key | *Is the sender the physical device this seat was issued to?* |
///
/// The first is `RequestSigner` and is unchanged by this milestone. The
/// second is this file. A bearer token satisfies the first from any machine
/// that has it; only the bound device can satisfy the second, and that is
/// the entire point.
///
/// **No second signature protocol was introduced.** The device proof is
/// computed over the *same canonical request string* `RequestSigner` already
/// builds — `METHOD|path|timestamp|nonce|sha256(body)` — so there is one
/// canonicalization to keep in step with the backend, not two. It is
/// prefixed with a version-tagged domain separator so a signature produced
/// for one purpose can never be replayed as the other, even though the
/// underlying context is shared.
///
/// See `docs/LICENSE_DEVICE_BINDING.md` §5.
class DeviceProof {
  DeviceProof._();

  /// Domain separator. Versioned so a future change to what a proof covers
  /// is a new tag rather than a silent reinterpretation of old signatures.
  static const String domain = 'RASP-DEVICE-PROOF-v1';

  /// The activation proof (Phase 4).
  ///
  /// Covers the **server-issued challenge nonce**, so the proof is fresh and
  /// single-use for exactly the same reason the licence HMAC is: the nonce
  /// is minted by the server, bound to this device and bundle, expires, and
  /// is consumed once. Covers [keyId] as well, so a captured proof cannot be
  /// presented alongside a different public key.
  ///
  /// Deliberately mirrors `activation_signature`'s field order
  /// (`nonce|device_id|bundle_id|sdk_version`) rather than inventing a new
  /// one — the same values, the same order, a different assertion.
  ///
  /// Throws [CanonicalFieldError] when any field contains the canonical
  /// delimiter — see `docs/DEVICE_BINDING_CANONICALIZATION.md`. Mirrors
  /// `device_binding.activation_proof_message`'s identical validation on
  /// the backend, so the same input is rejected on both sides rather than
  /// signed on one and refused on the other.
  static String activationMessage({
    required String nonce,
    required String deviceId,
    required String bundleId,
    required String sdkVersion,
    required String keyId,
  }) {
    CanonicalField.assertSafe('nonce', nonce);
    CanonicalField.assertSafe('device_id', deviceId);
    CanonicalField.assertSafe('bundle_id', bundleId);
    CanonicalField.assertSafe('sdk_version', sdkVersion);
    CanonicalField.assertSafe('key_id', keyId);
    return '$domain|$nonce|$deviceId|$bundleId|$sdkVersion|$keyId';
  }

  /// The per-request proof (Phase 6).
  ///
  /// [canonicalRequest] must be the string `RequestSigner.canonicalMessage`
  /// produced for this exact request — not a re-derivation of it. Passing it
  /// in rather than rebuilding it here is what guarantees the HMAC and the
  /// device proof describe the same bytes: they cannot drift, because there
  /// is only one construction.
  ///
  /// Throws [CanonicalFieldError] when [keyId] contains the delimiter.
  /// [canonicalRequest] is deliberately NOT checked here — it is already a
  /// complete, multi-field canonical string in its own right
  /// (`RequestSigner.canonicalMessage`, whose own fields were validated
  /// when it was built), and rejecting it for containing `|` would reject
  /// every legitimate request. Mirrors
  /// `device_binding.request_proof_message`'s identical scoping.
  static String requestMessage({
    required String canonicalRequest,
    required String keyId,
  }) {
    CanonicalField.assertSafe('key_id', keyId);
    return '$domain|$canonicalRequest|$keyId';
  }

  /// Header carrying the base64 device-key signature.
  static const String proofHeader = 'X-Rasp-Device-Proof';

  /// Header naming which registered key produced [proofHeader].
  ///
  /// Sent so the server can select the right public key without guessing,
  /// and so a proof made with a *replacement* key is recognisable as such
  /// rather than simply failing verification against the old one.
  static const String keyIdHeader = 'X-Rasp-Device-Key-Id';

  /// Build the two device-binding headers for a signed request.
  ///
  /// Returns an empty map when [signature] or [keyId] is absent — a device
  /// with no key sends no headers at all, which the server reads as an
  /// unbound (legacy) client rather than as a failed proof. Those are
  /// different verdicts and must stay different.
  static Map<String, String> headers({
    required String? keyId,
    required String? signature,
  }) {
    if (keyId == null || keyId.isEmpty) return const {};
    if (signature == null || signature.isEmpty) return const {};
    return {keyIdHeader: keyId, proofHeader: signature};
  }

  /// Convenience: the canonical request string for a signed request, taken
  /// from the one implementation that builds it.
  static String canonicalRequestFor({
    required String method,
    required String path,
    required String timestamp,
    required String nonce,
    required List<int> bodyBytes,
  }) =>
      RequestSigner.canonicalMessage(
        method: method,
        path: path,
        timestamp: timestamp,
        nonce: nonce,
        bodyBytes: bodyBytes,
      );
}
