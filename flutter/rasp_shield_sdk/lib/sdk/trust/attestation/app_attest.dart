import 'package:flutter/services.dart';

import 'attestation_challenge.dart';
import 'attestation_result.dart';

/// Apple App Attest key lifecycle stage.
///
/// Unlike Play Integrity (stateless per-request), App Attest is built around
/// a persistent device-generated keypair: generate once, attest once, then
/// assert repeatedly against the same key. This enum exists so
/// [AppAttestor] can report which stage it reached without conflating "no
/// key exists yet" with "attestation failed."
enum AppAttestKeyState {
  /// No key has ever been generated on this device/app install.
  none,

  /// A key was generated but has not yet been attested with Apple.
  generated,

  /// The key was attested (Apple issued an attestation object for it) and is
  /// ready to produce assertions.
  attested,
}

/// iOS's Apple App Attest boundary.
///
/// ## Current state: architecture only
///
/// Every method calls `com.shieldsdk.rasp/native_bridge`, which no native
/// iOS side answers — the same documented, honest `MissingPluginException`
/// → [AttestationStatus.unavailable] pattern [PlayIntegrityAttestor] uses.
/// See `docs/APP_ATTEST.md` for what a real native implementation needs
/// (`DCAppAttestService`, an Apple Developer Program membership, a real
/// device with a Secure Enclave).
///
/// **PHYSICAL DEVICE REQUIRED** for any of this to produce genuine output —
/// App Attest keys are Secure-Enclave-backed and cannot be generated in a
/// simulator. See `docs/ATTESTATION_ARCHITECTURE.md` §3.
class AppAttestor {
  const AppAttestor();

  static const MethodChannel _channel =
      MethodChannel('com.shieldsdk.rasp/native_bridge');

  /// Whether App Attest is supported on this device at all
  /// (`DCAppAttestService.isSupported` — false on simulators and devices
  /// without a Secure Enclave). `null` when the check itself could not run
  /// (no native implementation).
  Future<bool?> isSupported() async {
    try {
      return await _channel.invokeMethod<bool>('appAttestIsSupported');
    } on MissingPluginException {
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Generates a new App Attest key. Returns the opaque key identifier Apple
  /// assigns, or `null` if unavailable.
  Future<String?> generateKey() async {
    try {
      return await _channel.invokeMethod<String>('appAttestGenerateKey');
    } on MissingPluginException {
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Requests the one-time attestation object for [keyId], bound to
  /// [challenge]'s nonce as the client-data hash Apple's API requires.
  /// Returns base64 CBOR, or `null` if unavailable.
  Future<String?> attestKey(String keyId, AttestationChallenge challenge) async {
    try {
      return await _channel.invokeMethod<String>('appAttestAttestKey', {
        'key_id': keyId,
        'nonce': challenge.nonce,
      });
    } on MissingPluginException {
      return null;
    } catch (_) {
      return null;
    }
  }

  /// Requests an assertion (a lightweight, repeatable proof-of-possession
  /// for an already-attested key) bound to [challenge]. Returns base64 CBOR,
  /// or `null` if unavailable.
  Future<String?> generateAssertion(String keyId, AttestationChallenge challenge) async {
    try {
      return await _channel.invokeMethod<String>('appAttestGenerateAssertion', {
        'key_id': keyId,
        'nonce': challenge.nonce,
      });
    } on MissingPluginException {
      return null;
    } catch (_) {
      return null;
    }
  }
}

/// Normalizes an App Attest attestation/assertion **structural summary**
/// into an [AttestationResult].
///
/// ## The honest limit of this parser
///
/// A real App Attest attestation object is CBOR-encoded and contains an
/// X.509 certificate chain rooted at Apple's public App Attest root CA; a
/// real assertion is a COSE-signed structure covering a client-data hash.
/// Full cryptographic verification of either needs a CBOR/COSE decoder and
/// certificate-chain validation — genuinely implementable offline in
/// principle (Apple's root is public), but **never proven correct here**,
/// because no genuine Apple-issued attestation object exists in this
/// environment to test it against (`ATTESTATION_ARCHITECTURE.md` §3).
///
/// This parser therefore accepts an **already-decoded structural summary** —
/// the fields Apple's documentation specifies
/// (`developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server`):
/// RP ID hash, counter, AAGUID, credential id, and the client-data hash the
/// assertion was computed over — and performs the checks that do not require
/// the CBOR/COSE/cert-chain layer: RP ID (bundle id) binding, counter
/// monotonicity (replay), and challenge/nonce binding. The
/// signature-over-the-attestation-object step itself is explicitly **not**
/// performed here; production needs a real implementation of that layer,
/// stated plainly rather than simulated. See `docs/APP_ATTEST.md` §5.
class AppAttestAssertionParser {
  const AppAttestAssertionParser();

  /// [summary] is the already-decoded structural fields a real CBOR/COSE
  /// decoder would extract from an assertion object.
  AttestationResult parse(Map<String, dynamic> summary) {
    try {
      final rpIdHash = summary['rp_id_hash'] as String?;
      final bundleId = summary['bundle_id'] as String?;
      final counter = summary['counter'];
      final keyId = summary['key_id'] as String?;
      final clientDataHash = summary['client_data_hash'] as String?;
      final nonce = summary['nonce'] as String?;
      final timestampIso = summary['timestamp'] as String?;

      if (rpIdHash == null || keyId == null) {
        return const AttestationResult(
          platform: AttestationPlatform.ios,
          provider: AttestationProvider.appAttest,
          status: AttestationStatus.unknown,
          error: 'assertion summary missing required fields',
        );
      }

      final evidence = <AttestationEvidence>[
        AttestationEvidence('rp_id_hash', rpIdHash),
        if (counter != null) AttestationEvidence('counter', counter.toString()),
      ];

      // A client-data hash that does not match the nonce means the assertion
      // was not computed over this challenge — never a pass. This is the one
      // structural binding check meaningful without the full COSE signature
      // verification: it is still just a hash-equality check on data this
      // parser was handed, not proof the *signature* over that data is
      // genuine — see the class doc's honest limit.
      final bound = clientDataHash != null && clientDataHash == nonce;

      return AttestationResult(
        platform: AttestationPlatform.ios,
        provider: AttestationProvider.appAttest,
        // Never `valid`: this parser explicitly does not perform signature
        // verification (the class doc's stated limit), so it can only ever
        // report `unknown` — structurally plausible, cryptographically
        // unproven — until a real COSE/cert-chain verifier exists.
        status: bound ? AttestationStatus.unknown : AttestationStatus.invalid,
        packageIdentity: bundleId,
        nonce: clientDataHash,
        keyId: keyId,
        timestamp: timestampIso == null ? null : DateTime.tryParse(timestampIso),
        evidence: evidence,
        error: bound
            ? 'signature verification not implemented — see docs/APP_ATTEST.md'
            : 'client data hash does not match the issued challenge',
      );
    } catch (e) {
      return const AttestationResult(
        platform: AttestationPlatform.ios,
        provider: AttestationProvider.appAttest,
        status: AttestationStatus.error,
        error: 'malformed App Attest assertion summary',
      );
    }
  }
}
