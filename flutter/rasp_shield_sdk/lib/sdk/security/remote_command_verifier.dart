import 'dart:convert';

import 'package:crypto/crypto.dart';

import '../device/canonical_field.dart';
import '../remote_command.dart';
import '../trust/config_canonical.dart';
import 'request_signer.dart';

/// Cryptographic Remote Command Integrity milestone — client side.
///
/// Mirrors `app/licensing/remote_command_integrity.py` exactly. Reuses
/// [RequestSigner.hmacOver] (the same HMAC-SHA256-keyed-by-`activation_token`
/// primitive [RequestSigner] already uses for request signing — no new
/// cryptography), [ConfigCanonicalizer] (the same deterministic JSON
/// canonicalization signed configuration already uses — no new
/// serialization format), and [CanonicalField] (the same delimiter-injection
/// guard every other canonical message in this codebase already applies).
///
/// ```
/// COMMAND_INTEGRITY_SIGNATURE =
///     HMAC-SHA256(activation_token,
///                  "RASP_REMOTE_COMMAND_V1|command_id|command_type|
///                   device_id|application_id|issued_at|nonce|payload_digest")
/// ```
///
/// **Domain-separated from request signing on purpose**: the leading
/// `RASP_REMOTE_COMMAND_V1` literal means a valid request signature can
/// never be presented as a valid command signature, or vice versa, even
/// though both use the same key material and the same underlying HMAC
/// primitive. See `docs/REMOTE_COMMAND_SECURITY.md` §2 for why this reuse
/// does not conflate "server authentication" (the heartbeat's own request
/// signature — unchanged, unrelated to this), "command integrity" (this),
/// "device proof" (`DeviceProof`, cryptographic Keystore-backed
/// proof-of-possession — unrelated to this), and "request authentication"
/// (the same request signature as above).
class RemoteCommandVerifier {
  const RemoteCommandVerifier();

  static const String _domain = 'RASP_REMOTE_COMMAND_V1';

  /// How stale a command's `issued_at` (minted at delivery time, on the
  /// backend's one-shot `QUEUED -> DELIVERED` transition) may be by the time
  /// this device verifies it. Wider than the 120s request-signing window —
  /// this covers processing time after a heartbeat response is *received*,
  /// not network transit — but still tight enough that a captured-and-
  /// replayed heartbeat response cannot be reapplied minutes or hours later.
  static const Duration freshnessWindow = Duration(minutes: 5);

  /// The exact string this layer signs. Mirrors
  /// `remote_command_integrity.canonical_command_message` exactly — see its
  /// doc comment for why `payload` is never inlined, only its digest.
  ///
  /// Throws [CanonicalFieldError] when any field contains the canonical `|`
  /// delimiter.
  static String canonicalMessage({
    required int commandId,
    required String commandType,
    required String deviceId,
    required String applicationId,
    required String issuedAt,
    required String nonce,
    required Map<String, dynamic> payload,
  }) {
    CanonicalField.assertSafe('command_type', commandType);
    CanonicalField.assertSafe('device_id', deviceId);
    CanonicalField.assertSafe('application_id', applicationId);
    CanonicalField.assertSafe('issued_at', issuedAt);
    CanonicalField.assertSafe('nonce', nonce);
    final payloadDigest =
        sha256.convert(utf8.encode(ConfigCanonicalizer.canonicalJson(payload))).toString();
    return '$_domain|$commandId|$commandType|$deviceId|$applicationId|'
        '$issuedAt|$nonce|$payloadDigest';
  }

  /// Verifies [command] against this device's own identity.
  ///
  /// [observedDeviceId]/[observedApplicationId] are what THIS device
  /// independently believes its own identity to be (`DeviceIdentity.get()`,
  /// `ActivationManager.bundleId()`) — compared against what the SIGNED
  /// command claims, so a command whose signature is valid but whose
  /// claimed identity does not match this device's own is still rejected.
  /// This is defense-in-depth on top of the cryptographic binding itself:
  /// the signature already cannot be forged for a different device (it is
  /// keyed by that device's own `activation_token`, which this device does
  /// not possess), but a naive implementation that skipped this explicit
  /// comparison would still be correct — this check exists so the failure
  /// mode is an explicit, named [RemoteCommandVerdict.deviceMismatch]
  /// rather than "the HMAC just happens not to match," which is harder to
  /// diagnose and to write a targeted security event for.
  RemoteCommandVerdict verify(
    RemoteCommand command, {
    required String activationToken,
    required String observedDeviceId,
    required String observedApplicationId,
    DateTime? now,
  }) {
    if (!command.hasIntegrityFields) return RemoteCommandVerdict.missing;

    final deviceId = command.deviceId!;
    final applicationId = command.applicationId!;
    final issuedAt = command.issuedAt!;
    final nonce = command.nonce!;
    final signature = command.signature!;

    if (deviceId != observedDeviceId) return RemoteCommandVerdict.deviceMismatch;
    if (applicationId != observedApplicationId) {
      return RemoteCommandVerdict.applicationMismatch;
    }

    final issuedAtTime = DateTime.tryParse(issuedAt);
    if (issuedAtTime == null) return RemoteCommandVerdict.malformed;

    final effectiveNow = (now ?? DateTime.now()).toUtc();
    final drift = effectiveNow.difference(issuedAtTime.toUtc()).abs();
    if (drift > freshnessWindow) return RemoteCommandVerdict.expired;

    if (command.expiresAt != null) {
      final expiresAtTime = DateTime.tryParse(command.expiresAt!);
      if (expiresAtTime != null && effectiveNow.isAfter(expiresAtTime.toUtc())) {
        return RemoteCommandVerdict.expired;
      }
    }

    final String message;
    try {
      message = canonicalMessage(
        commandId: command.id,
        commandType: command.type,
        deviceId: deviceId,
        applicationId: applicationId,
        issuedAt: issuedAt,
        nonce: nonce,
        payload: command.payload,
      );
    } on CanonicalFieldError {
      return RemoteCommandVerdict.malformed;
    } catch (_) {
      return RemoteCommandVerdict.error;
    }

    final String expected;
    try {
      expected = RequestSigner.hmacOver(activationToken, message);
    } catch (_) {
      return RemoteCommandVerdict.error;
    }

    if (!_constantTimeEquals(expected, signature.trim().toLowerCase())) {
      return RemoteCommandVerdict.invalid;
    }

    return RemoteCommandVerdict.valid;
  }

  /// Constant-time string comparison — mirrors `hmac.compare_digest`'s
  /// intent on the backend. Both signature strings are the same fixed
  /// length (64 lowercase hex characters) in the valid case, so comparing
  /// by XOR-accumulation rather than short-circuiting `==` costs nothing
  /// meaningful here and is cheap defense-in-depth against local timing
  /// side channels.
  static bool _constantTimeEquals(String a, String b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a.codeUnitAt(i) ^ b.codeUnitAt(i);
    }
    return diff == 0;
  }
}

/// Outcome of [RemoteCommandVerifier.verify]. Mirrors
/// `RequestSignatureResult`'s shape (a named enum, not a boolean) and its
/// discipline: only [valid] means "execute this" — every other value is
/// either a failure or an absence of proof, never folded into a pass.
enum RemoteCommandVerdict {
  /// Every check passed — safe to execute.
  valid,

  /// No integrity fields at all — a command from a backend that predates
  /// this milestone. Distinct from [malformed]: this is "no proof offered,"
  /// not "proof offered but broken."
  missing,

  /// An integrity field could not be parsed (malformed timestamp, a
  /// canonical-delimiter violation).
  malformed,

  /// The signature does not match what this device computes.
  invalid,

  /// `issued_at` is outside [RemoteCommandVerifier.freshnessWindow], or
  /// `expires_at` has passed.
  expired,

  /// The command's `device_id` does not match this device's own observed
  /// identity.
  deviceMismatch,

  /// The command's `application_id` does not match this device's own
  /// observed bundle id.
  applicationMismatch,

  /// This exact command id has already been executed (see
  /// `RemoteCommandExecutionLedger`) — a replay, not a fresh command.
  replayed,

  /// Verification itself threw. Never treated as [valid].
  error,
}
