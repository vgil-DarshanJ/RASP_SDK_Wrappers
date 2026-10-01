/// Validates the *binding* claims of an entitlement token against what this
/// install can actually observe.
///
/// ## Which layer checks what (Phase 7)
///
/// A licence token is validated by three cooperating layers, and this file
/// owns exactly one of them. Recorded here because "the token was validated"
/// is otherwise an ambiguous statement:
///
/// | Property | Owner |
/// |---|---|
/// | Signature | `LicenseManager.verifyToken` (HMAC over the licence key) |
/// | Expiry / grace | `LicenseManager._statusFromPayload` |
/// | Trusted time | `TrustedClock` via `_assessClock` |
/// | Entitlements | `Entitlements.fromJson` + `LicenseManager.allows` |
/// | Revocation (live) | the server's own `/heartbeat` verdict |
/// | **Tenant, application, bundle, certificate, device id, device key, binding lifecycle** | **this file** |
///
/// Nothing here parses or trusts an unverified token: [validate] is only
/// ever called with a payload whose signature already verified, which is why
/// it may compare claims at face value.
///
/// ## The comparison rule
///
/// Every claim is compared **only when both sides are present**. An absent
/// claim, or an observation this platform could not make, yields *no
/// finding* — not a pass and not a failure. Inventing a mismatch out of a
/// value we could not read would lock legitimate devices out of their own
/// licence for a platform limitation; inventing a match would be the
/// fail-open this whole milestone exists to remove. The distinction is
/// carried in [LicenseBindingResult.isContradicted] vs
/// [LicenseBindingResult.isIndeterminate].
///
/// See `docs/LICENSE_DEVICE_BINDING.md`.
library;

import '../trust/certificate_trust.dart';
import 'device_binding_state.dart';
import 'device_key.dart';

/// One binding claim that was checked and found wrong.
enum LicenseBindingFailure {
  tenantMismatch,
  applicationMismatch,
  certificateMismatch,
  deviceIdMismatch,
  deviceKeyMismatch,
  deviceKeyMissing,
  deviceKeyRevoked,
  deviceProofInvalid,
}

extension LicenseBindingFailureX on LicenseBindingFailure {
  String get wireName => name
      .replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}')
      .toUpperCase();

  /// Operator-facing text. Names the *category* of mismatch and never the
  /// values involved — no tenant id, bundle id, fingerprint, device id or
  /// key id appears here, and a test asserts it.
  String get reason {
    switch (this) {
      case LicenseBindingFailure.tenantMismatch:
        return 'This licence was issued to a different organisation';
      case LicenseBindingFailure.applicationMismatch:
        return 'This licence was issued to a different application';
      case LicenseBindingFailure.certificateMismatch:
        return 'This licence was issued against a different signing identity';
      case LicenseBindingFailure.deviceIdMismatch:
        return 'This licence seat belongs to a different device';
      case LicenseBindingFailure.deviceKeyMismatch:
        return 'This licence is bound to a different device key';
      case LicenseBindingFailure.deviceKeyMissing:
        return 'This licence is bound to a device key that is not present here';
      case LicenseBindingFailure.deviceKeyRevoked:
        return 'The device binding for this licence is not active';
      case LicenseBindingFailure.deviceProofInvalid:
        return 'The device could not prove possession of its binding key';
    }
  }
}

/// What this install observes about itself, for [LicenseBindingValidator].
///
/// Every field is nullable because "could not read it" is a first-class
/// outcome — the same reason `TrustInputs` is shaped this way.
class LicenseBindingObservation {
  final String? tenantId;
  final String? bundleId;
  final String? deviceId;

  /// This build's own signing certificate fingerprint, in any of the formats
  /// `CertificateTrustStore.normalize` accepts.
  final String? signingCertificate;

  /// This device's binding key, or `null` when none could be loaded.
  final DeviceKeyInfo? deviceKey;

  /// Why [deviceKey] is `null`, when it is. Distinguishes "this platform has
  /// no keystore" (indeterminate) from "the keystore works and this device
  /// simply has no key" (a contradiction, when the token claims one).
  final DeviceKeyBacking keyBacking;

  /// Whether the platform keystore answered at all, independently of whether
  /// it holds a key.
  ///
  /// See `DeviceKeyManager.keystoreAvailable`. This is the signal that
  /// separates "this platform has no keystore" (indeterminate) from "the
  /// keystore works and this key is not in it" (the clone signature).
  final bool keystoreAvailable;

  /// The server's last known lifecycle verdict for this seat's binding.
  final DeviceBindingLifecycle lifecycle;

  /// Whether the most recent device proof this install produced was accepted.
  /// `null` when no proof has been attempted — the normal state offline.
  final bool? proofAccepted;

  const LicenseBindingObservation({
    this.tenantId,
    this.bundleId,
    this.deviceId,
    this.signingCertificate,
    this.deviceKey,
    this.keyBacking = DeviceKeyBacking.unavailable,
    this.keystoreAvailable = false,
    this.lifecycle = DeviceBindingLifecycle.unbound,
    this.proofAccepted,
  });

  /// The observation an install makes when it can see nothing at all — no
  /// platform, no keystore. Every check is skipped and the result is
  /// indeterminate, which is the honest answer in a unit test and on the
  /// web target alike.
  static const LicenseBindingObservation none = LicenseBindingObservation();
}

/// The outcome of validating one token's binding claims.
class LicenseBindingResult {
  /// The device-key verdict specifically, for the trust engine's
  /// `DEVICE_KEY_*` evidence.
  final DeviceBindingVerdict verdict;

  /// Every claim that was checked and found wrong. Empty when nothing was
  /// contradicted — which is *not* the same as everything having been
  /// checked.
  final List<LicenseBindingFailure> failures;

  const LicenseBindingResult({
    required this.verdict,
    this.failures = const [],
  });

  /// The token's binding claims were checked and all of them held, including
  /// a device key.
  bool get isBound => verdict.isSatisfied && failures.isEmpty;

  /// At least one claim was actively contradicted. This is the condition
  /// that must deny entitlement.
  bool get isContradicted => failures.isNotEmpty || verdict.isContradicted;

  /// Nothing was contradicted, and nothing was proven either.
  bool get isIndeterminate => !isBound && !isContradicted;

  /// The first failure's reason, or the verdict's, or `null`. Deliberately
  /// one line: it is rendered to an end user in a licence-gate screen.
  String? get reason =>
      failures.isNotEmpty ? failures.first.reason : verdict.reason;

  @override
  String toString() => 'LicenseBindingResult(${verdict.wireName}, '
      '${failures.map((f) => f.wireName).join(",")})';
}

/// Compares a verified token payload's binding claims with [observation].
///
/// Stateless and pure — no I/O, no platform, no clock — so every case in
/// `docs/DEVICE_BINDING_TEST_MATRIX.md` is a deterministic unit test rather
/// than something that needs a device to reproduce.
class LicenseBindingValidator {
  const LicenseBindingValidator();

  LicenseBindingResult validate({
    required Map<String, dynamic> payload,
    required LicenseBindingObservation observation,
  }) {
    final failures = <LicenseBindingFailure>[];

    void compare(
      Object? claimed,
      String? observed,
      LicenseBindingFailure failure, {
      String Function(String)? normalize,
    }) {
      final left = claimed?.toString().trim() ?? '';
      final right = observed?.trim() ?? '';
      if (left.isEmpty || right.isEmpty) return;
      final a = normalize?.call(left) ?? left;
      final b = normalize?.call(right) ?? right;
      if (a != b) failures.add(failure);
    }

    compare(payload['tenant_id'], observation.tenantId,
        LicenseBindingFailure.tenantMismatch);
    compare(payload['bundle_id'], observation.bundleId,
        LicenseBindingFailure.applicationMismatch);
    compare(payload['device_id'], observation.deviceId,
        LicenseBindingFailure.deviceIdMismatch);
    compare(
      payload['signing_cert_sha256'],
      observation.signingCertificate,
      LicenseBindingFailure.certificateMismatch,
      normalize: CertificateTrustStore.normalize,
    );

    final verdict = _deviceKeyVerdict(payload, observation);
    switch (verdict) {
      case DeviceBindingVerdict.keyMismatch:
        failures.add(LicenseBindingFailure.deviceKeyMismatch);
      case DeviceBindingVerdict.keyMissing:
        failures.add(LicenseBindingFailure.deviceKeyMissing);
      case DeviceBindingVerdict.keyRevoked:
        failures.add(LicenseBindingFailure.deviceKeyRevoked);
      case DeviceBindingVerdict.proofInvalid:
        failures.add(LicenseBindingFailure.deviceProofInvalid);
      case DeviceBindingVerdict.valid:
      case DeviceBindingVerdict.notBound:
      case DeviceBindingVerdict.keyUnavailable:
      case DeviceBindingVerdict.keyError:
        break;
    }

    return LicenseBindingResult(
      verdict: verdict,
      failures: List.unmodifiable(failures),
    );
  }

  /// The device-key half, in claim-then-observation order.
  ///
  /// Read top to bottom, the precedence is: a token that claims no key can
  /// never fail this check; a proof that was tried and rejected outranks
  /// everything (it is the only *positive* evidence of a forgery); a
  /// lifecycle that is not ACTIVE outranks a key comparison, because an
  /// operator's revoke beats a matching key; and only then are the two key
  /// ids compared.
  DeviceBindingVerdict _deviceKeyVerdict(
    Map<String, dynamic> payload,
    LicenseBindingObservation observation,
  ) {
    final claimed = payload['device_key_id']?.toString().trim().toUpperCase();

    if (claimed == null || claimed.isEmpty) {
      // Every token minted before this milestone, and every UNBOUND seat.
      return DeviceBindingVerdict.notBound;
    }

    if (observation.proofAccepted == false) {
      return DeviceBindingVerdict.proofInvalid;
    }

    if (observation.lifecycle.isContradicted) {
      return DeviceBindingVerdict.keyRevoked;
    }

    final local = observation.deviceKey;
    if (local == null) {
      // The token asserts a binding. Whether its absence here is damning
      // depends entirely on *why* we have no key: a platform with no
      // keystore proves nothing, while a working keystore that simply does
      // not contain this seat's key is the clone signature.
      if (observation.keyBacking == DeviceKeyBacking.error) {
        return DeviceBindingVerdict.keyError;
      }
      if (!observation.keystoreAvailable) {
        return DeviceBindingVerdict.keyUnavailable;
      }
      return DeviceBindingVerdict.keyMissing;
    }

    if (!local.isUsable) return DeviceBindingVerdict.keyError;
    if (local.keyId.toUpperCase() != claimed) {
      return DeviceBindingVerdict.keyMismatch;
    }

    // A key that matches, on a seat whose binding the server has not
    // confirmed as ACTIVE, is not yet a satisfied binding. UNBOUND here
    // means the token carried a key id the server never activated, which is
    // an inconsistency we report rather than resolve in the device's favour.
    return observation.lifecycle.isBindingSatisfied
        ? DeviceBindingVerdict.valid
        : DeviceBindingVerdict.keyUnavailable;
  }
}
