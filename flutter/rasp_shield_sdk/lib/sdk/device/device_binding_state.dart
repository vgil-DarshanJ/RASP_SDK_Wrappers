/// The lifecycle of one device's cryptographic binding to a licence seat.
///
/// Device binding without a recovery path is a support incident waiting to
/// happen: phones are replaced, factory-reset, and restored from backup, and
/// a legitimate customer whose keystore was wiped must be able to get back
/// in without an engineer editing a database row. These states are that
/// recovery path, made explicit. See `docs/DEVICE_REPLACEMENT.md`.
library;

/// Server-authoritative state of the device-key binding on a seat.
///
/// Mirrors `sdk_activations.device_binding_status` (migration 037)
/// one-for-one. The four operational states are the ones the milestone
/// specifies — ACTIVE, REPLACEMENT_PENDING, REVOKED, EXPIRED — plus
/// [unbound], which is not a fifth policy but the honest name for the state
/// every seat is in before it has ever registered a key, and the state every
/// device already in the field is in right now. Folding it into ACTIVE would
/// mean claiming a binding that does not exist; folding it into REVOKED
/// would lock out every existing install.
enum DeviceBindingLifecycle {
  /// No device key has ever been registered for this seat. The pre-milestone
  /// state, and the state of every SDK build that predates device binding.
  /// Nothing is enforced; nothing is claimed.
  unbound,

  /// A device key is registered and is the one this seat expects.
  active,

  /// A *different* device key was presented for a seat that already had one.
  /// The seat is not revoked and the customer is not locked out of their
  /// existing device — but the new device is not authorised until an
  /// operator approves the replacement. This is the state a stolen token
  /// lands in when it is replayed from another handset, and it is
  /// deliberately the same state a genuine phone upgrade lands in: the
  /// server cannot tell those two apart, and a human can.
  replacementPending,

  /// The binding was revoked by an operator. Terminal for that key.
  revoked,

  /// The binding aged out — the seat has not presented its key within the
  /// operator-configured window.
  expired,
}

extension DeviceBindingLifecycleX on DeviceBindingLifecycle {
  /// Stable `SCREAMING_SNAKE_CASE` wire name.
  String get wireName => name
      .replaceAllMapped(RegExp('[A-Z]'), (m) => '_${m[0]}')
      .toUpperCase();

  /// The single state in which a registered key authorises this seat.
  ///
  /// Note [unbound] is deliberately **not** authorised-by-binding: a seat
  /// with no key is authorised by the licence handshake alone, exactly as it
  /// was before this milestone. Callers ask [enforces] to tell those apart.
  bool get isBindingSatisfied => this == DeviceBindingLifecycle.active;

  /// Whether this seat has a binding at all, and therefore whether a device
  /// proof is required of it. `false` only for [unbound].
  bool get enforces => this != DeviceBindingLifecycle.unbound;

  /// States in which the binding actively contradicts this install, as
  /// opposed to merely not being established.
  bool get isContradicted =>
      this == DeviceBindingLifecycle.replacementPending ||
      this == DeviceBindingLifecycle.revoked ||
      this == DeviceBindingLifecycle.expired;

  /// Parse a wire name. Anything unrecognised is [unbound] — an unreadable
  /// status must never be read as [active].
  static DeviceBindingLifecycle parse(Object? raw) {
    switch (raw?.toString().toUpperCase()) {
      case 'ACTIVE':
        return DeviceBindingLifecycle.active;
      case 'REPLACEMENT_PENDING':
        return DeviceBindingLifecycle.replacementPending;
      case 'REVOKED':
        return DeviceBindingLifecycle.revoked;
      case 'EXPIRED':
        return DeviceBindingLifecycle.expired;
      default:
        return DeviceBindingLifecycle.unbound;
    }
  }
}

/// The outcome of checking this install against the device binding a licence
/// token asserts.
///
/// Seven values, matching the seven `DEVICE_KEY_*` / `DEVICE_PROOF_*`
/// evidence codes the trust engine emits, so there is a one-to-one mapping
/// and no translation table to drift.
enum DeviceBindingVerdict {
  /// The token's key claim matches this device's key, and the binding is
  /// ACTIVE.
  valid,

  /// The token asserts no device key. Not a failure: it is what every
  /// pre-milestone token and every UNBOUND seat looks like.
  notBound,

  /// The token asserts a key and this device holds a **different** one.
  /// The clone signature: a copied install generates its own key because the
  /// original's private key is non-exportable.
  keyMismatch,

  /// The token asserts a key and this device holds **none**. A seat that was
  /// issued with a binding is running somewhere that never had it.
  keyMissing,

  /// The binding lifecycle says REVOKED, REPLACEMENT_PENDING or EXPIRED.
  keyRevoked,

  /// A proof was produced and did not verify.
  proofInvalid,

  /// No keystore on this platform, or the native surface is not registered.
  /// Indeterminate, never a pass and never a failure.
  keyUnavailable,

  /// The keystore was reachable and threw.
  keyError,
}

extension DeviceBindingVerdictX on DeviceBindingVerdict {
  /// The one verdict that means "this device is the bound device".
  bool get isSatisfied => this == DeviceBindingVerdict.valid;

  /// The binding was actively contradicted — this install is provably not
  /// the one the seat was issued to. These are the verdicts that must deny
  /// entitlement rather than degrade it.
  bool get isContradicted =>
      this == DeviceBindingVerdict.keyMismatch ||
      this == DeviceBindingVerdict.keyMissing ||
      this == DeviceBindingVerdict.keyRevoked ||
      this == DeviceBindingVerdict.proofInvalid;

  /// No verdict could be reached.
  ///
  /// [notBound] belongs here rather than with [isSatisfied]: a token that
  /// asserts nothing has proven nothing. It is not a threat either, which is
  /// exactly what indeterminate means.
  bool get isIndeterminate =>
      this == DeviceBindingVerdict.notBound ||
      this == DeviceBindingVerdict.keyUnavailable ||
      this == DeviceBindingVerdict.keyError;

  /// Stable wire name, matching the trust-evidence codes:
  /// `DEVICE_KEY_VALID`, `DEVICE_KEY_MISMATCH`, `DEVICE_KEY_MISSING`,
  /// `DEVICE_KEY_REVOKED`, `DEVICE_PROOF_INVALID`,
  /// `DEVICE_KEY_UNAVAILABLE`, `DEVICE_KEY_ERROR`, `DEVICE_KEY_NOT_BOUND`.
  String get wireName {
    switch (this) {
      case DeviceBindingVerdict.valid:
        return 'DEVICE_KEY_VALID';
      case DeviceBindingVerdict.notBound:
        return 'DEVICE_KEY_NOT_BOUND';
      case DeviceBindingVerdict.keyMismatch:
        return 'DEVICE_KEY_MISMATCH';
      case DeviceBindingVerdict.keyMissing:
        return 'DEVICE_KEY_MISSING';
      case DeviceBindingVerdict.keyRevoked:
        return 'DEVICE_KEY_REVOKED';
      case DeviceBindingVerdict.proofInvalid:
        return 'DEVICE_PROOF_INVALID';
      case DeviceBindingVerdict.keyUnavailable:
        return 'DEVICE_KEY_UNAVAILABLE';
      case DeviceBindingVerdict.keyError:
        return 'DEVICE_KEY_ERROR';
    }
  }

  /// Operator-facing reason, or `null` when there is nothing to explain.
  ///
  /// Carries no key id, no public key, no token and no device id — the same
  /// no-secret rule `TrustEvidence.detail` follows.
  String? get reason {
    switch (this) {
      case DeviceBindingVerdict.valid:
      case DeviceBindingVerdict.notBound:
        return null;
      case DeviceBindingVerdict.keyMismatch:
        return 'This licence is bound to a different device key';
      case DeviceBindingVerdict.keyMissing:
        return 'This licence is bound to a device key that is not present here';
      case DeviceBindingVerdict.keyRevoked:
        return 'The device binding for this licence is not active';
      case DeviceBindingVerdict.proofInvalid:
        return 'The device could not prove possession of its binding key';
      case DeviceBindingVerdict.keyUnavailable:
        return 'No device keystore is available on this platform';
      case DeviceBindingVerdict.keyError:
        return 'The device keystore could not be read';
    }
  }
}
