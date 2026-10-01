/// Phase 4 — how sensitive a host-app operation is, as the host app
/// declares it.
///
/// ## This is not a threat severity, and not a risk score
///
/// `DetectionSeverity` answers "how bad is this finding" and `RiskPosture`
/// answers "how risky does the device look right now" — both are the SDK's
/// own judgment about the **device**. [OperationSensitivity] is the host
/// app's judgment about **the operation it is about to perform**, supplied
/// entirely by the caller because the SDK has no way to know that
/// `add_beneficiary` matters more than `view_balance` — it never interprets
/// operation semantics (see `transaction_integrity.dart`'s own doc comment).
///
/// The two dimensions are combined by [SensitiveOperationPolicy], never
/// conflated: a `CRITICAL`-sensitivity operation on a `trusted` device still
/// gets more scrutiny than a `NORMAL` one on the same device, and a
/// `NORMAL`-sensitivity operation on a `compromised` device can still be
/// blocked. Sensitivity sets the bar; trust/risk decide whether the device
/// clears it.
library;

enum OperationSensitivity {
  /// No special handling beyond ordinary integrity (tamper/replay/freshness).
  normal,

  /// Worth a stricter posture under degraded trust or elevated risk, but not
  /// worth demanding fresh authentication on a healthy device.
  elevated,

  /// Ordinarily requires step-up authentication regardless of device state,
  /// unless policy says otherwise.
  high,

  /// The host app's most sensitive class — a policy is expected to demand
  /// both step-up authentication and a trusted device/attestation state.
  critical,
}

extension OperationSensitivityX on OperationSensitivity {
  String get wireName => name.toUpperCase();

  /// Ordinal rank — higher is more sensitive. Declaration order is the
  /// ranking; a future value is added at the correct point in the enum, not
  /// given a separate numeric field to keep in sync.
  int get rank => index;
}

/// Parses [OperationSensitivity] from its wire name, or `null` for an
/// unrecognised value — never guessed, since guessing a sensitivity is a
/// security decision, not a convenience.
OperationSensitivity? operationSensitivityFromWire(String? wire) {
  if (wire == null) return null;
  for (final value in OperationSensitivity.values) {
    if (value.wireName == wire) return value;
  }
  return null;
}
