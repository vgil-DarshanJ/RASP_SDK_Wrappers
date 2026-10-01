/// Phase 3 — the four-value decision vocabulary a
/// [SensitiveOperationPolicy] produces.
///
/// Deliberately **not** [ProtectionAction]. That ladder (allow < monitor <
/// warn < stepUp < block < lockSession < lockApp) is a device-wide
/// enforcement decision built from aggregate detection results — reusing it
/// here would conflate "the device overall looks risky" with "this specific
/// operation should require step-up," which is the wrong coupling: a device
/// sitting at `ProtectionAction.warn` should still be able to `ALLOW` a
/// `NORMAL`-sensitivity operation while being required to step up for a
/// `CRITICAL` one. See `docs/SENSITIVE_OPERATION_SECURITY_AUDIT.md` §3.
library;

enum SensitiveOperationAction {
  /// The operation may proceed with no additional friction.
  allow,

  /// The operation may proceed only after a caller-supplied, successful
  /// step-up authentication result is presented. See `step_up.dart`.
  stepUp,

  /// The operation is restricted — the host app should offer a narrower
  /// capability (e.g. a lower limit, a delayed execution, a manual review
  /// queue) rather than the full operation. The SDK does not define what
  /// "restricted" means operationally; that is host-app business logic.
  restrict,

  /// The operation must not proceed.
  block,
}

extension SensitiveOperationActionX on SensitiveOperationAction {
  String get wireName => name.toUpperCase();

  /// Ordinal rank — higher is more restrictive. Declaration order is the
  /// ranking, exactly like `ProtectionAction.index` already is for the
  /// device-wide ladder — this is the invariant Phase 15/19's property
  /// tests are written against.
  int get rank => index;

  /// `true` when `this` is at least as restrictive as [other] — the
  /// building block for "risk can only maintain or strengthen a decision."
  bool isAtLeastAsRestrictiveAs(SensitiveOperationAction other) =>
      rank >= other.rank;
}

/// Parses [SensitiveOperationAction] from its wire name, or `null`.
SensitiveOperationAction? sensitiveOperationActionFromWire(String? wire) {
  if (wire == null) return null;
  for (final value in SensitiveOperationAction.values) {
    if (value.wireName == wire) return value;
  }
  return null;
}
