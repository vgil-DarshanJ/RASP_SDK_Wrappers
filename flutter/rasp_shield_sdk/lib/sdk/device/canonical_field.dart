/// Shared enforcement for the one invariant every `|`-delimited canonical
/// message in this SDK depends on: no field may contain the delimiter
/// itself.
///
/// ## Why this exists
///
/// `DeviceProof`'s activation/request messages and `RequestSigner`'s
/// canonical request string are all built by plain string interpolation —
/// `'$a|$b|$c'` — with no escaping and no length-prefixing. That is safe
/// **only** because every field that participates today (`nonce`,
/// `device_id`, `bundle_id`, `sdk_version`, `key_id`, HTTP method, path,
/// timestamp) happens not to contain `|` — not because anything enforced
/// it. A value that did contain `|` would let it shift which logical field
/// each byte range of the signed message belongs to: a `device_id` of
/// `"victim|com.good.app|9.9.9"` submitted where the message expects
/// `device_id|bundle_id|sdk_version` collapses into what looks like a
/// three-field sequence naming a different device and application
/// entirely.
///
/// This file makes that invariant explicit and enforced, mirroring
/// `app.licensing.tokens.assert_canonical_safe` on the backend exactly —
/// same rule, same rejection (never silent sanitisation), checked
/// independently on both sides of every proof. See
/// `docs/DEVICE_BINDING_CANONICALIZATION.md`.
library;

/// The character every canonical-message constructor in this codebase
/// joins fields with. A single source of truth so a future change to the
/// separator is one edit, not a grep-and-replace that must stay in
/// lockstep with the backend's `tokens.CANONICAL_DELIMITER`.
const String canonicalDelimiter = '|';

/// Thrown when a value cannot safely become part of a `|`-delimited
/// canonical message.
///
/// Deliberately a plain [Exception], not a return value: every call site
/// that constructs a canonical message is already inside a method that
/// either propagates naturally to a caller with its own error handling
/// (`ActivationManager.activate()`/`heartbeat()`'s existing broad `catch`,
/// which already converts any exception into `ActivationResult(status:
/// 'ERROR', ...)`) or is a pure function whose only two outcomes are "here
/// is the message" and "this cannot be turned into a message at all".
class CanonicalFieldError implements Exception {
  final String fieldName;
  final String reason;

  const CanonicalFieldError(this.fieldName, this.reason);

  @override
  String toString() => 'CanonicalFieldError($fieldName): $reason';
}

/// Enforcement for the canonical-delimiter invariant.
class CanonicalField {
  const CanonicalField._();

  /// Reject [value] if it cannot safely become part of a `|`-delimited
  /// canonical message.
  ///
  /// Deterministic and total: the same `(fieldName, value)` pair always
  /// produces the same outcome. Never trims, never strips the delimiter,
  /// never substitutes a placeholder — a value containing `|` is rejected
  /// outright. [fieldName] appears only in the thrown error's message,
  /// never in any canonical string.
  ///
  /// Returns [value] unchanged so this reads inline at each call site:
  /// `CanonicalField.assertSafe('nonce', nonce)`.
  static String assertSafe(String fieldName, String? value) {
    if (value == null) {
      throw CanonicalFieldError(fieldName, 'must not be null');
    }
    if (value.contains(canonicalDelimiter)) {
      throw CanonicalFieldError(
        fieldName,
        "may not contain the canonical delimiter '$canonicalDelimiter'",
      );
    }
    return value;
  }
}
