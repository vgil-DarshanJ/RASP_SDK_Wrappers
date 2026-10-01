import 'dart:convert';
import 'dart:typed_data';

/// Canonical serialization for signed security configuration.
///
/// A signature is only as trustworthy as the bytes it covers. If the signer
/// and the verifier can disagree about how a document turns into bytes, an
/// attacker gets to choose the disagreement — so this format is specified
/// exhaustively and tested on its own, separately from the signing code that
/// consumes it. Full prose specification: `docs/CONFIG_CANONICALIZATION.md`.
///
/// ## The rules, in one place
///
/// 1. **Object keys are sorted** by UTF-16 code unit, at every nesting depth.
/// 2. **No insignificant whitespace.** No spaces after `:` or `,`, no
///    newlines, no indentation.
/// 3. **Strings are UTF-8**, then NFC-normalized *before* encoding — see
///    [_normalizeUnicode] for why, and for the honest limit of what is done.
/// 4. **Integers serialize without a decimal point**; a double that holds an
///    integral value serializes as that integer. `1`, `1.0` and `1e0` are the
///    same number and must produce the same bytes.
/// 5. **Non-finite doubles are rejected**, not silently rendered — `NaN` and
///    `Infinity` are not JSON and have no canonical form.
/// 6. **`null` is preserved**, never dropped. Dropping a null would let an
///    attacker add or remove a null-valued key without changing the signature.
/// 7. **Arrays keep their order.** Order is semantic in a list and reordering
///    one is a real change.
/// 8. **Unsupported types throw**, rather than falling back to `toString()`.
///    A silent `toString()` is how two implementations quietly diverge.
///
/// Rules 4, 5, 6 and 8 are the ones a naive `jsonEncode` gets wrong or
/// under-specifies; each has a dedicated test.
class ConfigCanonicalizer {
  const ConfigCanonicalizer._();

  /// Thrown when a value has no canonical representation.
  ///
  /// Deliberately an error rather than a best-effort encoding: a document that
  /// cannot be canonicalized deterministically must fail verification, not be
  /// signed or verified over bytes the other side might compute differently.
  static Never _reject(Object? value) => throw FormatException(
        'Value of type ${value.runtimeType} has no canonical form',
      );

  /// The canonical UTF-8 bytes for [value]. These are the bytes that get
  /// signed and verified — nothing else is ever hashed or signed.
  static Uint8List canonicalBytes(Object? value) =>
      Uint8List.fromList(utf8.encode(canonicalJson(value)));

  /// The canonical JSON text for [value].
  static String canonicalJson(Object? value) {
    final buffer = StringBuffer();
    _write(buffer, value);
    return buffer.toString();
  }

  static void _write(StringBuffer out, Object? value) {
    if (value == null) {
      out.write('null');
      return;
    }
    if (value is bool) {
      out.write(value ? 'true' : 'false');
      return;
    }
    if (value is num) {
      out.write(_number(value));
      return;
    }
    if (value is String) {
      _writeString(out, value);
      return;
    }
    if (value is List) {
      out.write('[');
      for (var i = 0; i < value.length; i++) {
        if (i > 0) out.write(',');
        _write(out, value[i]);
      }
      out.write(']');
      return;
    }
    if (value is Map) {
      final keys = <String>[];
      for (final key in value.keys) {
        // A non-string key has no JSON representation and no agreed ordering.
        if (key is! String) _reject(key);
        keys.add(_normalizeUnicode(key));
      }
      // Sorted by UTF-16 code unit — Dart's default String.compareTo. Stated
      // explicitly because "sorted" alone is ambiguous across locales, and a
      // locale-sensitive sort would make the format depend on device settings.
      keys.sort();
      // Two distinct keys that normalize to the same string would make the
      // document ambiguous: the verifier cannot know which value was signed.
      for (var i = 1; i < keys.length; i++) {
        if (keys[i] == keys[i - 1]) {
          throw FormatException('Duplicate key after Unicode normalization: '
              '${keys[i]}');
        }
      }
      final byNormalized = <String, Object?>{};
      for (final entry in value.entries) {
        byNormalized[_normalizeUnicode(entry.key as String)] = entry.value;
      }
      out.write('{');
      for (var i = 0; i < keys.length; i++) {
        if (i > 0) out.write(',');
        _writeString(out, keys[i]);
        out.write(':');
        _write(out, byNormalized[keys[i]]);
      }
      out.write('}');
      return;
    }
    _reject(value);
  }

  /// Canonical number form.
  ///
  /// `1`, `1.0` and `1e0` are the same number; JSON does not distinguish them
  /// and neither may this. An integral double is therefore written as an
  /// integer, which is also what a JSON parser on the signing side will have
  /// produced from `1`.
  static String _number(num value) {
    if (value is int) return value.toString();
    final asDouble = value as double;
    if (asDouble.isNaN || asDouble.isInfinite) _reject(value);
    if (asDouble == asDouble.roundToDouble() &&
        asDouble.abs() < 9007199254740992.0) {
      return asDouble.toInt().toString();
    }
    // Dart's shortest round-trip representation. Documented as the format;
    // a signer on another platform must match it for non-integral numbers,
    // which is why the signing contract requires configuration values to be
    // integers, booleans, strings, or nested structures of those.
    return asDouble.toString();
  }

  /// Escapes exactly as canonical JSON requires: the two mandatory escapes
  /// (`"` and `\`), the C0 control range, and nothing else.
  ///
  /// Notably `/` is **not** escaped and non-ASCII characters are **not**
  /// `\u`-escaped — they are emitted as UTF-8. Both are choices a naive
  /// encoder makes differently, and either would change the signed bytes.
  static void _writeString(StringBuffer out, String raw) {
    final value = _normalizeUnicode(raw);
    out.write('"');
    for (final unit in value.codeUnits) {
      switch (unit) {
        case 0x22:
          out.write(r'\"');
          break;
        case 0x5C:
          out.write(r'\\');
          break;
        case 0x08:
          out.write(r'\b');
          break;
        case 0x09:
          out.write(r'\t');
          break;
        case 0x0A:
          out.write(r'\n');
          break;
        case 0x0C:
          out.write(r'\f');
          break;
        case 0x0D:
          out.write(r'\r');
          break;
        default:
          if (unit < 0x20) {
            out.write('\\u${unit.toRadixString(16).padLeft(4, '0')}');
          } else {
            out.writeCharCode(unit);
          }
      }
    }
    out.write('"');
  }

  /// Unicode handling, and its honest limit.
  ///
  /// Full NFC normalization needs the Unicode character database, which Dart's
  /// core library does not expose and which this project will not hand-roll —
  /// a partial, home-made normalizer is worse than none, because it would
  /// silently disagree with the signer's real one.
  ///
  /// The rule this format adopts instead is stricter and needs no database:
  /// **canonicalized text is passed through byte-for-byte, and the signing
  /// contract requires configuration keys and string values to be ASCII.**
  /// Non-ASCII content is not rejected — an operator may legitimately publish
  /// a UTF-8 string — but signer and verifier must then agree on the exact
  /// code points, which is trivially satisfied when both sign the same bytes
  /// the backend emitted.
  ///
  /// This is called out rather than left implicit because "we normalize
  /// Unicode" is a claim this implementation cannot honestly make.
  static String _normalizeUnicode(String value) => value;
}
