import 'dart:convert';

import 'package:crypto/crypto.dart';

/// Phase 10 — the privacy boundary every security event's evidence crosses.
///
/// ## Why this is enforced in the model, not by convention
///
/// `DeviceLogReporter` accepts a free-form `Map<String, dynamic> metadata`
/// that nothing constrains. That is an unreviewed privacy surface — a
/// well-meaning caller adding
/// `{'auth': token}` to help debug a licensing problem ships a bearer
/// credential to the backend and into `device_logs` forever, and no reviewer
/// would necessarily notice.
///
/// [SecurityEvent] therefore does not accept evidence directly. Every map goes
/// through [SecurityEventPrivacy.redact] inside the constructor, so there is
/// no code path — including a future one written by someone who has not read
/// this file — that puts unredacted evidence into an event.
///
/// ## The rule
///
/// Three transformations, in order:
///
/// 1. **Deny by key.** A key matching any [deniedKeySubstrings] entry is
///    dropped entirely and replaced with a marker, so the *fact* that
///    something was withheld is still visible. Dropping silently would make a
///    redaction indistinguishable from a producer that never set the field.
/// 2. **Hash by key.** A key matching [hashedKeySubstrings] is kept, but its
///    value is replaced by a truncated SHA-256. This preserves the one
///    property an investigation actually needs from an identifier —
///    *is this the same value as the one in that other event?* — without
///    transmitting the value itself.
/// 3. **Bound the length.** Everything surviving is truncated to
///    [maxValueLength]. An unbounded evidence string is both a privacy risk
///    (it is how screen contents or a stack trace containing user data would
///    leak) and a storage-exhaustion vector (Phase 15).
///
/// ## What is never collected
///
/// Personal content, screen contents, passwords, raw tokens, private keys,
/// raw attestation tokens, contact/location detail, and arbitrary host-app
/// user data. The deny list below is the mechanical expression of that; the
/// architectural expression is that no producer in this SDK *has* access to
/// most of it — see the audit's §2 for what each producer can actually see.
class SecurityEventPrivacy {
  const SecurityEventPrivacy._();

  /// Marker written in place of a denied value.
  static const String redactedMarker = '[redacted]';

  /// Marker written when a value was dropped for being unrepresentable.
  static const String unrepresentableMarker = '[unrepresentable]';

  /// Maximum characters retained for any single evidence value.
  static const int maxValueLength = 160;

  /// Maximum number of evidence entries retained on one event.
  ///
  /// A producer that wants to attach fifty fields is describing something
  /// that belongs in its own event, not in one event's evidence summary.
  static const int maxEntries = 24;

  /// Keys whose values are dropped outright.
  ///
  /// Matching is two-tier — see [matchesKey]. A needle of five characters or
  /// more matches as a substring, so `authToken`, `x-auth-token` and
  /// `AUTH_TOKEN` are all caught by `token` without an exhaustive spelling
  /// list. A shorter needle matches only as a **whole token**, because
  /// substring-matching a three-letter needle silently destroys legitimate
  /// evidence: `pin` would redact `certificate_pinning`, `pan` would redact
  /// `expanded_signals`, and `ip` would redact `recipient`. A redaction that
  /// eats real security evidence is a worse failure than one that is slightly
  /// narrower, because nobody ever notices it.
  static const List<String> deniedKeySubstrings = [
    'password',
    'passwd',
    'secret',
    'token',
    'credential',
    'private',
    'privkey',
    'apikey',
    'api_key',
    'authorization',
    'cookie',
    'session',
    'seed',
    'mnemonic',
    'pin',
    'otp',
    'cvv',
    'pan',
    'iban',
    'ssn',
    'licensekey',
    'license_key',
    'attestation_token',
    'jwt',
    'bearer',
    'screenshot',
    'screen_content',
    'clipboard',
    'contact',
    'message_body',
  ];

  /// Keys whose values are kept only as a truncated digest.
  ///
  /// Deliberately limited to identifiers **of a person or a device**. File
  /// paths are *not* here, and that is a considered decision rather than an
  /// omission: a detector's evidence is overwhelmingly system paths
  /// (`/system/xbin/su`, a Magisk artefact, a hooked library), and hashing
  /// those makes root-detection evidence unreadable to the analyst it exists
  /// for — the milestone asks for events that are *investigation-useful*.
  /// Paths are instead bounded by [maxValueLength], and no producer in this
  /// SDK emits a user-document path — every producer observes only
  /// device/security state, never user content.
  static const List<String> hashedKeySubstrings = [
    'email',
    'phone',
    'msisdn',
    'account',
    'user_id',
    'userid',
    'username',
    'imei',
    'imsi',
    'serial',
    'mac',
    'ip',
    'ssid',
  ];

  /// Characters of the SHA-256 hex digest retained for a hashed value.
  ///
  /// 16 hex characters is 64 bits — enough that two distinct values
  /// colliding within one device's event history is not a practical concern,
  /// and short enough that the digest is readable in a console.
  static const int hashPrefixLength = 16;

  /// Applies the three transformations above to [evidence].
  ///
  /// Deterministic and total: the same input always produces the same output,
  /// and no input throws. Keys are returned sorted so two events carrying the
  /// same facts produce the same canonical form regardless of insertion order
  /// — load-bearing for both the integrity digest and deduplication.
  static Map<String, String> redact(Map<String, Object?>? evidence) {
    if (evidence == null || evidence.isEmpty) return const {};

    final keys = evidence.keys.toList()..sort();
    final result = <String, String>{};

    for (final key in keys) {
      if (result.length >= maxEntries) break;
      final lowered = key.toLowerCase();

      if (matchesKey(lowered, deniedKeySubstrings)) {
        result[key] = redactedMarker;
        continue;
      }

      final rendered = _render(evidence[key]);
      if (rendered == null) {
        result[key] = unrepresentableMarker;
        continue;
      }

      if (matchesKey(lowered, hashedKeySubstrings)) {
        result[key] = hashValue(rendered);
        continue;
      }

      result[key] = _truncate(rendered);
    }
    return result;
  }

  /// `sha256:<first 16 hex chars>` — the stable, non-reversible stand-in for
  /// an identifier the backend does not need in the clear.
  static String hashValue(String value) {
    final digest = sha256.convert(utf8.encode(value)).toString();
    return 'sha256:${digest.substring(0, hashPrefixLength)}';
  }

  /// Length at or above which a needle matches as a substring rather than as
  /// a whole token. See [deniedKeySubstrings] for why the two tiers exist.
  static const int substringMatchThreshold = 5;

  /// `true` when [loweredKey] matches any of [needles].
  ///
  /// Public so a test can assert the matching rule directly rather than
  /// inferring it from redaction outcomes.
  static bool matchesKey(String loweredKey, List<String> needles) {
    final tokens = _tokens(loweredKey);
    for (final needle in needles) {
      if (needle.length >= substringMatchThreshold) {
        if (loweredKey.contains(needle)) return true;
      } else if (tokens.contains(needle)) {
        return true;
      }
    }
    return false;
  }

  /// Splits a lowercased key into its component words on any non-alphanumeric
  /// separator. `auth_token`, `auth-token` and `auth.token` all yield
  /// `{auth, token}`; a camelCase key has already been lowercased by the
  /// caller, so `authToken` is one token and is caught by the substring tier
  /// instead.
  static Set<String> _tokens(String loweredKey) => loweredKey
      .split(RegExp(r'[^a-z0-9]+'))
      .where((t) => t.isNotEmpty)
      .toSet();

  static String? _render(Object? value) {
    if (value == null) return null;
    if (value is String) return value;
    if (value is num || value is bool) return value.toString();
    if (value is Iterable) {
      return value.map((e) => _render(e) ?? '?').join(',');
    }
    // A Map or an arbitrary object has no stable, privacy-reviewed rendering.
    // Refusing it is deliberate: a nested structure is how unreviewed fields
    // get in past a key-based deny list.
    return null;
  }

  static String _truncate(String value) {
    if (value.length <= maxValueLength) return value;
    return '${value.substring(0, maxValueLength - 1)}…';
  }
}
