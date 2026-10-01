/// Dynamic TLS Certificate Pinning — the pinset model.
///
/// Deliberately mirrors [CertificateTrustStore]'s `current`/`next`/`revoked`
/// vocabulary (`sdk/trust/certificate_trust.dart`), which already solves the
/// same rotation problem for *app-signing* certificates. One vocabulary for
/// both is easier to reason about than two, and an operator who understands
/// signing-cert rotation already understands this.
///
/// **These are TLS server pins, not app-signing fingerprints.** The two are
/// unrelated values with unrelated lifecycles; they share only their rotation
/// shape.
library;

/// What a pin means for a host.
enum TlsPinRole {
  /// The certificate the server presents today. Accepted.
  current,

  /// The certificate the server is rotating *to*. Accepted, so a rotation
  /// that lands while a device is offline does not lock it out — this is the
  /// entire reason a pinset has two accepted roles rather than one.
  next,

  /// Explicitly withdrawn. **Never** accepted, and checked before every
  /// other role, so a pin that erroneously appears in both `revoked` and
  /// `current` rejects rather than accepts (fail-closed on contradiction —
  /// the same rule `CertificateTrustStore.roleOf` already applies).
  revoked,
}

/// How strictly a pinset is applied.
///
/// A remotely-delivered pin that is simply *wrong* must never be able to
/// permanently sever an app from the backend that would deliver its
/// correction — that is how a pinning rollout becomes unrecoverable. The
/// mode ladder, plus `TlsPinningController`'s failure-driven demotion, is
/// what keeps rotation reversible.
enum TlsPinningMode {
  /// Pins are parsed and reported but never enforced. The safe default for
  /// a host that has never been validated on this device.
  off,

  /// Mismatches are recorded and reported as security events, but the
  /// connection is still allowed. This is the rollout-observation mode: an
  /// operator sees how many real devices would have been broken *before*
  /// turning enforcement on.
  monitor,

  /// Mismatches abort the connection.
  enforce,
}

TlsPinningMode tlsPinningModeFromWire(String? wire) {
  switch (wire?.toLowerCase()) {
    case 'enforce':
      return TlsPinningMode.enforce;
    case 'monitor':
      return TlsPinningMode.monitor;
    default:
      return TlsPinningMode.off;
  }
}

extension TlsPinningModeX on TlsPinningMode {
  String get wireName => name;
}

/// The pins accepted for one host.
class TlsHostPinset {
  final String host;
  final Set<String> current;
  final Set<String> next;
  final Set<String> revoked;
  final TlsPinningMode mode;

  /// Whether an empty pinset for this host means "do not pin" (`false`) or
  /// "refuse every connection" (`true`). Always `false` here and not
  /// configurable from the wire: a delivered config that accidentally
  /// carried no pins must degrade to unpinned, never to a total outage.
  bool get failClosedWhenEmpty => false;

  const TlsHostPinset({
    required this.host,
    this.current = const {},
    this.next = const {},
    this.revoked = const {},
    this.mode = TlsPinningMode.off,
  });

  bool get isConfigured => current.isNotEmpty || next.isNotEmpty;

  /// Normalizes a SHA-256 pin to bare lowercase hex.
  ///
  /// Accepts the `AA:BB:...` form `openssl`/`keytool` print and the
  /// `sha256/<base64>` form used by HPKP-style configuration, so a value
  /// copied from either tool works without hand-editing. A value that is
  /// not a recognizable SHA-256 returns empty and is dropped by [fromMap]
  /// rather than silently becoming a pin that can never match.
  static String normalize(String raw) {
    final trimmed = raw.trim();
    if (trimmed.isEmpty) return '';
    var value = trimmed;
    if (value.toLowerCase().startsWith('sha256/')) {
      value = value.substring(7);
      // base64 form — left as-is for the caller to compare against a base64
      // digest; this SDK compares hex, so a base64 pin is normalized only if
      // it decodes to 32 bytes.
      return _base64ToHexOrEmpty(value);
    }
    value = value.replaceAll(RegExp(r'[:\s-]'), '').toLowerCase();
    return RegExp(r'^[0-9a-f]{64}$').hasMatch(value) ? value : '';
  }

  static String _base64ToHexOrEmpty(String b64) {
    try {
      final bytes = _decodeBase64(b64);
      if (bytes.length != 32) return '';
      return bytes
          .map((b) => b.toRadixString(16).padLeft(2, '0'))
          .join();
    } catch (_) {
      return '';
    }
  }

  static List<int> _decodeBase64(String input) {
    const alphabet =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    final cleaned = input.replaceAll('=', '').trim();
    final out = <int>[];
    var buffer = 0;
    var bits = 0;
    for (final char in cleaned.split('')) {
      final index = alphabet.indexOf(char);
      if (index < 0) throw const FormatException('not base64');
      buffer = (buffer << 6) | index;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        out.add((buffer >> bits) & 0xFF);
      }
    }
    return out;
  }

  static Set<String> _readPins(Object? value) {
    if (value is String) {
      final n = normalize(value);
      return n.isEmpty ? const {} : {n};
    }
    if (value is List) {
      final out = <String>{};
      for (final entry in value) {
        if (entry is String) {
          final n = normalize(entry);
          if (n.isNotEmpty) out.add(n);
        }
      }
      return out;
    }
    return const {};
  }

  static TlsHostPinset? fromMap(String host, Map<String, Object?> map) {
    final normalizedHost = host.trim().toLowerCase();
    if (normalizedHost.isEmpty) return null;
    return TlsHostPinset(
      host: normalizedHost,
      current: _readPins(map['current']),
      next: _readPins(map['next']),
      revoked: _readPins(map['revoked']),
      mode: tlsPinningModeFromWire(map['mode'] as String?),
    );
  }

  Map<String, Object?> toMap() => {
        'current': current.toList()..sort(),
        'next': next.toList()..sort(),
        'revoked': revoked.toList()..sort(),
        'mode': mode.wireName,
      };

  /// The role [pin] holds for this host, or `null` when unknown.
  TlsPinRole? roleOf(String pin) {
    final value = normalize(pin);
    if (value.isEmpty) return null;
    if (revoked.contains(value)) return TlsPinRole.revoked;
    if (current.contains(value)) return TlsPinRole.current;
    if (next.contains(value)) return TlsPinRole.next;
    return null;
  }

  /// Whether a certificate with this pin may complete a handshake.
  ///
  /// `null` role means "not in the pinset": rejected when the host is
  /// configured (that is what pinning *means*), allowed when it is not
  /// (nothing to pin against).
  bool accepts(String pin) {
    final role = roleOf(pin);
    if (role == TlsPinRole.revoked) return false;
    if (role == TlsPinRole.current || role == TlsPinRole.next) return true;
    return !isConfigured;
  }

  TlsHostPinset withMode(TlsPinningMode newMode) => TlsHostPinset(
        host: host, current: current, next: next, revoked: revoked,
        mode: newMode,
      );
}

/// Every host's pinset, as delivered by one signed configuration.
class TlsPinset {
  final Map<String, TlsHostPinset> hosts;

  /// The `config_version` of the signed bundle this pinset arrived in.
  /// Carried so a staged pinset can be compared against the active one
  /// without re-reading the whole config, and so persistence can reject a
  /// rollback.
  final int configVersion;

  const TlsPinset({this.hosts = const {}, this.configVersion = 0});

  static const TlsPinset empty = TlsPinset();

  bool get isConfigured => hosts.values.any((h) => h.isConfigured);

  TlsHostPinset? forHost(String host) => hosts[host.trim().toLowerCase()];

  /// Parses `config['tls_pinning']` out of a verified remote-config bundle.
  ///
  /// Returns [empty] for anything malformed rather than throwing: this runs
  /// inside the config-apply path, and a bad pinset must degrade to
  /// "no pinning" — never take down configuration handling as a whole.
  static TlsPinset fromConfig(Map<String, dynamic> config, {int configVersion = 0}) {
    final raw = config['tls_pinning'];
    if (raw is! Map) return TlsPinset(configVersion: configVersion);
    final hostsRaw = raw['hosts'];
    if (hostsRaw is! Map) return TlsPinset(configVersion: configVersion);

    final parsed = <String, TlsHostPinset>{};
    hostsRaw.forEach((key, value) {
      if (value is! Map) return;
      final pinset = TlsHostPinset.fromMap(
        key.toString(),
        value.map((k, v) => MapEntry(k.toString(), v)),
      );
      if (pinset != null) parsed[pinset.host] = pinset;
    });
    return TlsPinset(hosts: parsed, configVersion: configVersion);
  }

  Map<String, Object?> toMap() => {
        'config_version': configVersion,
        'hosts': {for (final e in hosts.entries) e.key: e.value.toMap()},
      };

  static TlsPinset? fromMap(Map<String, Object?> map) {
    try {
      final hostsRaw = map['hosts'];
      if (hostsRaw is! Map) return null;
      final parsed = <String, TlsHostPinset>{};
      hostsRaw.forEach((key, value) {
        if (value is! Map) return;
        final pinset = TlsHostPinset.fromMap(
          key.toString(),
          value.map((k, v) => MapEntry(k.toString(), v)),
        );
        if (pinset != null) parsed[pinset.host] = pinset;
      });
      return TlsPinset(
        hosts: parsed,
        configVersion: (map['config_version'] as num?)?.toInt() ?? 0,
      );
    } catch (_) {
      return null;
    }
  }
}
