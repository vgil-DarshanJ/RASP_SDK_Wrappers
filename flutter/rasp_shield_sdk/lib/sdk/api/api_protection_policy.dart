import 'package:flutter/foundation.dart';

/// Which hosts and paths API Protection covers, and on what terms.
///
/// ## Only signed configuration may write here
///
/// Every setter on this class is `@visibleForTesting` or driven by
/// `RemoteConfigManager` *after* `SignedConfigVerifier` has accepted the
/// bundle. That is the whole security property: if untrusted runtime input
/// could name the protected hosts, an attacker on a compromised device
/// would simply remove `api.bank.com` from the list and every request would
/// go out unsigned — the protection would disable itself on exactly the
/// devices it exists to defend against.
///
/// The client also cannot *weaken* the server's requirements. This policy
/// decides what the SDK signs; the verifying backend decides independently
/// what it will accept. A device that stops sending proofs does not become
/// trusted — it becomes a device sending unprotected requests to a gateway
/// that requires them.
///
/// ## Fail-closed on absence, not fail-open
///
/// With no policy at all, [covers] returns false and nothing is signed.
/// That is deliberate: silently signing every outbound request in the host
/// app — including calls to unrelated third parties — would leak this
/// device's identity headers far beyond the customer's own API.
class ApiProtectionPolicy {
  ApiProtectionPolicy._();

  static bool _enabled = false;
  static List<String> _hosts = const [];
  static List<String> _paths = const [];
  static int _freshnessSeconds = 120;
  static int _configVersion = 0;

  /// Whether protection is switched on at all by signed policy.
  static bool get enabled => _enabled;

  /// Hosts whose requests are protected (exact, case-insensitive).
  static List<String> get protectedHosts => List.unmodifiable(_hosts);

  /// Path globs within those hosts (`/payments/*`). Empty means "every path
  /// on a protected host".
  static List<String> get protectedPaths => List.unmodifiable(_paths);

  /// The freshness window the backend will enforce. Carried so the SDK can
  /// avoid signing a request it already knows is too stale to be accepted;
  /// it never widens what the server enforces.
  static int get freshnessSeconds => _freshnessSeconds;

  /// Version of the signed config this policy came from.
  static int get configVersion => _configVersion;

  /// Whether one request is covered.
  ///
  /// Host match is exact rather than suffix-based on purpose: a suffix rule
  /// for `bank.com` would also match `bank.com.evil.example`, which is a
  /// classic way to get a victim's app to sign requests aimed at an
  /// attacker's host.
  static bool covers({required String host, required String path}) {
    if (!_enabled || _hosts.isEmpty) return false;
    final h = host.toLowerCase();
    if (!_hosts.contains(h)) return false;
    if (_paths.isEmpty) return true;
    return _paths.any((glob) => _matchesGlob(glob, path));
  }

  /// Trailing-`*` glob matching, which is all the policy format allows.
  /// Kept intentionally small: a full regex here would be an expression
  /// evaluated from remote configuration.
  static bool _matchesGlob(String glob, String path) {
    if (glob == '*') return true;
    if (glob.endsWith('/*')) {
      final prefix = glob.substring(0, glob.length - 1);
      return path.startsWith(prefix);
    }
    if (glob.endsWith('*')) {
      return path.startsWith(glob.substring(0, glob.length - 1));
    }
    return path == glob;
  }

  /// Apply a policy block taken from an **already signature-verified**
  /// config bundle.
  ///
  /// Callers must only pass a bundle `SignedConfigVerifier` accepted; this
  /// class does not verify signatures and must never be handed raw network
  /// input. Same contract as `TlsPinningController.stageFromConfig`.
  ///
  /// A malformed block leaves the previous policy untouched rather than
  /// clearing it — losing protection because one field was the wrong type
  /// is the worse failure.
  static void applyFromVerifiedConfig(
    Map<String, dynamic> verifiedConfig, {
    required int configVersion,
  }) {
    final raw = verifiedConfig['api_protection'];
    if (raw is! Map) return;

    if (configVersion < _configVersion) {
      debugPrint('[RASP-TRACE] API-POLICY rollback refused '
          '($configVersion < $_configVersion)');
      return;
    }

    try {
      final hosts = (raw['protected_hosts'] as List?)
              ?.whereType<String>()
              .map((h) => h.trim().toLowerCase())
              .where((h) => h.isNotEmpty)
              .toList() ??
          const <String>[];
      final paths = (raw['protected_paths'] as List?)
              ?.whereType<String>()
              .map((p) => p.trim())
              .where((p) => p.isNotEmpty)
              .toList() ??
          const <String>[];
      final freshness = raw['freshness_seconds'];

      _enabled = raw['enabled'] == true;
      _hosts = hosts;
      _paths = paths;
      if (freshness is int && freshness > 0 && freshness <= 3600) {
        _freshnessSeconds = freshness;
      }
      _configVersion = configVersion;

      debugPrint('[RASP-TRACE] API-POLICY applied enabled=$_enabled '
          'hosts=${_hosts.length} paths=${_paths.length} '
          'freshness=${_freshnessSeconds}s version=$_configVersion');
    } catch (e) {
      debugPrint('[RASP-TRACE] API-POLICY malformed, keeping previous: $e');
    }
  }

  @visibleForTesting
  static void setForTests({
    bool enabled = true,
    List<String> hosts = const [],
    List<String> paths = const [],
    int freshnessSeconds = 120,
    int configVersion = 1,
  }) {
    _enabled = enabled;
    _hosts = hosts.map((h) => h.toLowerCase()).toList();
    _paths = paths;
    _freshnessSeconds = freshnessSeconds;
    _configVersion = configVersion;
  }

  @visibleForTesting
  static void resetForTests() {
    _enabled = false;
    _hosts = const [];
    _paths = const [];
    _freshnessSeconds = 120;
    _configVersion = 0;
  }
}
