import 'package:flutter/foundation.dart';

/// Signed remote policy for Malware & Risky-App Intelligence.
///
/// Mirrors `ApiProtectionPolicy`'s exact shape and the same reasoning:
/// only an **already signature-verified** config bundle may write here, so a
/// compromised device cannot switch its own risky-app checking off by
/// forging local state. This is the SAME signed Remote Security Control
/// Plane every other policy-driven capability in this SDK uses — no second
/// configuration system.
///
/// ## Disabled is not clean
///
/// Per the milestone's explicit instruction, a remotely disabled detector
/// must never be reported as [AppRiskClassification.clean] — see
/// `AppIntelligenceDetector.scan()`, which returns
/// [DetectionStatus.unavailable] (this SDK's existing "did not run" state,
/// not a new one) when [enabled] is `false`, rather than silently reporting
/// no findings.
class AppIntelligencePolicy {
  AppIntelligencePolicy._();

  static bool _enabled = true;
  static String _action = 'WARN';
  static String _threshold = 'HIGH';
  static int _configVersion = 0;

  /// Defaults to `true` — the built-in local database (§`LocalReputationProvider`)
  /// is safe to run with no configuration at all, matching every other
  /// built-in detector's "just works" default. Signed policy can turn it
  /// off, never turn on something this SDK cannot safely evaluate offline.
  static bool get enabled => _enabled;

  /// `ALLOW`/`WARN`/`RESTRICT`/`BLOCK` — mirrors `ProtectionAction`'s wire
  /// names, not re-derives them; the recommended response an evaluating
  /// caller (e.g. `RaspShield`'s own protection pipeline) should apply when
  /// this detector's classification meets [threshold].
  static String get action => _action;

  /// `AppRiskClassification.wireName` this action applies at or above —
  /// e.g. `'HIGH_RISK'` means WARN/BLOCK triggers for HIGH_RISK and
  /// KNOWN_MALICIOUS, never for SUSPICIOUS alone.
  static String get threshold => _threshold;

  static int get configVersion => _configVersion;

  /// Apply a policy block taken from an **already signature-verified**
  /// config bundle. Same contract as `ApiProtectionPolicy.applyFromVerifiedConfig`
  /// and `TlsPinningController.stageFromConfig` — never call with raw
  /// network input.
  static void applyFromVerifiedConfig(
    Map<String, dynamic> verifiedConfig, {
    required int configVersion,
  }) {
    final raw = verifiedConfig['app_intelligence'];
    if (raw is! Map) return;

    if (configVersion < _configVersion) {
      debugPrint('[RASP-TRACE] APP-INTEL-POLICY rollback refused '
          '($configVersion < $_configVersion)');
      return;
    }

    try {
      final enabled = raw['enabled'];
      final action = raw['action'];
      final threshold = raw['threshold'];

      if (enabled is bool) _enabled = enabled;
      if (action is String && action.isNotEmpty) _action = action.toUpperCase();
      if (threshold is String && threshold.isNotEmpty) {
        _threshold = threshold.toUpperCase();
      }
      _configVersion = configVersion;

      debugPrint('[RASP-TRACE] APP-INTEL-POLICY applied enabled=$_enabled '
          'action=$_action threshold=$_threshold version=$_configVersion');
    } catch (e) {
      debugPrint('[RASP-TRACE] APP-INTEL-POLICY malformed, keeping previous: $e');
    }
  }

  @visibleForTesting
  static void setForTests({
    bool enabled = true,
    String action = 'WARN',
    String threshold = 'HIGH',
    int configVersion = 1,
  }) {
    _enabled = enabled;
    _action = action;
    _threshold = threshold;
    _configVersion = configVersion;
  }

  @visibleForTesting
  static void resetForTests() {
    _enabled = true;
    _action = 'WARN';
    _threshold = 'HIGH';
    _configVersion = 0;
  }
}
