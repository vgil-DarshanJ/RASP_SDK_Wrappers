/// Data model for the licensing layer: entitlements, lifecycle state, and the
/// decoded offline entitlement token.
library;

/// Effective runtime state of the SDK's license.
enum LicenseState {
  /// Not yet initialised.
  uninitialized,

  /// Activated and fully valid.
  active,

  /// Expired but inside the offline grace window — features stay enabled.
  grace,

  /// Registered, but a dashboard administrator must approve this device.
  pending,

  /// Expired and past grace.
  expired,

  /// Killed remotely by an administrator.
  revoked,

  /// License or customer account suspended.
  suspended,

  /// This SDK build is older than the license's minimum version.
  upgradeRequired,

  /// Could not reach the backend and no valid cached token exists.
  unlicensed,
}

extension LicenseStateX on LicenseState {
  /// Whether protection features may run.
  bool get grantsFeatures =>
      this == LicenseState.active || this == LicenseState.grace;

  /// Whether the host app should refuse to start.
  bool get isFatal =>
      this == LicenseState.expired ||
      this == LicenseState.revoked ||
      this == LicenseState.suspended ||
      this == LicenseState.upgradeRequired ||
      this == LicenseState.unlicensed;

  String get label {
    switch (this) {
      case LicenseState.uninitialized:
        return 'Not initialised';
      case LicenseState.active:
        return 'Active';
      case LicenseState.grace:
        return 'Grace period';
      case LicenseState.pending:
        return 'Awaiting approval';
      case LicenseState.expired:
        return 'Expired';
      case LicenseState.revoked:
        return 'Revoked';
      case LicenseState.suspended:
        return 'Suspended';
      case LicenseState.upgradeRequired:
        return 'SDK upgrade required';
      case LicenseState.unlicensed:
        return 'Unlicensed';
    }
  }
}

/// Feature entitlement keys, mirroring the backend catalogue.
///
/// Keys are referenced by string so a backend that adds a new detector does
/// not break an older SDK build.
class Entitlement {
  static const rootDetection = 'root_detection';
  static const emulatorDetection = 'emulator_detection';
  static const deviceBinding = 'device_binding';
  static const deviceFingerprint = 'device_fingerprint';
  static const cloneDetection = 'clone_detection';
  static const fridaDetection = 'frida_detection';
  static const debuggerDetection = 'debugger_detection';
  static const hookDetection = 'hook_detection';
  static const reToolsDetection = 're_tools_detection';
  static const tamperDetection = 'tamper_detection';
  static const repackagingDetection = 'repackaging_detection';
  static const vpnDetection = 'vpn_detection';
  static const mitmDetection = 'mitm_detection';
  static const geoFiltering = 'geo_filtering';
  static const overlayDetection = 'overlay_detection';
  static const accessibilityDetection = 'accessibility_detection';
  static const screenshotProtection = 'screenshot_protection';
  static const blockingEnforcement = 'blocking_enforcement';
  static const deceptionMode = 'deception_mode';
  static const offlineCompliance = 'offline_compliance';
  static const aiAnalyst = 'ai_analyst';
  static const telemetry = 'telemetry';
  static const remoteConfig = 'remote_config';

  const Entitlement._();
}

/// An immutable entitlement map. Unknown keys resolve to `false`, so a detector
/// is only ever run when the license explicitly grants it.
class Entitlements {
  final Map<String, bool> _values;

  const Entitlements(this._values);

  const Entitlements.empty() : _values = const {};

  factory Entitlements.fromJson(Map<String, dynamic>? json) {
    if (json == null) return const Entitlements.empty();
    return Entitlements({
      for (final entry in json.entries) entry.key: entry.value == true,
    });
  }

  /// `true` only when the license explicitly enables [key].
  bool has(String key) => _values[key] == true;

  bool operator [](String key) => has(key);

  int get enabledCount => _values.values.where((v) => v).length;

  int get totalCount => _values.length;

  Map<String, bool> toJson() => Map.unmodifiable(_values);

  /// Keys granted by this license, sorted for stable display.
  List<String> get enabledKeys =>
      (_values.entries.where((e) => e.value).map((e) => e.key).toList())..sort();
}

/// A verified, decoded entitlement token plus its lifecycle state.
class LicenseStatus {
  final LicenseState state;
  final Entitlements entitlements;
  final String message;
  final DateTime? expiresAt;
  final DateTime? graceUntil;
  final String plan;
  final int configVersion;

  /// `true` when this status came from the on-device cache rather than a
  /// fresh backend response.
  final bool fromCache;

  const LicenseStatus({
    required this.state,
    this.entitlements = const Entitlements.empty(),
    this.message = '',
    this.expiresAt,
    this.graceUntil,
    this.plan = 'UNKNOWN',
    this.configVersion = 0,
    this.fromCache = false,
  });

  const LicenseStatus.uninitialized()
    : state = LicenseState.uninitialized,
      entitlements = const Entitlements.empty(),
      message = '',
      expiresAt = null,
      graceUntil = null,
      plan = 'UNKNOWN',
      configVersion = 0,
      fromCache = false;

  bool get grantsFeatures => state.grantsFeatures;

  /// Days remaining before the license expires; negative once expired.
  int? get daysRemaining {
    final expiry = expiresAt;
    if (expiry == null) return null;
    return expiry.difference(DateTime.now().toUtc()).inDays;
  }

  LicenseStatus copyWith({
    LicenseState? state,
    Entitlements? entitlements,
    String? message,
    bool? fromCache,
  }) {
    return LicenseStatus(
      state: state ?? this.state,
      entitlements: entitlements ?? this.entitlements,
      message: message ?? this.message,
      expiresAt: expiresAt,
      graceUntil: graceUntil,
      plan: plan,
      configVersion: configVersion,
      fromCache: fromCache ?? this.fromCache,
    );
  }
}
