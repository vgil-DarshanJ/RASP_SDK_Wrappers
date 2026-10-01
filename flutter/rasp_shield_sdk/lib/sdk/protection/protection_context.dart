import '../core/core.dart';

/// Device facts an evaluation may take into account, as plain data.
///
/// Deliberately **not** `device_info_plus` types or the SDK's
/// `DeviceIdentity`: the Protection Engine should be evaluable in a unit test
/// from a literal, with no platform channel and no secure storage. Whoever
/// builds the context is responsible for reading these values; the engine
/// only consumes them.
class ProtectionDeviceInfo {
  /// The SDK's stable per-install device identifier.
  final String? deviceId;

  /// Manufacturer + model, in the same shape activation already reports.
  final String? deviceModel;

  /// OS name and version, e.g. `Android 14 (API 34)`.
  final String? osVersion;

  /// `android`, `ios`, … Left free-form rather than an enum so a platform
  /// the SDK does not support yet is still representable.
  final String? platform;

  /// `false` for an emulator or simulator, when that is known. `null` means
  /// "not determined" — distinct from "determined to be physical".
  final bool? isPhysicalDevice;

  /// Creates a device-info snapshot. Every field is optional: a value that
  /// could not be read stays `null` rather than being guessed, so an
  /// evaluation can tell "unknown" apart from a real reading.
  const ProtectionDeviceInfo({
    this.deviceId,
    this.deviceModel,
    this.osVersion,
    this.platform,
    this.isPhysicalDevice,
  });

  /// Plain-map form for logging or diagnostics.
  Map<String, Object?> toMap() => {
        'device_id': deviceId,
        'device_model': deviceModel,
        'os_version': osVersion,
        'platform': platform,
        'is_physical_device': isPhysicalDevice,
      };
}

/// License facts an evaluation may take into account, as plain data.
///
/// **Intentionally decoupled from the licensing module.** This does not
/// import `license_models.dart` and does not reference `LicenseManager` —
/// the licensing layer is untouched by the Protection Engine, and the engine
/// gains no dependency on it. Whoever builds a [ProtectionContext] projects
/// the current license into these plain fields; the engine reads nothing
/// else. That keeps licensing free to evolve without dragging the protection
/// layer along, and keeps the engine unit-testable with a literal license
/// state.
class ProtectionLicenseInfo {
  /// The license state as a plain string (e.g. `active`, `pending`,
  /// `revoked`), projected by the caller from whatever the licensing layer
  /// currently reports.
  final String? state;

  /// Entitlement keys granted by the active license.
  final Set<String> entitlements;

  /// When the license expires, if known.
  final DateTime? expiresAt;

  /// Creates a license snapshot.
  const ProtectionLicenseInfo({
    this.state,
    this.entitlements = const {},
    this.expiresAt,
  });

  /// `true` when the license grants [entitlementKey].
  bool grants(String entitlementKey) => entitlements.contains(entitlementKey);

  /// Plain-map form for logging or diagnostics.
  Map<String, Object?> toMap() => {
        'state': state,
        'entitlements': entitlements.toList(),
        'expires_at': expiresAt?.toIso8601String(),
      };
}

/// Everything an evaluation knows *besides* the detections themselves.
///
/// The Protection Engine is a pure function of (detections, context, policy).
/// Pulling the ambient facts into an explicit object — rather than letting
/// the engine reach out to `DeviceIdentity`, `PackageInfo`, or
/// `LicenseManager` at evaluation time — is what makes an evaluation
/// reproducible: the same three inputs always produce the same
/// `ProtectionResult`, in a test or on a device, with no I/O in between.
class ProtectionContext {
  /// Device facts. See [ProtectionDeviceInfo].
  final ProtectionDeviceInfo device;

  /// The RASP SDK's own version, for policies or diagnostics that care which
  /// SDK produced a decision.
  final String? sdkVersion;

  /// The host application's version.
  final String? appVersion;

  /// License facts. See [ProtectionLicenseInfo].
  final ProtectionLicenseInfo license;

  /// `true` when the last backend contact failed, so this evaluation is
  /// running on cached evidence alone.
  ///
  /// Read by `ProtectionEngine.evaluate` to apply the policy's
  /// [OfflinePolicy]. Defaults to `false`: a caller that does not know its
  /// connectivity should not have the SDK infer a network outage and change
  /// the decision on its behalf.
  final bool isOffline;

  /// **Placeholder — always empty today.** Nothing in the SDK persists or
  /// replays past detections into an evaluation yet, and this task
  /// deliberately does not add that. The field exists so the *shape* of a
  /// future history-aware policy ("this device has failed the same check
  /// three times this week") is fixed now, and adding the store later is
  /// purely additive rather than a signature change on every call site.
  final List<DetectionResult> detectionHistory;

  /// Creates an evaluation context. Everything is optional so a caller can
  /// supply only what it actually knows.
  const ProtectionContext({
    this.device = const ProtectionDeviceInfo(),
    this.sdkVersion,
    this.appVersion,
    this.license = const ProtectionLicenseInfo(),
    this.detectionHistory = const [],
    this.isOffline = false,
  });

  /// Plain-map form for logging or diagnostics.
  Map<String, Object?> toMap() => {
        'device': device.toMap(),
        'sdk_version': sdkVersion,
        'app_version': appVersion,
        'license': license.toMap(),
        'is_offline': isOffline,
        'detection_history': detectionHistory.map((d) => d.toMap()).toList(),
      };
}
