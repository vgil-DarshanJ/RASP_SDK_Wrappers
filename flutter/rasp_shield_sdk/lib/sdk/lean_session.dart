/// Flutter facade for the Kotlin lean-session engine.
///
/// The native engine is the sole owner of ticking, detector execution,
/// timeout handling, change detection, and event shipping. This file only
/// sends configuration/location to Android and reflects native state events.
library;

import 'dart:async';

import 'package:flutter/services.dart';

import 'core/core.dart';
import 'detectors/rasp_native_channel.dart';
import 'security_controls.dart';

class RaspLocationSnapshot {
  final double latitude;
  final double longitude;
  final double? accuracyMeters;
  final DateTime capturedAt;

  /// The fix's own mock flag when known (geolocator `Position.isMocked`);
  /// `null` when unknown. Used by `mock_location`.
  final bool? isMock;

  const RaspLocationSnapshot({
    required this.latitude,
    required this.longitude,
    this.accuracyMeters,
    required this.capturedAt,
    this.isMock,
  });
}

/// Native-engine configuration. All detectors remain opt-in.
class RaspLeanConfig {
  final bool screenshotProtection;
  final bool usbDetection;
  final bool adbDetection;
  final bool clipboardProtection;
  final bool clipboardAutoClear;
  final bool rootDetection;
  final bool emulatorDetection;
  final bool deviceBindingCheck;
  final bool cloneDetection;
  final bool developerModeDetection;
  final bool deviceLockCheck;
  final bool secureHardwareCheck;
  final bool deviceFingerprintCheck;
  final bool fridaDetection;
  final bool debuggerDetection;
  final bool reverseEngineeringToolsDetection;
  final bool hookDetection;
  final bool riskyAppDetection;
  final bool tamperDetection;
  final bool untrustedInstallSourceDetection;
  final bool repackagingDetection;
  final String? expectedSigningCertSha256;
  final bool vpnDetection;
  final bool mitmDetection;

  /// Host for the `mitm` SPKI pin check (e.g. your API host). `null` (or no
  /// [certificatePins]) = no pin check: with no proxy or user-CA signal,
  /// `mitm` is SECURE with `pin_not_configured` evidence.
  final String? certificatePinHost;

  /// Accepted SPKI pins for [certificatePinHost], each `sha256/<Base64>`.
  final List<String> certificatePins;
  final bool highRiskIpDetection;
  final bool overlayDetection;
  final bool accessibilityDetection;
  final bool externalDisplayDetection;
  final bool screenshotEventDetection;
  final bool mockLocationDetection;
  final bool timeSpoofingDetection;
  final bool unsafeWifiDetection;
  final bool screenRecordingDetection;

  /// Optional trusted server time for `time_spoofing`; anchored when the session starts.
  final DateTime? serverTime;
  final bool vishingCallDetection;
  final bool simChangeDetection;
  final bool thirdPartyKeyboardDetection;
  final bool taskHijackDetection;

  /// Extra keyboard packages trusted when installed from Google Play (Gboard is built in).
  final List<String> trustedKeyboardPackages;
  final bool deviceStateAttestationDetection;

  /// Report `patch_too_old` when the attested OS patch is older than this; `null` = off.
  final int? maxSecurityPatchAgeDays;
  final bool malwareReputationDetection;

  /// Signed reputation list JSON (e.g. `await rootBundle.loadString(...)`).
  final String? malwareReputationListJson;

  /// Ed25519 public key that signs the list (Base64, raw 32 bytes or SPKI).
  final String? malwareReputationPublicKey;
  /// Enable Evidence Envelope path (device-key signed, replay-resistant) instead of legacy HMAC. Default off.
  final bool useEvidenceEnvelope;
  final Duration pollInterval;
  final Duration heartbeatInterval;

  const RaspLeanConfig({
    this.screenshotProtection = false,
    this.usbDetection = false,
    this.adbDetection = false,
    this.clipboardProtection = false,
    this.clipboardAutoClear = true,
    this.rootDetection = false,
    this.emulatorDetection = false,
    this.deviceBindingCheck = false,
    this.cloneDetection = false,
    this.developerModeDetection = false,
    this.deviceLockCheck = false,
    this.secureHardwareCheck = false,
    this.deviceFingerprintCheck = false,
    this.fridaDetection = false,
    this.debuggerDetection = false,
    this.reverseEngineeringToolsDetection = false,
    this.hookDetection = false,
    this.riskyAppDetection = false,
    this.tamperDetection = false,
    this.untrustedInstallSourceDetection = false,
    this.repackagingDetection = false,
    this.expectedSigningCertSha256,
    this.vpnDetection = false,
    this.mitmDetection = false,
    this.certificatePinHost,
    this.certificatePins = const [],
    this.highRiskIpDetection = false,
    this.overlayDetection = false,
    this.accessibilityDetection = false,
    this.externalDisplayDetection = false,
    this.screenshotEventDetection = false,
    this.mockLocationDetection = false,
    this.timeSpoofingDetection = false,
    this.unsafeWifiDetection = false,
    this.screenRecordingDetection = false,
    this.serverTime,
    this.vishingCallDetection = false,
    this.simChangeDetection = false,
    this.thirdPartyKeyboardDetection = false,
    this.taskHijackDetection = false,
    this.trustedKeyboardPackages = const [],
    this.deviceStateAttestationDetection = false,
    this.maxSecurityPatchAgeDays,
    this.malwareReputationDetection = false,
    this.malwareReputationListJson,
    this.malwareReputationPublicKey,
    this.useEvidenceEnvelope = false,
    this.pollInterval = const Duration(seconds: 4),
    this.heartbeatInterval = const Duration(seconds: 20),
  });

  Map<String, Object?> toNativeMap() => {
        'screenshotProtection': screenshotProtection,
        'usbDetection': usbDetection,
        'adbDetection': adbDetection,
        'clipboardProtection': clipboardProtection,
        'clipboardAutoClear': clipboardAutoClear,
        'rootDetection': rootDetection,
        'emulatorDetection': emulatorDetection,
        'deviceBindingCheck': deviceBindingCheck,
        'cloneDetection': cloneDetection,
        'developerModeDetection': developerModeDetection,
        'deviceLockCheck': deviceLockCheck,
        'secureHardwareCheck': secureHardwareCheck,
        'deviceFingerprintCheck': deviceFingerprintCheck,
        'fridaDetection': fridaDetection,
        'debuggerDetection': debuggerDetection,
        'reverseEngineeringToolsDetection': reverseEngineeringToolsDetection,
        'hookDetection': hookDetection,
        'riskyAppDetection': riskyAppDetection,
        'tamperDetection': tamperDetection,
        'untrustedInstallSourceDetection': untrustedInstallSourceDetection,
        'repackagingDetection': repackagingDetection,
        'expectedSigningCertSha256': expectedSigningCertSha256,
        'vpnDetection': vpnDetection,
        'mitmDetection': mitmDetection,
        'certificatePinHost': certificatePinHost,
        'certificatePins': certificatePins,
        'highRiskIpDetection': highRiskIpDetection,
        'overlayDetection': overlayDetection,
        'accessibilityDetection': accessibilityDetection,
        'externalDisplayDetection': externalDisplayDetection,
        'screenshotEventDetection': screenshotEventDetection,
        'mockLocationDetection': mockLocationDetection,
        'timeSpoofingDetection': timeSpoofingDetection,
        'unsafeWifiDetection': unsafeWifiDetection,
        'screenRecordingDetection': screenRecordingDetection,
        'serverTimeMillis': serverTime?.millisecondsSinceEpoch,
        'vishingCallDetection': vishingCallDetection,
        'simChangeDetection': simChangeDetection,
        'thirdPartyKeyboardDetection': thirdPartyKeyboardDetection,
        'taskHijackDetection': taskHijackDetection,
        'trustedKeyboardPackages': trustedKeyboardPackages,
        'deviceStateAttestationDetection': deviceStateAttestationDetection,
        'maxSecurityPatchAgeDays': maxSecurityPatchAgeDays,
        'malwareReputationDetection': malwareReputationDetection,
        'malwareReputationListJson': malwareReputationListJson,
        'malwareReputationPublicKey': malwareReputationPublicKey,
        'useEvidenceEnvelope': useEvidenceEnvelope,
        'pollIntervalMillis': pollInterval.inMilliseconds,
        'heartbeatIntervalMillis': heartbeatInterval.inMilliseconds,
      };
}

class RaspLeanState {
  final bool? screenshotActive;
  final RaspUsbState usb;
  final bool? clipboardActive;
  final RaspClipboardEvidence clipboardEvidence;
  final Map<String, DetectionResult> extendedDetectors;

  const RaspLeanState({
    required this.screenshotActive,
    required this.usb,
    required this.clipboardActive,
    required this.clipboardEvidence,
    this.extendedDetectors = const {},
  });

  static const initial = RaspLeanState(
    screenshotActive: null,
    usb: RaspUsbState.unsupported,
    clipboardActive: null,
    clipboardEvidence: RaspClipboardEvidence.unsupported,
  );
}

class RaspLeanSession {
  RaspLeanSession._(this._config);

  static const EventChannel _stateChannel =
      EventChannel('com.shieldsdk.security/lean_state');

  final RaspLeanConfig _config;
  final StreamController<RaspLeanState> _stateController =
      StreamController<RaspLeanState>.broadcast();
  StreamSubscription<dynamic>? _nativeStateSubscription;
  bool _disposed = false;
  RaspLeanState _current = RaspLeanState.initial;
  RaspLocationSnapshot? _currentLocation;

  RaspLeanState get current => _current;
  Stream<RaspLeanState> get stateStream => _stateController.stream;

  RaspLocationSnapshot? get currentLocation => _currentLocation;
  set currentLocation(RaspLocationSnapshot? value) {
    _currentLocation = value;
    if (value == null || _disposed) return;
    unawaited(RaspNativeChannel.boolCall('setLeanSessionLocation', {
      'latitude': value.latitude,
      'longitude': value.longitude,
      'accuracyMeters': value.accuracyMeters,
      'capturedAtMillis': value.capturedAt.millisecondsSinceEpoch,
      'isMock': value.isMock,
    }));
  }

  /// Supplies a trusted server time (e.g. from an HTTP `Date` header) for
  /// `time_spoofing`.
  Future<void> setServerTime(DateTime serverTime) async {
    if (!_disposed) {
      await RaspNativeChannel.boolCall('setLeanSessionServerTime', serverTime.millisecondsSinceEpoch);
    }
  }

  /// Evidence-envelope delivery counters since the app process started:
  /// `delivered`, `dropped_invalid` (400/422), `dropped_expired` (older than
  /// 7 days), `dropped_unauthorized` (401 again after re-registration),
  /// `dropped_rejected` (other 4xx) and `re_registrations`. Empty when the
  /// native side does not answer.
  static Future<Map<String, int>> deliveryStats() async {
    final raw = await RaspNativeChannel.mapCall('getLeanDeliveryStats');
    if (raw == null) return const {};
    return {
      for (final e in raw.entries)
        if (e.value is num) e.key: (e.value as num).toInt(),
    };
  }

  /// For payment/transfer screens: `true` while a phone call is ringing or in
  /// progress, `false` when there is none, `null` when it cannot be told
  /// (READ_PHONE_STATE not granted). Works without a running session.
  static Future<bool?> isCallActive() => RaspNativeChannel.boolCall('isCallActive');

  /// Accepts the current SIMs after `sim_change` reported a change (e.g. once
  /// the customer has been re-verified). Returns `false` if nothing was pending.
  static Future<bool> acknowledgeSimChange() async =>
      await RaspNativeChannel.boolCall('acknowledgeSimChange') ?? false;

  /// Testing only: forgets the stored SIM baseline, so the next `sim_change`
  /// run stores a new one and reports UNKNOWN "baseline stored". The native
  /// side refuses it (returns `false`, baseline kept) unless the app is a
  /// debuggable build; production apps use [acknowledgeSimChange].
  static Future<bool> resetSimBaseline() async =>
      await RaspNativeChannel.boolCall('resetSimBaseline') ?? false;

  /// How long [start] and [dispose] wait for a native call before moving on.
  static const nativeCallTimeout = Duration(seconds: 2);

  /// Starts the native session. Returns after the native side answers, or
  /// after [nativeCallTimeout] if it does not (state then arrives once it
  /// starts); it never blocks longer.
  static Future<RaspLeanSession> start(RaspLeanConfig config) async {
    final session = RaspLeanSession._(config);
    session._nativeStateSubscription = _stateChannel
        .receiveBroadcastStream()
        .listen(session._onNativeState, onError: (_) {});
    await RaspNativeChannel.boolCall('startLeanSession', config.toNativeMap())
        .timeout(nativeCallTimeout, onTimeout: () => null);
    return session;
  }

  /// Requests an immediate native-engine tick. It does not run detectors in Dart.
  Future<void> refreshNow() async {
    if (!_disposed) await RaspNativeChannel.boolCall('refreshLeanSession');
  }

  void _onNativeState(dynamic raw) {
    if (_disposed || raw is! Map) return;
    final state = _decodeState(raw.map((key, value) => MapEntry('$key', value)));
    _current = state;
    if (!_stateController.isClosed) _stateController.add(state);
  }

  RaspLeanState _decodeState(Map<String, dynamic> raw) {
    final usbConnected = raw['usbConnected'] as bool?;
    final adbEnabled = raw['usbDebuggingEnabled'] as bool?;
    final developerModeEnabled = raw['developerModeEnabled'] as bool?;
    final usbSupported = usbConnected != null || adbEnabled != null || developerModeEnabled != null;
    final clipboardActive = raw['clipboardActive'] as bool?;
    final extendedRaw = raw['extendedDetectors'];
    final extended = <String, DetectionResult>{};
    if (extendedRaw is Map) {
      extendedRaw.forEach((key, value) {
        if (value is Map) {
          extended['$key'] = _decodeCheck(
            '$key', value.map((k, v) => MapEntry('$k', v)),
          );
        }
      });
    }
    return RaspLeanState(
      screenshotActive: raw['screenshotActive'] as bool?,
      usb: RaspUsbState(
        supported: usbSupported,
        usbConnected: usbConnected,
        usbDebuggingEnabled: adbEnabled,
        developerModeEnabled: developerModeEnabled,
        connectedDeviceCount: (raw['usbDeviceCount'] as num?)?.toInt() ?? 0,
      ),
      clipboardActive: clipboardActive,
      clipboardEvidence: RaspClipboardEvidence(
        supported: clipboardActive != null,
        active: clipboardActive ?? false,
        autoClearEnabled: _config.clipboardAutoClear,
        changeCount: (raw['clipboardChangeCount'] as num?)?.toInt() ?? 0,
        lastChangeAt: null,
      ),
      extendedDetectors: extended,
    );
  }

  DetectionResult _decodeCheck(String fallbackId, Map<String, dynamic> raw) {
    final id = raw['detectorId'] as String? ?? fallbackId;
    final statusName = (raw['status'] as String? ?? 'ERROR').toLowerCase();
    final status = DetectionStatus.values.firstWhere(
      (value) => value.name == statusName,
      orElse: () => DetectionStatus.error,
    );
    final evidenceRaw = raw['evidence'];
    final evidence = evidenceRaw is List
        ? evidenceRaw.whereType<Map>().map((entry) => DetectionEvidence(
              key: '${entry['key']}',
              value: entry['value'],
              note: entry['note'] as String?,
            )).toList(growable: false)
        : const <DetectionEvidence>[];
    final descriptor = RaspDetectorDescriptor.forId(id);
    return DetectionResult(
      detectorId: id,
      detectorType: descriptor.type,
      category: descriptor.category,
      status: status,
      severity: descriptor.severity,
      title: descriptor.title,
      description: 'Verdict produced by the native Kotlin lean-session engine.',
      evidence: evidence,
      unavailableReason: raw['reason'] as String?,
      observedAt: DateTime.fromMillisecondsSinceEpoch(
        (raw['observedAtMillis'] as num?)?.toInt() ?? DateTime.now().millisecondsSinceEpoch,
        isUtc: true,
      ),
      platform: 'android',
    );
  }

  /// Stops the native session and closes [stateStream]. Never blocks for
  /// long, so a restart (dispose, then [start]) cannot hang:
  /// - the native stop call gets [nativeCallTimeout], then dispose continues
  ///   (the next `startLeanSession` replaces any native session still running);
  /// - the event-channel subscription is cancelled without waiting: the
  ///   cancel takes effect at once, and its future only reports clean-up (for
  ///   a broadcast stream it is completed in the root zone, so it never
  ///   resolves inside a widget test's fake async);
  /// - closing [stateStream] is bounded by [nativeCallTimeout] as well.
  /// Safe to call more than once.
  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await RaspNativeChannel.boolCall('disposeLeanSession')
        .timeout(nativeCallTimeout, onTimeout: () => null);
    final subscription = _nativeStateSubscription;
    _nativeStateSubscription = null;
    if (subscription != null) unawaited(subscription.cancel().catchError((Object _) {}));
    if (!_stateController.isClosed) {
      await _stateController.close().timeout(nativeCallTimeout, onTimeout: () {});
    }
  }
}

/// Display name, category and severity for a native engine detector id.
///
/// Every id the Kotlin engine can report (its lean-session detectors and the
/// four basic controls) has an entry here; titles, categories and severities
/// for the entries added since Task 3 follow the dashboard's catalog
/// (`FE/lib/alertCatalog.ts`). An id without an entry gets [generic]
/// ("Security Check") — `test/detector_descriptor_test.dart` fails if any
/// engine id does.
class RaspDetectorDescriptor {
  final DetectorType type;
  final ThreatCategory category;
  final DetectionSeverity severity;
  final String title;

  const RaspDetectorDescriptor(this.type, this.category, this.severity, this.title);

  /// Fallback for an id this table does not know.
  static const generic =
      RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.other, DetectionSeverity.medium, 'Security Check');

  bool get isGeneric => identical(this, generic);

  static RaspDetectorDescriptor forId(String id) => _byId[id] ?? generic;

  /// Every detector id with a specific descriptor.
  static Iterable<String> get knownIds => _byId.keys;

  static const _byId = <String, RaspDetectorDescriptor>{
    // Basic controls (shipped by the session; shown on their own cards in apps).
    'screenshot_protection': RaspDetectorDescriptor(DetectorType.screenshot, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Screenshot & Video Block'),
    'usb_connection': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.low, 'USB Connection'),
    'adb_enabled': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'USB Debugging (ADB)'),
    'clipboard_protection': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.low, 'Clipboard Protection'),
    // Device integrity
    'root_jailbreak': RaspDetectorDescriptor(DetectorType.root, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Root / Jailbreak'),
    'emulator': RaspDetectorDescriptor(DetectorType.emulator, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Emulator'),
    'device_binding': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Device Binding'),
    'clone': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'App Clone / Dual Space'),
    'developer_mode': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.low, 'Developer Mode'),
    'device_lock_missing': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Device Lock'),
    'secure_hardware_unavailable': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.low, 'Hardware-Backed Keystore'),
    'device_fingerprint': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Device Fingerprint'),
    // Runtime protection
    'frida': RaspDetectorDescriptor(DetectorType.frida, ThreatCategory.runtimeProtection, DetectionSeverity.critical, 'Frida'),
    'debugger': RaspDetectorDescriptor(DetectorType.debugger, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Debugger'),
    'hook_detection': RaspDetectorDescriptor(DetectorType.hook, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Hook Detection'),
    're_tools': RaspDetectorDescriptor(DetectorType.reverseEngineeringTools, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Reverse Engineering Tools'),
    'risky_app': RaspDetectorDescriptor(DetectorType.riskyApp, ThreatCategory.other, DetectionSeverity.high, 'Risky Application / Environment'),
    // App integrity
    'tamper': RaspDetectorDescriptor(DetectorType.tamper, ThreatCategory.appIntegrity, DetectionSeverity.high, 'App Tampering'),
    'repackage': RaspDetectorDescriptor(DetectorType.repackage, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Repackaging'),
    'untrusted_install_source': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Installation Source'),
    // Network security
    'vpn': RaspDetectorDescriptor(DetectorType.vpn, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'VPN'),
    'mitm': RaspDetectorDescriptor(DetectorType.proxy, ThreatCategory.networkSecurity, DetectionSeverity.high, 'MITM / Proxy'),
    'high_risk_ip': RaspDetectorDescriptor(DetectorType.highRiskIp, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'High-risk IP'),
    // Privacy & screen
    'overlay': RaspDetectorDescriptor(DetectorType.overlay, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Overlay'),
    'accessibility': RaspDetectorDescriptor(DetectorType.accessibility, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Accessibility Abuse'),
    'external_display': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'External Display / Mirroring'),
    'screenshot_event': RaspDetectorDescriptor(DetectorType.screenshot, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Screenshot Event'),
    // Task 3a-3c (same title, category and severity as the dashboard)
    'mock_location': RaspDetectorDescriptor(DetectorType.locationSpoof, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Mock Location'),
    'time_spoofing': RaspDetectorDescriptor(DetectorType.timeSpoof, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Time Spoofing'),
    'unsafe_wifi': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'Unsafe Wi-Fi'),
    'screen_recording': RaspDetectorDescriptor(DetectorType.screenshot, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Screen Recording'),
    'vishing_call': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Call During App Use'),
    'sim_change': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'SIM Change'),
    'third_party_keyboard': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Third-party Keyboard'),
    'task_hijack': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Task Hijacking'),
    'device_state_attestation': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Device State Attestation'),
    'malware_reputation': RaspDetectorDescriptor(DetectorType.riskyApp, ThreatCategory.deviceIntegrity, DetectionSeverity.critical, 'Known Malware Installed'),
  };
}

/// Heading used when grouping detectors by category (same wording as the
/// dashboard's categories).
extension RaspThreatCategoryHeading on ThreatCategory {
  String get heading => switch (this) {
        ThreatCategory.deviceIntegrity => 'Device Integrity',
        ThreatCategory.runtimeProtection => 'Runtime Protection',
        ThreatCategory.appIntegrity => 'App Integrity',
        ThreatCategory.networkSecurity => 'Network Security',
        ThreatCategory.privacyScreen => 'Privacy & Screen',
        ThreatCategory.locationIntegrity => 'Location Integrity',
        ThreatCategory.other => 'Other',
      };
}
