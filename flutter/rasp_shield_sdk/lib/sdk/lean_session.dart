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

  /// For payment/transfer screens: `true` while a phone call is ringing or in
  /// progress, `false` when there is none, `null` when it cannot be told
  /// (READ_PHONE_STATE not granted). Works without a running session.
  static Future<bool?> isCallActive() => RaspNativeChannel.boolCall('isCallActive');

  /// Accepts the current SIMs after `sim_change` reported a change (e.g. once
  /// the customer has been re-verified). Returns `false` if nothing was pending.
  static Future<bool> acknowledgeSimChange() async =>
      await RaspNativeChannel.boolCall('acknowledgeSimChange') ?? false;

  static Future<RaspLeanSession> start(RaspLeanConfig config) async {
    final session = RaspLeanSession._(config);
    session._nativeStateSubscription = _stateChannel
        .receiveBroadcastStream()
        .listen(session._onNativeState, onError: (_) {});
    await RaspNativeChannel.boolCall('startLeanSession', config.toNativeMap());
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
    final descriptor = _descriptorFor(id);
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

  _Descriptor _descriptorFor(String id) => switch (id) {
        'root_jailbreak' => const _Descriptor(DetectorType.root, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Root / Jailbreak'),
        'emulator' => const _Descriptor(DetectorType.emulator, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Emulator'),
        'frida' => const _Descriptor(DetectorType.frida, ThreatCategory.runtimeProtection, DetectionSeverity.critical, 'Frida'),
        'debugger' => const _Descriptor(DetectorType.debugger, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Debugger'),
        'hook_detection' => const _Descriptor(DetectorType.hook, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Hook Detection'),
        're_tools' => const _Descriptor(DetectorType.reverseEngineeringTools, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Reverse Engineering Tools'),
        'tamper' => const _Descriptor(DetectorType.tamper, ThreatCategory.appIntegrity, DetectionSeverity.high, 'App Tampering'),
        'repackage' => const _Descriptor(DetectorType.repackage, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Repackaging'),
        'vpn' => const _Descriptor(DetectorType.vpn, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'VPN'),
        'mitm' => const _Descriptor(DetectorType.proxy, ThreatCategory.networkSecurity, DetectionSeverity.high, 'MITM / Proxy'),
        'high_risk_ip' => const _Descriptor(DetectorType.highRiskIp, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'High-risk IP'),
        'overlay' => const _Descriptor(DetectorType.overlay, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Overlay'),
        'accessibility' => const _Descriptor(DetectorType.accessibility, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Accessibility Abuse'),
        'screenshot_event' => const _Descriptor(DetectorType.screenshot, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Screenshot Event'),
        'mock_location' => const _Descriptor(DetectorType.locationSpoof, ThreatCategory.locationIntegrity, DetectionSeverity.high, 'Mock Location'),
        'time_spoofing' => const _Descriptor(DetectorType.timeSpoof, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Time Spoofing'),
        'unsafe_wifi' => const _Descriptor(DetectorType.custom, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'Unsafe Wi-Fi'),
        'screen_recording' => const _Descriptor(DetectorType.screenshot, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Screen Recording'),
        'vishing_call' => const _Descriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Call During App Use'),
        'sim_change' => const _Descriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'SIM Change'),
        'third_party_keyboard' => const _Descriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Third-party Keyboard'),
        'task_hijack' => const _Descriptor(DetectorType.custom, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Task Hijacking'),
        'device_state_attestation' => const _Descriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Device State Attestation'),
        'malware_reputation' => const _Descriptor(DetectorType.riskyApp, ThreatCategory.appIntegrity, DetectionSeverity.critical, 'Known Malware Installed'),
        _ => const _Descriptor(DetectorType.custom, ThreatCategory.other, DetectionSeverity.medium, 'Security Check'),
      };

  Future<void> dispose() async {
    if (_disposed) return;
    _disposed = true;
    await RaspNativeChannel.boolCall('disposeLeanSession');
    await _nativeStateSubscription?.cancel();
    await _stateController.close();
  }
}

class _Descriptor {
  final DetectorType type;
  final ThreatCategory category;
  final DetectionSeverity severity;
  final String title;
  const _Descriptor(this.type, this.category, this.severity, this.title);
}
