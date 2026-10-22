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
import 'fraud_risk.dart';
import 'security_controls.dart';

export 'fraud_risk.dart';

class RaspLocationSnapshot {
  final double latitude;
  final double longitude;
  final double? accuracyMeters;
  final DateTime capturedAt;

  /// The fix's own mock flag when known (geolocator `Position.isMocked`);
  /// `null` when unknown. Used by `mock_location`.
  final bool? isMock;

  /// The location provider when known (e.g. `gps`, `fused`); evidence only.
  final String? provider;

  /// `true` only when the user opted in to sharing location with the
  /// backend. Then the coordinates are attached to shipped results with
  /// `location_opt_in = true` and sent in a location heartbeat (see
  /// [RaspLeanConfig.locationHeartbeatInterval]); otherwise they stay on the
  /// device and are only used by `mock_location`.
  final bool shareWithBackend;

  const RaspLocationSnapshot({
    required this.latitude,
    required this.longitude,
    this.accuracyMeters,
    required this.capturedAt,
    this.isMock,
    this.provider,
    this.shareWithBackend = false,
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

  /// The app's signing certificate SHA-256 (hex); `tamper` and `repackage`
  /// compare against it. `null` = `tamper` reports UNKNOWN "not configured".
  final String? expectedSigningCertSha256;

  /// `tamper`: installer packages accepted (e.g. `com.android.vending`);
  /// empty = installer not checked.
  final List<String> expectedInstallers;

  /// `tamper`: dex digest baked at build time (see the engine's
  /// `RaspTamperAnalysis.dexSha256`); `null` = not checked.
  final String? expectedClassesDexSha256;

  /// `tamper`: SHA-256 of `resources.arsc` baked at build time; `null` = not checked.
  final String? expectedResourcesArscSha256;
  final bool vpnDetection;
  final bool mitmDetection;

  /// Host for the `mitm` SPKI pin check (e.g. your API host). `null` (or no
  /// [certificatePins]) = no pin check: with no proxy or user-CA signal,
  /// `mitm` is SECURE with `pin_not_configured` evidence.
  final String? certificatePinHost;

  /// Accepted SPKI pins for [certificatePinHost], each `sha256/` + Base64 of
  /// the 32-byte SHA-256 of the certificate's SubjectPublicKeyInfo. Any other
  /// value makes `mitm` report ERROR "invalid pin".
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

  /// Keep the list current from the backend (`GET /v1/reputation/list`, once
  /// a day). The list must verify with [malwareReputationPublicKey], or else
  /// with the credential's `reputation_public_key`. Default off.
  final bool malwareReputationAutoUpdate;
  /// Signed Evidence Envelopes (device key, replay-resistant) instead of the
  /// legacy HMAC path. Default on: new backend applications accept envelopes
  /// only (F-14). Set false only for an old backend.
  final bool useEvidenceEnvelope;
  final Duration pollInterval;
  final Duration heartbeatInterval;

  /// Location heartbeat (Task 9.3): while [RaspLeanSession.currentLocation]
  /// is set with `shareWithBackend: true`, the SDK sends one small signed
  /// `location_heartbeat` event (coarse coordinates, accuracy, fix age, mock
  /// flag) at this interval and on the first fix, independent of threats.
  /// The native side uses at least 30 seconds. Nothing is sent while sharing
  /// is off, nor for a fix older than 2 minutes; turning sharing off sends
  /// one "sharing off" message so the backend clears the stored location.
  /// The delivery result is in [RaspLeanState.locationHeartbeat].
  final Duration locationHeartbeatInterval;

  // Task 8.1 fraud signals — all off by default.
  final bool otpInterceptionDetection;
  final bool smsReaderAbuseDetection;

  /// `otp_forwarding_risk` is a risk hint from the environment, never proof.
  final bool otpForwardingDetection;
  final bool remoteControlAppDetection;
  final bool screenSharingDetection;

  /// Notification-listener packages to trust (e.g. a wearable companion app).
  final List<String> notificationListenerAllowlist;

  /// `sms_reader_abuse`: packages allowed to hold SMS permissions.
  final List<String> smsAppAllowlist;

  /// `otp_forwarding_risk`: extra SMS auto-forward packages (declare them in
  /// the app manifest's `<queries>`).
  final List<String> autoForwardPackages;

  /// `remote_control_app`: signed extra package list, same format as the
  /// malware reputation list.
  final String? remoteControlListJson;

  /// Ed25519 key for [remoteControlListJson] (Base64, raw 32 bytes or SPKI).
  final String? remoteControlListPublicKey;

  // Task 8.1 session risk and transaction API — off by default.
  /// Computes the session risk on every tick and enables
  /// [RaspLeanSession.reportSession], [RaspLeanSession.reportTransaction] and
  /// [RaspLeanSession.signTransaction].
  final bool sessionRiskScoring;
  final int riskMediumThreshold;
  final int riskHighThreshold;

  /// Also recommend step-up at or above this score; `null` = only at HIGH.
  final int? stepUpThreshold;

  /// Stricter profile for sensitive screens: step-up also at MEDIUM and
  /// UNKNOWN. Can be changed with [RaspLeanSession.setHighRiskTransactionMode].
  final bool highRiskTransactionMode;

  /// Salt (hex) for the id hashes when the credential has no
  /// `account_hash_salt`. Normally leave `null`: the issued credential has it.
  final String? accountHashSalt;

  /// How often the auto-updated malware list is refreshed, in hours (1..168).
  final int malwareReputationRefreshHours;

  // Task 10.0 signed remote configuration — off by default.
  /// Fetch and apply the backend's signed remote configuration
  /// (`GET /v1/config`). It is accepted only when its Ed25519 signature
  /// verifies (credential `config_public_key`, or [remoteConfigPublicKey]),
  /// it is for this app, not expired, and newer than the last one; a refused
  /// config is reported as `remote_config_rejected`. It can change
  /// intervals, risk thresholds and the detectors listed in
  /// [remoteManagedDetectors] only — never the backend URL, credential,
  /// keys, envelopes or TLS pins. Status and version are in
  /// [RaspLeanState.remoteConfigStatus] / [RaspLeanState.remoteConfigVersion].
  final bool remoteConfigEnabled;

  /// The ceiling: detector ids (e.g. `root_jailbreak`) a remote config may
  /// switch on or off. Default empty = none.
  final Set<String> remoteManagedDetectors;

  /// Minutes between remote-config checks (5..1440, with jitter).
  final int remoteConfigPollMinutes;

  /// Optional app-pinned public key for the remote config (Base64); else the credential's.
  final String? remoteConfigPublicKey;

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
    this.expectedInstallers = const [],
    this.expectedClassesDexSha256,
    this.expectedResourcesArscSha256,
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
    this.malwareReputationAutoUpdate = false,
    this.useEvidenceEnvelope = true,
    this.pollInterval = const Duration(seconds: 4),
    this.heartbeatInterval = const Duration(seconds: 20),
    this.locationHeartbeatInterval = const Duration(seconds: 60),
    this.otpInterceptionDetection = false,
    this.smsReaderAbuseDetection = false,
    this.otpForwardingDetection = false,
    this.remoteControlAppDetection = false,
    this.screenSharingDetection = false,
    this.notificationListenerAllowlist = const [],
    this.smsAppAllowlist = const [],
    this.autoForwardPackages = const [],
    this.remoteControlListJson,
    this.remoteControlListPublicKey,
    this.sessionRiskScoring = false,
    this.riskMediumThreshold = 30,
    this.riskHighThreshold = 60,
    this.stepUpThreshold,
    this.highRiskTransactionMode = false,
    this.accountHashSalt,
    this.malwareReputationRefreshHours = 24,
    this.remoteConfigEnabled = false,
    this.remoteManagedDetectors = const {},
    this.remoteConfigPollMinutes = 15,
    this.remoteConfigPublicKey,
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
        'expectedInstallers': expectedInstallers,
        'expectedClassesDexSha256': expectedClassesDexSha256,
        'expectedResourcesArscSha256': expectedResourcesArscSha256,
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
        'malwareReputationAutoUpdate': malwareReputationAutoUpdate,
        'useEvidenceEnvelope': useEvidenceEnvelope,
        'pollIntervalMillis': pollInterval.inMilliseconds,
        'heartbeatIntervalMillis': heartbeatInterval.inMilliseconds,
        'locationHeartbeatIntervalMillis': locationHeartbeatInterval.inMilliseconds,
        'otpInterceptionDetection': otpInterceptionDetection,
        'smsReaderAbuseDetection': smsReaderAbuseDetection,
        'otpForwardingDetection': otpForwardingDetection,
        'remoteControlAppDetection': remoteControlAppDetection,
        'screenSharingDetection': screenSharingDetection,
        'notificationListenerAllowlist': notificationListenerAllowlist,
        'smsAppAllowlist': smsAppAllowlist,
        'autoForwardPackages': autoForwardPackages,
        'remoteControlListJson': remoteControlListJson,
        'remoteControlListPublicKey': remoteControlListPublicKey,
        'sessionRiskScoring': sessionRiskScoring,
        'riskMediumThreshold': riskMediumThreshold,
        'riskHighThreshold': riskHighThreshold,
        'stepUpThreshold': stepUpThreshold,
        'highRiskTransactionMode': highRiskTransactionMode,
        'accountHashSalt': accountHashSalt,
        'malwareReputationRefreshHours': malwareReputationRefreshHours,
        'remoteConfigEnabled': remoteConfigEnabled,
        'remoteManagedDetectors': (remoteManagedDetectors.toList()..sort()),
        'remoteConfigPollMinutes': remoteConfigPollMinutes,
        'remoteConfigPublicKey': remoteConfigPublicKey,
      };
}

/// What happened to the last location heartbeat.
enum RaspLocationHeartbeatOutcome {
  /// The backend accepted it.
  delivered,

  /// No answer from the backend: network, backend down, or the device key is
  /// not registered yet. The next heartbeat tries again.
  notDelivered,

  /// The backend refused it (e.g. a wrong or revoked credential).
  rejected,

  /// No backend credential is configured.
  notConfigured,
}

/// Delivery result of the last location heartbeat (Task 9.3).
class RaspLocationHeartbeatStatus {
  final DateTime at;
  final RaspLocationHeartbeatOutcome outcome;

  /// Short text without URLs or keys: "delivered", "HTTP 400", ...
  final String detail;

  /// `true` for the message sent when sharing was turned off.
  final bool cleared;

  const RaspLocationHeartbeatStatus({
    required this.at,
    required this.outcome,
    required this.detail,
    this.cleared = false,
  });

  /// From the native state map; `null` when absent or unreadable.
  static RaspLocationHeartbeatStatus? fromWire(Object? raw) {
    if (raw is! Map) return null;
    final atMillis = raw['atMillis'];
    final outcome = switch (raw['outcome']) {
      'DELIVERED' => RaspLocationHeartbeatOutcome.delivered,
      'NOT_DELIVERED' => RaspLocationHeartbeatOutcome.notDelivered,
      'REJECTED' => RaspLocationHeartbeatOutcome.rejected,
      'NOT_CONFIGURED' => RaspLocationHeartbeatOutcome.notConfigured,
      _ => null,
    };
    if (atMillis is! num || outcome == null) return null;
    final detail = raw['detail'];
    return RaspLocationHeartbeatStatus(
      at: DateTime.fromMillisecondsSinceEpoch(atMillis.toInt()),
      outcome: outcome,
      detail: detail is String ? detail : outcome.name,
      cleared: raw['cleared'] == true,
    );
  }
}

/// Where the signed remote configuration stands (Task 10.0).
enum RaspRemoteConfigStatus {
  /// `remoteConfigEnabled` is off.
  off,

  /// No credential or no config public key: nothing can be verified.
  unavailable,

  /// Nothing received yet, or nothing published; the app's own config applies.
  waiting,

  /// A verified config is applied.
  applied,

  /// The last config received was refused; the last good one (or the app's own) still applies.
  rejected,

  /// The stored config expired; the app's own config applies again.
  expired;

  static RaspRemoteConfigStatus fromWire(Object? raw) => switch (raw) {
        'UNAVAILABLE' => unavailable,
        'WAITING' => waiting,
        'APPLIED' => applied,
        'REJECTED' => rejected,
        'EXPIRED' => expired,
        _ => off,
      };
}

class RaspLeanState {
  final bool? screenshotActive;
  final RaspUsbState usb;
  final bool? clipboardActive;
  final RaspClipboardEvidence clipboardEvidence;
  final Map<String, DetectionResult> extendedDetectors;

  /// Session risk from the last tick; `null` unless `sessionRiskScoring` is on.
  final RaspSessionRisk? risk;

  /// Delivery result of the last location heartbeat; `null` until one was sent.
  final RaspLocationHeartbeatStatus? locationHeartbeat;

  /// Version of the applied remote config; `null` when none (Task 10.0).
  final int? remoteConfigVersion;
  final RaspRemoteConfigStatus remoteConfigStatus;

  const RaspLeanState({
    required this.screenshotActive,
    required this.usb,
    required this.clipboardActive,
    required this.clipboardEvidence,
    this.extendedDetectors = const {},
    this.risk,
    this.locationHeartbeat,
    this.remoteConfigVersion,
    this.remoteConfigStatus = RaspRemoteConfigStatus.off,
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
  /// `null` clears the location on the native side too (e.g. when the user
  /// turns location sharing off), so nothing more is shipped or checked.
  set currentLocation(RaspLocationSnapshot? value) {
    _currentLocation = value;
    if (_disposed) return;
    if (value == null) {
      unawaited(RaspNativeChannel.boolCall('clearLeanSessionLocation'));
      return;
    }
    unawaited(RaspNativeChannel.boolCall('setLeanSessionLocation', {
      'latitude': value.latitude,
      'longitude': value.longitude,
      'accuracyMeters': value.accuracyMeters,
      'capturedAtMillis': value.capturedAt.millisecondsSinceEpoch,
      'isMock': value.isMock,
      'provider': value.provider,
      'shareWithBackend': value.shareWithBackend,
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

  // ── Task 8.1: session risk and transaction API ───────────────────────

  /// The session risk from the last tick; `null` until the first tick or when
  /// `sessionRiskScoring` is off.
  RaspSessionRisk? get risk => _current.risk;

  /// Reports a login, resume or logout. The ids are pseudonymous values from
  /// your app (never an email or phone number); the native engine hashes
  /// them at once and never stores or sends them. Needs `sessionRiskScoring`
  /// and a salt (from the credential). Throws [RaspFraudApiException].
  Future<RaspSessionReport> reportSession({
    required String accountId,
    required String sessionId,
    required RaspSessionEvent event,
  }) async {
    final raw = await _fraudCall('reportLeanSession', {
      'accountId': accountId,
      'sessionId': sessionId,
      'event': event.name,
    });
    return RaspSessionReport(
      accountHash: raw['accountHash'] as String,
      sessionHash: raw['sessionHash'] as String,
      event: RaspSessionEvent.values.firstWhere((e) => e.name == raw['event'], orElse: () => event),
      risk: RaspSessionRisk.fromWire(raw['risk']),
      sentToBackend: raw['sentToBackend'] == true,
    );
  }

  /// Signs the transaction binding with the device key and reports the
  /// transaction (hashes and the binding digest; the amount stays on the
  /// device). [amount]: plain decimal string, e.g. `"1500.00"`; [currency]:
  /// ISO 4217 (`INR`); [channel]: `[a-z0-9_-]{1,32}` (e.g. `upi`). Needs an
  /// active session ([reportSession] with login). Throws [RaspFraudApiException].
  Future<RaspTransactionReport> reportTransaction({
    required String amount,
    required String currency,
    required String beneficiaryId,
    required String channel,
  }) async {
    final raw = await _fraudCall('reportLeanTransaction', {
      'amount': amount,
      'currency': currency,
      'beneficiaryId': beneficiaryId,
      'channel': channel,
    });
    final transaction = raw['transaction'];
    if (transaction is! Map) throw const RaspFraudApiException('UNAVAILABLE', 'Malformed native reply');
    return RaspTransactionReport(
      transaction: RaspSignedTransaction.fromWire(transaction.map((k, v) => MapEntry('$k', v))),
      channel: raw['channel'] as String? ?? channel,
      sentToBackend: raw['sentToBackend'] == true,
    );
  }

  /// Signs the transaction binding only; nothing is sent. Throws
  /// [RaspFraudApiException].
  Future<RaspSignedTransaction> signTransaction({
    required String amount,
    required String currency,
    required String beneficiaryId,
  }) async {
    final raw = await _fraudCall('signLeanTransaction', {
      'amount': amount,
      'currency': currency,
      'beneficiaryId': beneficiaryId,
    });
    return RaspSignedTransaction.fromWire(raw);
  }

  /// Turns the stricter high-risk transaction profile on or off (e.g. while
  /// a payment screen is open). The SDK only recommends; your app enforces.
  Future<RaspSessionRisk> setHighRiskTransactionMode(bool enabled) async =>
      RaspSessionRisk.fromWire(await _fraudCall('setLeanHighRiskTransactionMode', enabled));

  Future<Map<String, Object?>> _fraudCall(String method, Object? arguments) async {
    if (_disposed) throw const RaspFraudApiException('UNAVAILABLE', 'Session disposed');
    try {
      final raw = await RaspNativeChannel.mapCallOrThrow(method, arguments);
      if (raw == null) throw const RaspFraudApiException('UNAVAILABLE', 'No native answer');
      return raw;
    } on PlatformException catch (e) {
      throw RaspFraudApiException(e.code, e.message ?? e.code);
    }
  }

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

  /// Checks the backend for a new remote config now (in the background).
  /// No-op unless `remoteConfigEnabled`; the result arrives in [states].
  Future<void> refreshRemoteConfigNow() async {
    if (!_disposed) await RaspNativeChannel.boolCall('refreshLeanRemoteConfig');
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
      risk: raw['risk'] is Map ? RaspSessionRisk.fromWire(raw['risk']) : null,
      locationHeartbeat: RaspLocationHeartbeatStatus.fromWire(raw['locationHeartbeat']),
      remoteConfigVersion: (raw['remoteConfigVersion'] as num?)?.toInt(),
      remoteConfigStatus: RaspRemoteConfigStatus.fromWire(raw['remoteConfigStatus']),
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
/// four basic controls) has an entry here; titles and categories follow the
/// dashboard's catalog (`FE/lib/alertCatalog.ts`), severities the backend's
/// table (`BE/src/detectors/severity.ts`, exported to
/// test/fixtures/detector_severities.json; `test/detector_severity_test.dart`
/// fails on any difference, F-26). An id without an entry gets [generic]
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
    'root_jailbreak': RaspDetectorDescriptor(DetectorType.root, ThreatCategory.deviceIntegrity, DetectionSeverity.critical, 'Root / Jailbreak'),
    'emulator': RaspDetectorDescriptor(DetectorType.emulator, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Emulator'),
    'device_binding': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'Device Binding'),
    'clone': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.high, 'App Clone / Dual Space'),
    'developer_mode': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.low, 'Developer Mode'),
    'device_lock_missing': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Device Lock'),
    'secure_hardware_unavailable': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.low, 'Hardware-Backed Keystore'),
    'device_fingerprint': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.deviceIntegrity, DetectionSeverity.medium, 'Device Fingerprint'),
    // Runtime protection
    'frida': RaspDetectorDescriptor(DetectorType.frida, ThreatCategory.runtimeProtection, DetectionSeverity.critical, 'Frida'),
    'debugger': RaspDetectorDescriptor(DetectorType.debugger, ThreatCategory.runtimeProtection, DetectionSeverity.medium, 'Debugger'),
    'hook_detection': RaspDetectorDescriptor(DetectorType.hook, ThreatCategory.runtimeProtection, DetectionSeverity.critical, 'Hook Detection'),
    're_tools': RaspDetectorDescriptor(DetectorType.reverseEngineeringTools, ThreatCategory.runtimeProtection, DetectionSeverity.high, 'Reverse Engineering Tools'),
    'risky_app': RaspDetectorDescriptor(DetectorType.riskyApp, ThreatCategory.other, DetectionSeverity.high, 'Risky Application / Environment'),
    // App integrity
    'tamper': RaspDetectorDescriptor(DetectorType.tamper, ThreatCategory.appIntegrity, DetectionSeverity.high, 'App Tampering'),
    'repackage': RaspDetectorDescriptor(DetectorType.repackage, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Repackaging'),
    'untrusted_install_source': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Installation Source'),
    // Network security
    'vpn': RaspDetectorDescriptor(DetectorType.vpn, ThreatCategory.networkSecurity, DetectionSeverity.low, 'VPN'),
    'mitm': RaspDetectorDescriptor(DetectorType.proxy, ThreatCategory.networkSecurity, DetectionSeverity.high, 'MITM / Proxy'),
    'high_risk_ip': RaspDetectorDescriptor(DetectorType.highRiskIp, ThreatCategory.networkSecurity, DetectionSeverity.medium, 'High-risk IP'),
    // Privacy & screen
    'overlay': RaspDetectorDescriptor(DetectorType.overlay, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Overlay'),
    'accessibility': RaspDetectorDescriptor(DetectorType.accessibility, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'Accessibility Abuse'),
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
    // Task 8.1 fraud signals (same title, category and severity as the dashboard)
    'otp_interception_risk': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.high, 'OTP Interception Risk'),
    'sms_reader_abuse': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.high, 'SMS Reader Apps'),
    'otp_forwarding_risk': RaspDetectorDescriptor(DetectorType.custom, ThreatCategory.privacyScreen, DetectionSeverity.medium, 'OTP Forwarding Risk (hint)'),
    'remote_control_app': RaspDetectorDescriptor(DetectorType.riskyApp, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Remote Control App'),
    'screen_sharing_risk': RaspDetectorDescriptor(DetectorType.screenshot, ThreatCategory.privacyScreen, DetectionSeverity.high, 'Screen Sharing During App Use'),
    // Task 10.0 signed remote configuration
    'remote_config_rejected': RaspDetectorDescriptor(DetectorType.tamper, ThreatCategory.appIntegrity, DetectionSeverity.high, 'Remote Configuration Rejected'),
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
