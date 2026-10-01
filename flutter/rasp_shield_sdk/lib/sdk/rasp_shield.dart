import 'dart:async';

import 'package:flutter/foundation.dart';

import 'activation_manager.dart' show ActivationManager;
import 'ai/rasp_shield_ai.dart';
import 'api/api_protection.dart';
import 'transaction/transaction_protection.dart';
import 'api/api_protection_policy.dart' show ApiProtectionPolicy;
import 'core/core.dart' show DetectionResult;
import 'detectors/detector_entitlements.dart';
import 'detectors/scan_runner.dart';
import 'detectors/builtin_detectors.dart' show defaultRegistry;
import 'device/device_key_manager.dart' show DeviceKeyManager;
import 'device_identity.dart';
import 'events/security_event_center.dart';
import 'events/security_event_shipper.dart';
import 'protection/protection.dart';
import 'rasp_sdk.dart';
import 'tls/tls_pinning_controller.dart';
import 'vault/vault_client.dart';
import 'risk/risk_posture.dart' show RiskPostureX;
import 'remote_config_manager.dart';
import 'sdk_config.dart';
import 'trust/config_signing_keys.dart' show ConfigVerificationResult;
import 'trust/trust_anchor_collector.dart';
import 'trust/trust_engine.dart';

export 'protection/protection.dart'
    show ProtectionAction, ProtectionResult, ProtectionActionEnforcement;
export 'rasp_sdk.dart' show NativeSecurityLayerStatus, NativeSecurityLayerStatusCode;
export 'events/security_event_shipper.dart' show RaspSecurityEventShipper;

/// Where [RaspShield] is in its startup/runtime lifecycle.
///
/// A strictly forward-moving sequence during startup, ending in exactly one
/// of three terminal-ish states. [degraded] and [blocked] are not dead ends —
/// the next successful [RaspShield.rescan] or heartbeat tick can return the
/// SDK to [protected] — but they are never silently skipped over: a native
/// layer that never answered, or a policy that recommends blocking, is
/// reported as exactly that, never folded into [protected].
enum RaspShieldLifecycleState {
  /// [RaspShield.initialize] has never been called.
  uninitialized,

  /// [RaspShield.initialize] is running; no verdict yet.
  initializing,

  /// Establishing this build's application identity (bundle id, signing
  /// certificate) as part of the activation handshake.
  verifyingApp,

  /// Establishing this install's device identity (device id, device-bound
  /// key) as part of the same handshake.
  verifyingDevice,

  /// The challenge/activate round trip is in flight.
  activating,

  /// Adopting the signed remote configuration and protection policy the
  /// activation response carried.
  loadingPolicy,

  /// A scan has run, the native engine answered, and the policy engine's
  /// recommended action does not require blocking anything. The only state
  /// in which a host app should treat the device as currently clean.
  protected,

  /// Protection could not be fully established — most commonly
  /// [NativeSecurityLayerStatus.unavailable] (see [RaspShieldStatus.degradedReason]).
  /// Never reported as [protected]: an unavailable security layer is an
  /// operational failure, not a clean scan result.
  degraded,

  /// The last evaluation's recommended action was
  /// [ProtectionAction.block]/[ProtectionAction.lockSession]/
  /// [ProtectionAction.lockApp] or higher. The host app owns everything
  /// except [ProtectionAction.lockApp] — see [ProtectionActionEnforcement].
  blocked,

  /// The license itself is in a fatal state ([LicenseStateX.isFatal]) — the
  /// SDK never activated, independent of anything a scan could find.
  failed,
}

/// See [RaspShieldStatus.deviceIdType].
enum DeviceIdType { cryptographic, installScoped }

/// A point-in-time snapshot of [RaspShield]'s health — see
/// [RaspShield.status]. Never claims [RaspShieldLifecycleState.protected]
/// when the native engine has not actually answered.
@immutable
class RaspShieldStatus {
  final RaspShieldLifecycleState lifecycleState;
  final String sdkVersion;

  /// Per-Build Security Personalization — this build's non-secret identity
  /// (`SdkConfig.buildId`), or `''` for an SDK build with no
  /// `--dart-define=RASP_BUILD_ID` (predates this milestone, or a
  /// developer build the customer's own packaging never touched). Safe to
  /// log, safe to show in a diagnostics screen — never a credential.
  final String buildId;
  final NativeSecurityLayerStatus nativeLayerStatus;
  final LicenseState licenseState;

  /// The most recent policy decision, or `null` before any scan has run.
  final ProtectionAction? lastAction;

  /// The most recent risk score (0-100), or `null` before any scan has run.
  final int? lastRiskScore;

  final DateTime? lastScanAt;
  final DateTime? lastTelemetryAt;

  /// Set only in [RaspShieldLifecycleState.degraded] or
  /// [RaspShieldLifecycleState.failed] — a stable, loggable machine reason
  /// (e.g. `NATIVE_SECURITY_LAYER_UNAVAILABLE`), never a translated string.
  final String? degradedReason;

  /// Human-readable reasons behind [lastAction], from the risk engine — see
  /// `ProtectionResult.reasons`.
  final List<String> reasons;

  // ── Remote Security Control Plane visibility ────────────────────────────
  // Never exposes signing material (keys, raw signatures) — only the
  // already-public metadata an operator/support engineer would want to see
  // to answer "did this device get the policy I published".

  /// The top-level remote-config bundle version this device has actually
  /// APPLIED — not merely fetched. See `RemoteConfigManager.appliedConfigVersion`.
  final int policyVersion;

  /// Outcome of the most recent verify-then-apply attempt — `null` before
  /// any bundle has ever been evaluated this session. `legacyUnsigned` means
  /// "applied, but the backend has no signing key configured"; anything else
  /// that is not `valid` means the offered bundle was REJECTED and
  /// [policyVersion] still names the previous, still-in-force one.
  final ConfigVerificationResult? policyVerificationStatus;

  /// Why the most recent bundle was rejected, when it was. `null` when the
  /// most recent evaluated bundle was applied.
  final String? lastPolicyError;

  /// When the currently-applied protection policy was issued by the backend.
  final DateTime? policyIssuedAt;

  /// When the currently-applied protection policy expires — past this, the
  /// policy escalates to [ProtectionPolicy.strict] rather than lapsing to no
  /// protection. See `ProtectionPolicy.effective`.
  final DateTime? policyExpiresAt;

  /// When this device last received a config bundle to evaluate, whether or
  /// not it was applied.
  final DateTime? lastConfigFetchAt;

  /// Detector ids currently disabled by remote policy — surfaced so a host
  /// app (or support engineer reading this status) can tell "this detector
  /// is off by policy" apart from "this detector ran and found nothing".
  /// A disabled detector's own scan result already reports this distinctly
  /// (see `RaspShield._runProtectionScan`'s gate) — this is the same fact,
  /// visible without needing to inspect individual scan results.
  final Set<String> remotelyDisabledDetectors;

  // ── Secure AI Gateway visibility ─────────────────────────────────────
  //
  // Deliberately just these two, not the full `aiAvailable`/`aiPolicyVersion`/
  // `aiProviderStatus` set a spec might list: this SDK has no AI health-check
  // call, so "is AI available right now" is not a fact it actually has —
  // reporting one would be a guess dressed up as a status field. What it DOES
  // genuinely know, from its own most recent `RaspShield.ai.ask()` call, is
  // when that call last completed and — if it failed — the backend's own
  // error code. Both `null` until the first `ask()` call this process.

  // ── Continuous Security Telemetry — Device Identity ──────────────────
  //
  // `deviceId` prefers the cryptographic, Keystore-generated device-binding
  // key id (`DeviceKeyManager.cachedKeyId` — SHA-256 of the device's
  // non-exportable public key, the same value already stamped on every
  // canonical security event as `deviceBindingId`) over the plain
  // install-scoped UUID (`DeviceIdentity`) every SDK call has always sent
  // as `device_id`. `deviceIdType` says honestly which kind this build
  // actually has — never silently claims cryptographic binding a device
  // without a usable Keystore does not have.

  /// This device's RASP identity — see [deviceIdType] for what kind. `null`
  /// only before any identity has been loaded this session (before the
  /// first activation attempt).
  final String? deviceId;

  /// `cryptographic` when [deviceId] is the Keystore-backed device-binding
  /// key id; `installScoped` when it falls back to the plain per-install
  /// UUID (no usable platform Keystore, or the key has not been loaded yet
  /// this session).
  final DeviceIdType deviceIdType;

  /// When the most recent `RaspShield.ai.ask()` call completed.
  final DateTime? lastAiRequest;

  /// The error code from the most recent *failed* AI request, or `null`
  /// when the last one succeeded (or none has been made yet).
  final String? lastAiError;

  const RaspShieldStatus({
    required this.lifecycleState,
    required this.sdkVersion,
    this.buildId = SdkConfig.buildId,
    required this.nativeLayerStatus,
    required this.licenseState,
    this.lastAction,
    this.lastRiskScore,
    this.lastScanAt,
    this.lastTelemetryAt,
    this.degradedReason,
    this.reasons = const [],
    this.policyVersion = 0,
    this.policyVerificationStatus,
    this.lastPolicyError,
    this.policyIssuedAt,
    this.policyExpiresAt,
    this.lastConfigFetchAt,
    this.remotelyDisabledDetectors = const {},
    this.deviceId,
    this.deviceIdType = DeviceIdType.installScoped,
    this.lastAiRequest,
    this.lastAiError,
  });

  /// `true` only in [RaspShieldLifecycleState.protected] — the single
  /// boolean a host app should gate "is this device currently protected and
  /// clean" on, rather than re-deriving it from the other fields.
  bool get isProtected => lifecycleState == RaspShieldLifecycleState.protected;

  Map<String, Object?> toMap() => {
        'lifecycle_state': lifecycleState.name,
        'sdk_version': sdkVersion,
        'native_layer_status': nativeLayerStatus.code,
        'license_state': licenseState.name,
        'last_action': lastAction?.name,
        'last_risk_score': lastRiskScore,
        'last_scan_at': lastScanAt?.toIso8601String(),
        'last_telemetry_at': lastTelemetryAt?.toIso8601String(),
        'degraded_reason': degradedReason,
        'reasons': reasons,
        'policy_version': policyVersion,
        'policy_verification_status': policyVerificationStatus?.name,
        'last_policy_error': lastPolicyError,
        'policy_issued_at': policyIssuedAt?.toIso8601String(),
        'policy_expires_at': policyExpiresAt?.toIso8601String(),
        'last_config_fetch_at': lastConfigFetchAt?.toIso8601String(),
        'remotely_disabled_detectors': remotelyDisabledDetectors.toList(growable: false),
        'last_ai_request': lastAiRequest?.toIso8601String(),
        'last_ai_error': lastAiError,
        'device_id': deviceId,
        'device_id_type': deviceIdType.name,
      };

  @override
  String toString() => 'RaspShieldStatus(${toMap()})';
}

/// One completed protection evaluation, delivered to
/// [RaspShield.onProtectionEvent] as it happens — the reactive counterpart
/// to polling [RaspShield.status]. A host app that wants to react the
/// instant a policy recommends [ProtectionAction.lockApp] or
/// [ProtectionAction.block] should listen here rather than poll.
@immutable
class RaspShieldProtectionEvent {
  final ProtectionResult result;
  final RaspShieldLifecycleState lifecycleState;
  final DateTime at;

  const RaspShieldProtectionEvent({
    required this.result,
    required this.lifecycleState,
    required this.at,
  });
}

/// The public entry point of the RASP Shield SDK.
///
/// ```dart
/// await RaspShield.initialize();
///
/// RaspShield.onProtectionEvent.listen((event) {
///   if (event.result.recommendedAction == ProtectionAction.lockApp) {
///     // The SDK already rendered its own lock screen; nothing to do.
///   } else if (event.result.recommendedAction == ProtectionAction.block) {
///     disableSensitiveFeatures();
///   }
/// });
///
/// final status = RaspShield.status();
/// if (!status.isProtected) showDegradedBanner(status.degradedReason);
/// ```
///
/// ## What "initialize" actually does, automatically
///
/// One call establishes application identity and device identity (the
/// existing challenge/activate handshake — see `ActivationManager`),
/// activates the license, adopts the signed remote configuration and
/// protection policy, runs the SDK's own detector registry once, and
/// evaluates the result through the Protection Engine's risk-aware pipeline
/// (`ProtectionEngine.evaluateWithRisk`) — the same engine every subsequent
/// scan uses. Nothing about this requires the host app to call a detector,
/// register a `MethodChannel`, or poll on its own screen.
///
/// ## Continuous monitoring rides the existing heartbeat — no second timer
///
/// [RaspSdk] already runs one periodic heartbeat for license refresh,
/// remote-config sync, and telemetry flushing. [RaspShield] registers itself
/// as a heartbeat listener (`RaspSdk.addHeartbeatListener`) rather than
/// scheduling a `Timer` of its own, so "continuous protection" costs exactly
/// zero additional timers, wakeups, or battery.
///
/// ## Thin wrapper, not a second state machine
///
/// [RaspShield] does not duplicate licensing, remote-config, or attestation
/// logic — it drives the existing, already-real [RaspSdk] / `LicenseManager`
/// / `RemoteConfigManager` / `AttestationOrchestrator` machinery and adds
/// exactly what was missing: an automatic first scan, automatic continuous
/// scanning, and a lifecycle/status/event model a host app can build a UI on
/// without re-deriving "is this actually protected right now" from five
/// different getters. [RaspSdk] remains available underneath for existing
/// integrations; nothing here changes its behavior.
class RaspShield {
  RaspShield._();

  /// The Secure AI Gateway — see [RaspShieldAi]. `await RaspShield.ai.ask(...)`.
  static const RaspShieldAi ai = RaspShieldAi();

  /// The Secure Vault — see [RaspShieldVault].
  /// `await RaspShield.vault.get("PAYMENT_API_TOKEN")`.
  static RaspShieldVault get vault => RaspShieldVault.instance;

  /// **API Protection** — cryptographic request trust for the customer's own
  /// API. See [RaspShieldApi].
  ///
  /// Automatic protection of an existing client is one line:
  /// `RaspShield.api.protect(myDio)`. Which hosts and paths that covers is
  /// decided by signed remote policy, never by the app — see
  /// [ApiProtectionPolicy] for why that distinction is the whole security
  /// property.
  static const RaspShieldApi api = RaspShieldApi();

  /// **Transaction Protection** — see [RaspShieldTransactions].
  ///
  /// `RaspShield.api` proves a request is authentic. This additionally proves
  /// the *business intent* inside it — ₹10,000 to beneficiary X — is the one
  /// the user approved, by binding the transaction digest into the same
  /// signed message. A bank recomputes that digest from the fields it is
  /// about to execute, so an altered amount fails the signature rather than
  /// needing a manual comparison.
  static const RaspShieldTransactions transactions = RaspShieldTransactions();

  static RaspShieldLifecycleState _lifecycle =
      RaspShieldLifecycleState.uninitialized;
  static ProtectionResult? _lastResult;
  static DateTime? _lastScanAt;
  static DateTime? _lastTelemetryAt;
  static String? _degradedReason;
  static bool _heartbeatWired = false;
  static void Function()? _unwireHeartbeat;

  /// In-flight [initialize] call, so a second concurrent call awaits the
  /// same activation instead of racing it — a common real-world integration
  /// bug (e.g. two widgets both calling `initialize()` on first frame).
  static Future<RaspShieldStatus>? _inFlightInitialize;

  static final StreamController<RaspShieldStatus> _statusController =
      StreamController<RaspShieldStatus>.broadcast();
  static final StreamController<RaspShieldProtectionEvent> _eventController =
      StreamController<RaspShieldProtectionEvent>.broadcast();

  /// Every lifecycle transition, as it happens. A host app can drive its
  /// entire security UI off this stream instead of polling [status].
  static Stream<RaspShieldStatus> get statusStream => _statusController.stream;

  /// Every completed protection evaluation, as it happens — see
  /// [RaspShieldProtectionEvent].
  static Stream<RaspShieldProtectionEvent> get onProtectionEvent =>
      _eventController.stream;

  /// A snapshot of current SDK health. Never reports [RaspShieldLifecycleState.protected]
  /// when the native engine has not actually answered — see
  /// [RaspShieldStatus.isProtected].
  static RaspShieldStatus status() {
    final keyId = DeviceKeyManager.cachedKeyId;
    return RaspShieldStatus(
        lifecycleState: _lifecycle,
        sdkVersion: SdkConfig.sdkVersion,
        buildId: SdkConfig.buildId,
        nativeLayerStatus: RaspSdk.nativeLayerStatus,
        licenseState: RaspSdk.status.state,
        lastAction: _lastResult?.recommendedAction,
        lastRiskScore: _lastResult?.riskScore,
        lastScanAt: _lastScanAt,
        lastTelemetryAt: _lastTelemetryAt,
        degradedReason: _degradedReason,
        reasons: _lastResult?.reasons ?? const [],
        policyVersion: RemoteConfigManager.appliedConfigVersion,
        policyVerificationStatus: RemoteConfigManager.lastVerificationResult,
        lastPolicyError: RemoteConfigManager.lastApplyError,
        policyIssuedAt: RemoteConfigManager.policy.issuedAt,
        policyExpiresAt: RemoteConfigManager.policy.expiresAt,
        lastConfigFetchAt: RemoteConfigManager.lastFetchAt,
        remotelyDisabledDetectors: RemoteConfigManager.policy.disabledDetectors,
        lastAiRequest: RaspShieldAi.lastRequestAt,
        lastAiError: RaspShieldAi.lastErrorCode,
        deviceId: keyId ?? DeviceIdentity.cached,
        deviceIdType:
            keyId != null ? DeviceIdType.cryptographic : DeviceIdType.installScoped,
      );
  }

  /// Establishes application identity and device identity, activates the
  /// license, loads policy, and runs the first protection scan — see the
  /// class doc for the full sequence.
  ///
  /// **Idempotent and concurrency-safe.** A second call while the first is
  /// still running returns the same in-flight result rather than starting a
  /// second activation; a call after a completed initialization re-validates
  /// (equivalent to [rescan] after a fresh license refresh) rather than
  /// re-running the handshake from scratch. Never throws — a failure
  /// surfaces as [RaspShieldLifecycleState.failed] or
  /// [RaspShieldLifecycleState.degraded] in the returned status, exactly
  /// like [RaspSdk.initialize] never throwing today.
  static Future<RaspShieldStatus> initialize() {
    final inFlight = _inFlightInitialize;
    if (inFlight != null) return inFlight;

    final future = _runInitialize();
    _inFlightInitialize = future;
    future.whenComplete(() => _inFlightInitialize = null);
    return future;
  }

  static Future<RaspShieldStatus> _runInitialize() async {
    _wireHeartbeat();
    await _wireTlsPinning();

    _setLifecycle(RaspShieldLifecycleState.initializing);
    // The challenge/activate handshake (inside RaspSdk.initialize →
    // LicenseManager) establishes application identity (bundle id, signing
    // certificate) and device identity (device id, device-bound key) in one
    // round trip — there is no separate network call to split these two
    // states across, so both are reported together around it rather than
    // invented as a fake delay.
    _setLifecycle(RaspShieldLifecycleState.verifyingApp);
    _setLifecycle(RaspShieldLifecycleState.verifyingDevice);
    _setLifecycle(RaspShieldLifecycleState.activating);

    final licenseStatus = await RaspSdk.initialize();

    _setLifecycle(RaspShieldLifecycleState.loadingPolicy);
    // RemoteConfigManager.syncFromLicense() already ran inside
    // RaspSdk.initialize(); RemoteConfigManager.policy reflects it.

    if (licenseStatus.state.isFatal) {
      _degradedReason = 'LICENSE_${licenseStatus.state.name.toUpperCase()}';
      _setLifecycle(RaspShieldLifecycleState.failed);
      return status();
    }

    if (!licenseStatus.state.grantsFeatures) {
      // e.g. LicenseState.pending — awaiting manual approval. Not a failure,
      // but nothing may run yet, so it is honestly reported as degraded
      // rather than protected.
      _degradedReason = 'LICENSE_${licenseStatus.state.name.toUpperCase()}';
      _setLifecycle(RaspShieldLifecycleState.degraded);
      return status();
    }

    await _runProtectionScan();
    return status();
  }

  /// Re-runs the detector registry and re-evaluates policy immediately.
  ///
  /// Useful after a sensitive action, on app resume, or in response to a
  /// remote command — the same evaluation [initialize] and every heartbeat
  /// tick already perform. Safe to call before [initialize] (it is then a
  /// no-op returning the current, [RaspShieldLifecycleState.uninitialized]
  /// status) and safe to call concurrently with [initialize].
  static Future<RaspShieldStatus> rescan() async {
    if (_lifecycle == RaspShieldLifecycleState.uninitialized) return status();
    await _runProtectionScan();
    return status();
  }

  static Future<void> _runProtectionScan({bool isRescan = false}) async {
    final policy = RemoteConfigManager.policy;

    // The same three-way gate the reference app's own scan loop already
    // applies (license entitlement, then policy-level disablement) — see
    // DetectorEntitlements' doc for why this lives in the SDK core rather
    // than being re-supplied by every host app. A gated detector is reported
    // UNAVAILABLE with the reason, never silently omitted and never counted
    // as clean — see ScanRunner's own contract.
    final detections = await ScanRunner(
      registry: defaultRegistry(debugMode: false),
      gate: (detector) {
        final id = detector.detectorId;
        final entitlement = DetectorEntitlements.entitlementFor(id);
        if (entitlement != null && !RaspSdk.allows(entitlement)) {
          return 'Not included in your license plan';
        }
        if (policy.isDetectorDisabled(id)) {
          return 'Disabled by security policy v${policy.version}';
        }
        return null;
      },
    ).scanAll();
    _lastScanAt = DateTime.now().toUtc();

    // Risk + Response Engine milestone: fold self-integrity standing into
    // the same evidence list the risk engine scores, instead of scoring
    // detector output alone. `TrustAnchorCollector().collect()` +
    // `TrustEngine().evaluate()` were already real and exhaustively tested
    // in isolation but never called from the live scan loop — closing that
    // gap is what lets a contradicted identity/signing/sdk-integrity anchor
    // reach `ProtectionEngine`'s existing critical-severity ladder, with no
    // new override logic invented (see `TrustAssessment._severityFor`).
    final trustInputs = await const TrustAnchorCollector().collect();
    final trustAssessment = const TrustEngine().evaluate(trustInputs);
    final evidence = <DetectionResult>[
      ...detections,
      ...trustAssessment.toDetectionResults(),
    ];

    // `RaspSdk.nativeLayerStatus` (read here, and again by every caller of
    // `status()` immediately after this method returns) is derived from
    // `RaspNativeChannel`'s attempt/missing-plugin counters. Both this gate
    // and `status()` must therefore never race a *new* native call — which
    // an `unawaited()` event recorder below genuinely is: calling an async
    // function runs it synchronously up to its first `await`, so if that
    // prefix reaches a native call, `_nativeCallAttempts` increments
    // immediately while the matching `_missingPluginResponses` increment
    // only lands once that call's `MissingPluginException` is actually
    // caught, later in the event loop. A read in that window sees `attempts
    // > missing` and misreads a genuinely fully-unavailable native layer as
    // `available` — caught by `rasp_shield_test.dart`'s existing
    // loud-failure test, not reasoned about in advance (it reproduced both
    // at this gate and, once this gate alone was fixed, again at the
    // caller's later `status()` read). `_recordAsync` below schedules each
    // recorder as a genuinely new macrotask (`Future(...)`, not a directly
    // invoked async function), so none of its native calls can start before
    // this whole synchronous method — and the synchronous resumption of
    // whichever caller `await`s it — has finished running.
    if (RaspSdk.nativeLayerStatus == NativeSecurityLayerStatus.unavailable) {
      // The single most important branch in this class: a native engine
      // that never answered is reported as exactly that, never folded into
      // "scanned clean". See NativeSecurityLayerStatus's own doc.
      _degradedReason = NativeSecurityLayerStatus.unavailable.code;
      _setLifecycle(RaspShieldLifecycleState.degraded);
      _recordAsync(() => SecurityEventCenter.recordDetections(detections));
      _recordAsync(() => SecurityEventCenter.recordTrustAssessment(trustAssessment));
      return;
    }
    _degradedReason = null;

    _recordAsync(() => SecurityEventCenter.recordDetections(detections));
    _recordAsync(() => SecurityEventCenter.recordTrustAssessment(trustAssessment));

    // Ships to the RASP Shield platform's ingestion API (see
    // RaspSecurityEventShipper's class doc) — a no-op until a host app
    // calls RaspSecurityEventShipper.configure() with its downloaded
    // credential. Called directly, not via _recordAsync: that helper
    // exists solely to defer a NEW native-channel call past this
    // method's synchronous return (see its own doc on the
    // attempts-vs-missing race it closes) — the shipper makes no native
    // calls at all (pure Dart/dio), so that race cannot apply here, and
    // it already dispatches its own HTTP call fire-and-forget internally.
    RaspSecurityEventShipper.shipDetectionResults(detections);

    final license = RaspSdk.status;
    final context = ProtectionContext(
      device: ProtectionDeviceInfo(
        deviceId: await DeviceIdentity.get(),
        platform: defaultTargetPlatform.name,
      ),
      sdkVersion: SdkConfig.sdkVersion,
      license: ProtectionLicenseInfo(
        state: license.state.name,
        entitlements: RaspSdk.entitlements.enabledKeys.toSet(),
        expiresAt: license.expiresAt,
      ),
      // Whether the last successful license read came from the offline
      // cache rather than a live backend contact — drives `policy`'s
      // OfflinePolicy (enforce/monitorOnly/fail). See
      // ProtectionContext.isOffline's own doc for why a caller must supply
      // this rather than the engine guessing at connectivity.
      isOffline: license.fromCache,
    );

    final result = const ProtectionEngine().evaluateWithRisk(
      evidence,
      context: context,
      policy: policy,
    );
    _lastResult = result;

    if (result.assessment != null) {
      _recordAsync(() => SecurityEventCenter.recordRiskAssessment(
            result.assessment!,
            evaluatedAt: _lastScanAt,
            action: result.recommendedAction,
            policyVersion: result.policyVersion,
            recommendRescan: result.recommendRescan,
            triggeredByRescan: isRescan,
          ));
    }

    _setLifecycle(
      result.recommendedAction.index >= ProtectionAction.block.index
          ? RaspShieldLifecycleState.blocked
          : RaspShieldLifecycleState.protected,
    );

    _eventController.add(RaspShieldProtectionEvent(
      result: result,
      lifecycleState: _lifecycle,
      at: _lastScanAt!,
    ));

    // FORCE_RESCAN response: evidence was too incomplete to trust the
    // verdict, and nothing already earned a stronger action — see
    // `ProtectionResult.recommendRescan`'s doc. Bounded to exactly one
    // extra pass via `isRescan`: the rescan's own result is never itself
    // eligible to trigger another rescan, so a persistently-indeterminate
    // device settles into its (already-recorded) verdict rather than
    // looping. Fire-and-forget so a slow rescan never blocks the scan that
    // requested it.
    if (!isRescan && result.recommendRescan) {
      _recordAsync(() => _runProtectionScan(isRescan: true));
    }
  }

  /// Schedules [action] as a genuinely new macrotask rather than invoking it
  /// directly. `unawaited(action())` still runs `action`'s synchronous
  /// prefix — up to its first `await` — immediately, which is exactly what
  /// the native-layer-unavailable gate above cannot tolerate from a native
  /// call it does not already know about. `Future(action)` defers even that
  /// prefix until after the current synchronous call stack (and the
  /// microtask that resumes whichever caller is `await`ing this scan) has
  /// fully unwound.
  static void _recordAsync(Future<void> Function() action) {
    unawaited(Future(action));
  }

  static void _wireHeartbeat() {
    if (_heartbeatWired) return;
    _heartbeatWired = true;
    // Continuous Security Telemetry milestone — see
    // `ActivationManager.securityStateProvider`'s doc for why this
    // injection point exists rather than `ActivationManager` reading
    // `RaspShield` state directly. Set once, read fresh on every call: this
    // heartbeat's payload reflects whatever `_runProtectionScan()` most
    // recently computed — necessarily the *previous* cycle's result, since
    // `RaspSdk._scheduleHeartbeat` sends the heartbeat before notifying
    // listeners (this scan included). Converges every cycle; documented,
    // not silently assumed instantaneous.
    ActivationManager.securityStateProvider = _buildHeartbeatSecurityState;
    _unwireHeartbeat = RaspSdk.addHeartbeatListener(() async {
      _lastTelemetryAt = DateTime.now().toUtc();
      if (RaspSdk.status.state.grantsFeatures) {
        await _runProtectionScan();
      }
    });
  }

  static bool _tlsPinningWired = false;

  /// Dynamic TLS Certificate Pinning — restores whatever pinset was
  /// activated in a prior process (so a device enforces the pins it
  /// already validated from its very first request this run, not only
  /// after the first heartbeat lands) and tells the controller which host
  /// is this SDK's own backend, which is the only host eligible for
  /// failure-driven recovery demotion (see `TlsPinningController`'s class
  /// doc for why that host is special).
  ///
  /// A no-op when `SdkConfig` has not been configured yet — mirrors every
  /// other `SdkConfig.isConfigured` guard in this class; the host app is
  /// required to call `SdkConfig.configure()` before `initialize()`.
  static Future<void> _wireTlsPinning() async {
    if (_tlsPinningWired) return;
    _tlsPinningWired = true;
    await TlsPinningController.instance.restore();
    if (!SdkConfig.isConfigured) return;
    try {
      TlsPinningController.instance.backendHost =
          Uri.parse(SdkConfig.sdkApiBaseUrl).host;
    } catch (_) {
      // Malformed backend URL is caught elsewhere (SdkConfig's own
      // validation); pinning simply has no backend host to reason about.
    }
  }

  /// The compact, SDK-observed security-state snapshot folded into every
  /// heartbeat — see `HeartbeatRequest`'s matching fields on the backend.
  /// Deliberately excludes full evidence/detections and full location; a
  /// number, a handful of state words, a timestamp.
  static Map<String, Object?> _buildHeartbeatSecurityState() {
    final result = _lastResult;
    return {
      if (result != null) 'risk_score': result.riskScore,
      if (result != null) 'risk_level': result.highestSeverity?.name,
      if (result != null) 'posture': result.posture.wireName,
      'protection_state': _lifecycle.name,
      'native_layer_state': RaspSdk.nativeLayerStatus.code,
      'reported_policy_version': RemoteConfigManager.appliedConfigVersion,
      if (_lastScanAt != null) 'last_scan_at': _lastScanAt!.toIso8601String(),
    };
  }

  /// Stops the heartbeat and resets to [RaspShieldLifecycleState.uninitialized].
  /// Call from tests or on logout.
  static Future<void> shutdown() async {
    await RaspSdk.shutdown();
    _unwireHeartbeat?.call();
    _unwireHeartbeat = null;
    _heartbeatWired = false;
    _lifecycle = RaspShieldLifecycleState.uninitialized;
    _lastResult = null;
    _lastScanAt = null;
    _lastTelemetryAt = null;
    _degradedReason = null;
  }

  static void _setLifecycle(RaspShieldLifecycleState next) {
    _lifecycle = next;
    _statusController.add(status());
  }
}
