import 'dart:async';
import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'api/api_protection_policy.dart';
import 'detectors/app_intelligence_policy.dart';
import 'detectors/builtin_detectors.dart';
import 'detectors/rasp_native_channel.dart';
import 'license_manager.dart';
import 'protection/protection.dart';
import 'tls/tls_pinning_controller.dart';
import 'trust/config_signing_keys.dart';
import 'trust/signed_config_verifier.dart';

/// Per-customer runtime configuration, published from the dashboard and
/// delivered with each entitlement refresh.
///
/// Values survive restarts via SharedPreferences, so an offline launch still
/// honours the last policy the operator published rather than silently
/// reverting to SDK defaults.
class RemoteConfigManager {
  static const _cacheKey = 'rasp_sdk_remote_config';

  /// Fallbacks, mirroring `DEFAULT_REMOTE_CONFIG` on the backend.
  static const Map<String, dynamic> defaults = {
    'block_on_threat': true,
    'deception_on_critical': true,
    'risk_score_block_threshold': 100,
    // Continuous Security Telemetry milestone: was 15 — the integer-minutes
    // heartbeat model's floor (`clamp(1, 1440)` in `RaspSdk._scheduleHeartbeat`)
    // IS 60 seconds, so "approximately every 60 seconds while active" is
    // this default, not a sub-minute timer. An operator can still raise
    // this per-tenant via signed remote config for a lower-traffic profile.
    'heartbeat_interval_minutes': 1,
    'offline_max_minutes': 30,
    'report_telemetry': true,
  };

  /// The security policy is cached in secure storage rather than
  /// SharedPreferences: it is the document that decides whether the app locks
  /// itself, and prefs are world-readable on a rooted device — precisely the
  /// device this SDK exists to detect.
  static const _policyKey = 'rasp_sdk_protection_policy';
  static const _secureStorage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static Map<String, dynamic> _values = Map.of(defaults);

  // ── Remote Security Control Plane — whole-bundle verify-then-apply ────
  //
  // Closes the gap `trust_anchor_collector.dart` has documented since the
  // Signed Security Configuration milestone: `_merge()` used to overwrite
  // every top-level config value on every heartbeat with NO version gate at
  // all — only the nested `protection_policy` had real monotonic gating via
  // `_adoptPolicy()`. A genuine, correctly-signed, unexpired configuration
  // from last month was still a downgrade if this device had already moved
  // past it, and nothing rejected that.
  //
  // `_applyIncomingConfig` is now the ONLY path that may call `_merge()` —
  // both `syncFromLicense()` and the `applyForTests()` test seam go through
  // it, so a test cannot pass against logic production never runs. A signed
  // bundle is verified (authenticity, freshness, anti-rollback, platform
  // binding) *before* anything is applied; on any rejection the previously
  // held configuration is left completely untouched — never partially
  // applied, never replaced by an unverified one. An unsigned bundle
  // (`ConfigVerificationResult.legacyUnsigned`) is still applied exactly as
  // before this milestone — a deployment with no signing key configured
  // (every test in this suite, and any backend that has not set one) is
  // completely unaffected. See docs/REMOTE_SECURITY_CONTROL_PLANE.md.

  /// The most recently *applied* top-level config version — distinct from
  /// whatever version the latest fetch merely offered. This is the real
  /// "held version" `SignedConfigVerifier` compares a new signed bundle
  /// against; before this fix nothing played that role for the top-level
  /// bundle at all.
  static int _appliedConfigVersion = 0;

  /// SharedPreferences key `_appliedConfigVersion` is persisted under, so a
  /// process restart does not reset downgrade protection to zero — an
  /// attacker able to force an app restart must not thereby regain the
  /// ability to replay an old signed bundle.
  static const _versionCacheKey = 'rasp_sdk_remote_config_applied_version';

  static int get appliedConfigVersion => _appliedConfigVersion;

  /// Outcome of the most recent verification attempt — `null` before any
  /// bundle has ever been offered this session. `legacyUnsigned` means
  /// "applied, but never proven authentic", exactly like every remote config
  /// before this milestone; every other non-`valid` value means the offered
  /// bundle was rejected and the previous one is still in force.
  static ConfigVerificationResult? lastVerificationResult;

  /// Human-readable reason the most recent bundle was rejected, or `null`
  /// when the most recent attempt was applied. Never contains signing
  /// material — mirrors `SignedConfigVerification.detail`.
  static String? lastApplyError;

  /// When this device last *received* a config bundle to evaluate — set
  /// regardless of whether it was applied or rejected.
  static DateTime? lastFetchAt;

  /// When this device last *applied* a new bundle (moved `appliedConfigVersion`
  /// forward). Distinct from [lastFetchAt]: a rejected fetch updates the
  /// former but not the latter.
  static DateTime? lastAppliedAt;

  /// Test-only reset — production code learns every one of these fields from
  /// real network responses / cache restoration.
  @visibleForTesting
  static void resetControlPlaneStateForTesting() {
    _appliedConfigVersion = 0;
    lastVerificationResult = null;
    lastApplyError = null;
    lastFetchAt = null;
    lastAppliedAt = null;
    testTrustRoot = null;
  }

  /// Overrides the trust root a signed bundle is verified against — test
  /// only. Production always resolves `ConfigTrustRoot.fromBuildEnvironment()`
  /// (the real, compiled-in `--dart-define` pinned keys); `flutter test` runs
  /// with none of those defines set, so without this seam no test could ever
  /// construct a bundle this class would actually accept as `valid` — every
  /// signed test bundle would hit `unknownKey` against an empty trust root.
  /// Same precedent as `TrustAnchorCollector`'s own constructor-injected
  /// `trustRoot` parameter. `null` (the default) means "use the real one".
  @visibleForTesting
  static ConfigTrustRoot? testTrustRoot;

  /// Notifies listeners when a heartbeat delivers a new config version.
  ///
  /// Private backing notifier + a [ValueListenable]-typed public getter —
  /// not `static final ValueNotifier<int>` directly — for the same reason
  /// `LicenseManager.status` was changed the same way: a `final` field still
  /// exposes `ValueNotifier.value`'s public setter, which would let any
  /// Dart code in the process forge a config version with no cryptography
  /// involved. See `docs/SDK_SELF_INTEGRITY_AUDIT.md` §15. Unlike
  /// `LicenseManager.status`, nothing outside this file has ever read
  /// this notifier (confirmed by a repo-wide search, including tests), so
  /// no test-only setter is needed.
  static final ValueNotifier<int> _version = ValueNotifier<int>(0);

  static ValueListenable<int> get version => _version;

  static Map<String, dynamic> get values => Map.unmodifiable(_values);

  // ── Protection policy ──────────────────────────────────────────────────

  /// The policy in force. Observe-only until the backend delivers one, so an
  /// SDK that has never reached a server interrupts nobody while still
  /// reporting everything.
  static ProtectionPolicy _policy = ProtectionPolicy.monitorOnly;

  /// Notifies listeners when a newer policy is adopted. Same
  /// private-backing/`ValueListenable`-getter reasoning as [version] above.
  static final ValueNotifier<int> _policyVersion = ValueNotifier<int>(0);

  static ValueListenable<int> get policyVersion => _policyVersion;

  /// The policy the Protection Engine should evaluate against, already aged:
  /// an expired policy resolves to [ProtectionPolicy.strict] rather than
  /// continuing to enforce stale, possibly-too-permissive rules.
  static ProtectionPolicy get policy => _policy.effective();

  /// The raw cached policy, before expiry is applied. Diagnostics only.
  @visibleForTesting
  static ProtectionPolicy get rawPolicy => _policy;

  /// Replace the in-memory policy. Tests only.
  @visibleForTesting
  static void resetPolicyForTests([ProtectionPolicy? next]) {
    _policy = next ?? ProtectionPolicy.monitorOnly;
    _policyVersion.value = _policy.version;
  }

  /// Adopt [incoming] only when it is strictly newer than what we hold.
  ///
  /// Returns whether it was adopted. Rejecting an equal-or-older version is
  /// what stops a replayed policy from downgrading protection: an attacker who
  /// can serve a stale heartbeat body cannot roll a device back to a
  /// permissive stance it has already moved past.
  static bool _adoptPolicy(ProtectionPolicy incoming) {
    if (incoming.version <= _policy.version) return false;
    _policy = incoming;
    _policyVersion.value = incoming.version;
    return true;
  }

  /// Load the last-published config from disk. Call once during SDK startup,
  /// before the first network round trip, so offline launches are configured.
  static Future<void> loadCached() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      final raw = prefs.getString(_cacheKey);
      if (raw != null) {
        final decoded = jsonDecode(raw);
        if (decoded is Map) _merge(Map<String, dynamic>.from(decoded));
      }
      // Restore the genuinely-applied version too — otherwise a process
      // restart would reset downgrade protection to zero, and an attacker
      // able to force a restart would regain the ability to replay an old
      // signed bundle that this device had already moved past.
      _appliedConfigVersion = prefs.getInt(_versionCacheKey) ?? 0;
    } catch (_) {
      // Corrupt cache — defaults already in place.
    }

    // The policy is cached separately, in secure storage. Loaded here so an
    // offline launch enforces the last policy an operator published rather
    // than silently reverting to observe-only.
    try {
      final raw = await _secureStorage.read(key: _policyKey);
      if (raw == null) return;
      final decoded = jsonDecode(raw);
      if (decoded is Map) {
        _adoptPolicy(
          ProtectionPolicy.fromJson(Map<String, dynamic>.from(decoded)),
        );
      }
    } catch (_) {
      // A corrupt or unreadable policy cache leaves the observe-only default
      // in place. It never opens the SDK up: monitorOnly cannot authorise an
      // action that a real policy would have forbidden.
    }
  }

  /// Adopt the config attached to the latest entitlement bundle.
  ///
  /// Verify-then-apply (see the class doc above [_appliedConfigVersion]): a
  /// signed bundle that fails authenticity, freshness, anti-rollback, or
  /// platform-binding checks is rejected outright and the previously held
  /// configuration stays completely untouched.
  static Future<void> syncFromLicense() async {
    final incoming = LicenseManager.remoteConfig;
    if (incoming.isEmpty) return;
    await _applyIncomingConfig(
      incoming,
      incomingVersion: LicenseManager.status.value.configVersion,
    );
  }

  /// Apply a remote-config bundle exactly as a heartbeat would, without one.
  ///
  /// Drives the real [_applyIncomingConfig] path (verify → apply → persist)
  /// rather than a test-only reimplementation, so a test cannot pass against
  /// logic production never runs. [incomingVersion] mirrors what the backend
  /// sends as `config_version`'s sibling field on a real response; omitted,
  /// it defaults to whatever `config_version` the bundle itself carries (0
  /// for the plain unsigned bundles most existing tests already use, which
  /// is exactly the bootstrap case `SignedConfigVerifier` already treats as
  /// "nothing held yet, always accept").
  @visibleForTesting
  static Future<bool> applyForTests(
    Map<String, dynamic> bundle, {
    int? incomingVersion,
  }) {
    return _applyIncomingConfig(
      bundle,
      incomingVersion: incomingVersion ??
          (bundle['config_version'] is num
              ? (bundle['config_version'] as num).toInt()
              : 0),
    );
  }

  /// The one path that may call [_merge] — see the class doc above
  /// [_appliedConfigVersion] for why. Returns whether [incoming] was applied.
  static Future<bool> _applyIncomingConfig(
    Map<String, dynamic> incoming, {
    required int incomingVersion,
  }) async {
    lastFetchAt = DateTime.now().toUtc();

    final envelope = SignedConfigEnvelope.fromConfig(
      incoming,
      configVersionOverride: incomingVersion,
    );

    if (envelope.isSigned) {
      final verifier = SignedConfigVerifier(
        trustRoot: testTrustRoot ?? ConfigTrustRoot.fromBuildEnvironment(),
      );
      final verification = await verifier.verify(
        envelope,
        now: DateTime.now(),
        // `null` — not 0 — when nothing has ever been applied yet, matching
        // SignedConfigVerifier's own bootstrap contract: the very first
        // configuration a device ever sees is always accepted regardless of
        // its version number.
        heldVersion: _appliedConfigVersion > 0 ? _appliedConfigVersion : null,
        heldConfigId: _stringOrNull(_values, 'config_id'),
      );
      lastVerificationResult = verification.result;
      if (verification.result != ConfigVerificationResult.valid) {
        lastApplyError = verification.detail ??
            'signed configuration rejected: ${verification.result.name}';
        return false; // KEEP CURRENT — nothing below this line runs.
      }
    } else {
      // Unsigned: applied exactly as every remote config was before this
      // milestone — a deployment with no signing key configured is
      // completely unaffected. See the class doc above [_appliedConfigVersion].
      lastVerificationResult = ConfigVerificationResult.legacyUnsigned;
    }

    // Platform binding — real and new (see the class doc above). Only
    // enforced when the bundle actually names a platform; an unnamed/`ANY`
    // platform matches every device, exactly like a policy an operator never
    // scoped. Checked after authenticity: an unsigned or forged claim about
    // platform must not be able to reject a legitimate device's config.
    final declaredPlatform = incoming['platform'];
    if (declaredPlatform is String && declaredPlatform.trim().isNotEmpty) {
      final normalized = declaredPlatform.trim().toUpperCase();
      if (normalized != 'ANY') {
        final actual = defaultTargetPlatform == TargetPlatform.android
            ? 'ANDROID'
            : defaultTargetPlatform == TargetPlatform.iOS
                ? 'IOS'
                : null;
        if (actual != null && normalized != actual) {
          lastApplyError =
              'configuration is bound to platform $normalized, this device is $actual';
          return false;
        }
      }
    }

    _merge(incoming);
    _version.value = incomingVersion;
    if (incomingVersion > _appliedConfigVersion) {
      _appliedConfigVersion = incomingVersion;
    }
    lastAppliedAt = DateTime.now().toUtc();
    lastApplyError = null;

    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString(_cacheKey, jsonEncode(_values));
      await prefs.setInt(_versionCacheKey, _appliedConfigVersion);
    } catch (_) {
      // Cache write failure is non-fatal; memory copy is authoritative.
    }

    await _syncPolicy(incoming);
    await _syncSigningCertificate(incoming);
    await _syncTlsPinset(incoming, incomingVersion);
    _syncApiProtection(incoming, incomingVersion);
    _syncAppIntelligence(incoming, incomingVersion);
    return true;
  }

  /// Malware & Risky-App Intelligence policy — hands the `app_intelligence`
  /// block to [AppIntelligencePolicy]. Same reasoning and same "reached only
  /// after verification" property as [_syncApiProtection] above.
  static void _syncAppIntelligence(
    Map<String, dynamic> incoming,
    int incomingVersion,
  ) {
    if (!incoming.containsKey('app_intelligence')) return;
    try {
      AppIntelligencePolicy.applyFromVerifiedConfig(
        incoming,
        configVersion: incomingVersion,
      );
    } catch (e) {
      debugPrint('[RASP-TRACE] APP-INTEL-POLICY apply failed: $e');
    }
  }

  /// API Protection — hands the protected-host policy carried by this
  /// (already-verified) bundle to [ApiProtectionPolicy].
  ///
  /// Reached only after signature, version-monotonicity, expiry and
  /// platform-binding checks have all passed above, which is exactly the
  /// property this policy depends on: if untrusted input could name the
  /// protected hosts, a compromised device would simply drop `api.bank.com`
  /// from the list and send every request unsigned.
  ///
  /// Synchronous and never throws — applying a host list is pure state, and
  /// a malformed block must not be able to take down config delivery for
  /// everything else in the bundle.
  static void _syncApiProtection(
    Map<String, dynamic> incoming,
    int incomingVersion,
  ) {
    if (!incoming.containsKey('api_protection')) return;
    try {
      ApiProtectionPolicy.applyFromVerifiedConfig(
        incoming,
        configVersion: incomingVersion,
      );
    } catch (e) {
      debugPrint('[RASP-TRACE] API-POLICY apply failed: $e');
    }
  }

  /// Dynamic TLS Certificate Pinning — hands the pinset carried by this
  /// (already-verified) bundle to [TlsPinningController] for staging.
  ///
  /// Deliberately the LAST step of the apply path: everything above has
  /// already established that this bundle is authentic, fresh, not a
  /// rollback and bound to this platform, so the controller can treat what
  /// it receives as trusted input and concentrate on the separate question
  /// signing cannot answer — whether the pins are *correct*. See
  /// `TlsPinningController`'s class doc for why that needs live validation
  /// rather than trust alone.
  ///
  /// Never throws and never blocks the rest of config application: a
  /// pinning failure must not be able to take down policy delivery.
  static Future<void> _syncTlsPinset(
    Map<String, dynamic> incoming,
    int incomingVersion,
  ) async {
    if (!incoming.containsKey('tls_pinning')) return;
    try {
      await TlsPinningController.instance.stageFromConfig(
        incoming,
        configVersion: incomingVersion,
      );
    } catch (e) {
      debugPrint('[RASP-TRACE] TLS-PIN staging failed: $e');
    }
  }

  static String? _stringOrNull(Map<String, dynamic> map, String key) {
    final value = map[key];
    return value is String && value.trim().isNotEmpty ? value : null;
  }

  /// Parse, validate, adopt and persist the policy from a heartbeat bundle.
  static Future<void> _syncPolicy(Map<String, dynamic> incoming) async {
    final raw = incoming['protection_policy'];
    // A bundle with no policy leaves whatever is already in force untouched.
    // Treating "absent" as "reset to permissive" would let a truncated
    // response disarm a device.
    if (raw is! Map) return;

    final ProtectionPolicy parsed;
    try {
      parsed = ProtectionPolicy.fromJson(Map<String, dynamic>.from(raw));
    } catch (_) {
      // fromJson is written not to throw; this is belt-and-braces so a
      // malformed policy can never take down the heartbeat.
      return;
    }

    // A policy with no version cannot be ordered against what we hold, so it
    // cannot be trusted not to be a replay. Rejected outright rather than
    // adopted optimistically.
    if (parsed.version <= 0) return;
    if (!_adoptPolicy(parsed)) return;

    try {
      await _secureStorage.write(
        key: _policyKey,
        value: jsonEncode(parsed.toJson()),
      );
    } catch (_) {
      // In-memory policy is authoritative for this session; the next
      // heartbeat re-delivers it.
    }

    unawaited(_enforceScreenshotPolicy(parsed));
  }

  /// Remote Security Control Plane — makes `screenshotProtection.enabled`
  /// (expressed, like every other per-detector toggle, via
  /// `protection_policy.disabled_detectors`) actually change device
  /// behavior, not just gate whether the detector *scans*.
  ///
  /// `RaspShield._runProtectionScan`'s existing gate already stops a
  /// disabled detector from running at all — but the native FLAG_SECURE
  /// window flag `RaspShieldPlugin` applies at activity-attach time is
  /// independent Kotlin state that gate never touched, so a customer who
  /// published `disabled_detectors: ["screenshot_protection"]` would still
  /// have screenshots blocked at the OS level. This closes that: the exact
  /// same native `enableScreenshotRestriction`/`disableScreenshotRestriction`
  /// methods the reference app's own UI has always called, now driven by
  /// policy instead of only a host-app button press. Fails silently (native
  /// call errors are swallowed) — a failed toggle leaves the window in
  /// whatever state it was already in, never a crash, and
  /// `isScreenshotBlockingActive`'s next read reports the real outcome
  /// honestly either way.
  static Future<void> _enforceScreenshotPolicy(ProtectionPolicy policy) async {
    if (!RaspNativeChannel.isSupportedPlatform) return;
    final method = policy.isDetectorDisabled('screenshot_protection')
        ? 'disableScreenshotRestriction'
        : 'enableScreenshotRestriction';
    try {
      await RaspNativeChannel.boolCall(method);
    } catch (_) {
      // See doc above — never let this take down policy sync.
    }
  }

  /// Hand the app's registered signing certificate to the repackaging
  /// detector, which reports NOT_CONFIGURED until it has one.
  static Future<void> _syncSigningCertificate(
    Map<String, dynamic> incoming,
  ) async {
    final fingerprint = incoming['signing_cert_sha256'];
    if (fingerprint is! String || fingerprint.trim().isEmpty) return;
    await RepackagingDetector.configureExpectedCertificate(fingerprint);
  }

  static void _merge(Map<String, dynamic> incoming) {
    final next = Map<String, dynamic>.of(defaults);
    next.addAll(incoming);
    _values = next;
  }

  // ── Typed accessors ────────────────────────────────────────────────────

  static bool getBool(String key, {bool fallback = false}) {
    final value = _values[key];
    if (value is bool) return value;
    return defaults[key] as bool? ?? fallback;
  }

  static int getInt(String key, {int fallback = 0}) {
    final value = _values[key];
    if (value is num) return value.toInt();
    return defaults[key] as int? ?? fallback;
  }

  /// Whether the most recently evaluated configuration proved authentic.
  ///
  /// Set by `TrustAnchorCollector.collect()` from the **same**
  /// `SignedConfigVerifier` verdict that already gates the certificate trust
  /// store — there is one signing mechanism and one verifier, and this is a
  /// read of its result, not a second check.
  ///
  /// Defaults to `false`: until a configuration has been *proven* authentic,
  /// security-sensitive values delivered in it must not be honoured. Any
  /// consumer that reads a threshold from remote config must consult this
  /// first — see `OfflineComplianceEvaluator.resolveThreshold`.
  static bool _configAuthenticated = false;

  static bool get isConfigAuthenticated => _configAuthenticated;

  /// Records the signed-configuration verdict. Called only by
  /// `TrustAnchorCollector`.
  static void setConfigAuthenticated(bool value) {
    _configAuthenticated = value;
  }

  /// Test hook to restore the fail-safe default between cases.
  @visibleForTesting
  static void resetConfigAuthenticatedForTesting() {
    _configAuthenticated = false;
  }

  static bool get blockOnThreat => getBool('block_on_threat', fallback: true);
  static bool get deceptionOnCritical =>
      getBool('deception_on_critical', fallback: true);
  static bool get reportTelemetry => getBool('report_telemetry', fallback: true);
  static int get riskScoreBlockThreshold =>
      getInt('risk_score_block_threshold', fallback: 100);
  static int get heartbeatIntervalMinutes =>
      getInt('heartbeat_interval_minutes', fallback: 15);
  static int get offlineMaxMinutes => getInt('offline_max_minutes', fallback: 30);
}
