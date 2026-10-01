import 'dart:async';
import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'activation_manager.dart';
import 'device/device.dart';
import 'events/security_event_center.dart';
import 'license_models.dart';
import 'offline/offline_compliance_store.dart';
import 'offline/trusted_clock.dart';
import 'sdk_config.dart';
import 'trust/attestation/attestation_orchestrator.dart';

/// Owns the license lifecycle: activation, offline caching, grace-period
/// enforcement, and the remote kill switch.
///
/// Offline behaviour
/// -----------------
/// Every successful activation or heartbeat yields a signed entitlement token.
/// It is cached in secure storage and re-verified locally on each launch, so
/// the app keeps working without a network until `grace_until` passes. A
/// REVOKED verdict purges the cache immediately.
///
/// Integrity note
/// --------------
/// The token is HMAC-signed with the license key that this build already
/// carries. That defeats tampering by anyone *without* the key, but not by an
/// attacker who has extracted it from the binary. Hardware-backed attestation
/// (Play Integrity) is the answer to that, and is not yet wired up.
class LicenseManager {
  static const _tokenKey = 'rasp_sdk_entitlement_token';
  static const _activationKey = 'rasp_sdk_activation_token';

  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  /// Broadcasts license changes so UI can react to a mid-session kill switch.
  ///
  /// ## Why this is not just `static final ValueNotifier<LicenseStatus>`
  ///
  /// `ValueNotifier<T>` is `final`-safe against *reassignment*, but its own
  /// `.value` setter is public — a `static final ValueNotifier` field is a
  /// one-line, no-cryptography licensing bypass reachable from any Dart code
  /// in the process (`LicenseManager.status.value = LicenseStatus(state:
  /// LicenseState.active, ...)`), since `allows()`/`RaspSdk.allows()` read
  /// straight from it. Found in the SDK Self-Integrity audit — see
  /// `docs/SDK_SELF_INTEGRITY_AUDIT.md` §12. The backing notifier is private;
  /// the public surface is typed as [ValueListenable], whose interface has
  /// no setter at all, so every legitimate read call site (`.value` getter,
  /// used everywhere this was previously read) keeps compiling unchanged
  /// while `.value = ...` from outside this file no longer does.
  static final ValueNotifier<LicenseStatus> _status =
      ValueNotifier<LicenseStatus>(const LicenseStatus.uninitialized());

  static ValueListenable<LicenseStatus> get status => _status;

  /// Test-only escape hatch for the write access the read-only [status]
  /// getter above deliberately does not expose. Named and annotated so it is
  /// flagged by tooling if ever called outside a test.
  @visibleForTesting
  static void setStatusForTesting(LicenseStatus value) {
    _status.value = value;
  }

  static Map<String, dynamic> _lastRemoteConfig = const {};

  /// Remote configuration delivered alongside the most recent entitlements.
  static Map<String, dynamic> get remoteConfig => _lastRemoteConfig;

  /// Additive, read-only hand-off of the heartbeat's `pending_commands` to the
  /// remote-command dispatcher (wired by `RaspSdk`). The commands ride the same
  /// heartbeat response as [remoteConfig]; this only forwards them. It makes no
  /// licensing decision, and while unset (the default) it is a no-op — so
  /// existing licensing behaviour is unchanged. See [_acceptBundle].
  static void Function(List<dynamic> rawCommands)? onPendingCommands;

  static Entitlements get entitlements => status.value.entitlements;

  /// Convenience guard used by detectors: a feature runs only when the license
  /// is valid *and* the entitlement is granted.
  static bool allows(String entitlementKey) =>
      status.value.grantsFeatures && status.value.entitlements.has(entitlementKey);

  /// This device's activation token from the last successful activate/heartbeat,
  /// or `null` before the device has ever activated. `/security/analyze`
  /// requires it — a device with no token has nothing to prove it's real.
  static Future<String?> get activationToken => _read(_activationKey);

  /// The `issued_at` claim of the cached entitlement token, **only** if the
  /// token's signature verifies. `null` otherwise.
  ///
  /// This is the SDK's trusted-time anchor and its proof of last
  /// authenticated backend contact, in one value: the server stamps
  /// `issued_at` (`build_entitlement_token`, `app/licensing/service.py`),
  /// HMAC-signs the payload with the licence key, and only ever issues a
  /// token from a successful `/activate` or `/heartbeat`. A token whose
  /// signature does not verify yields `null` rather than its claimed time,
  /// so editing the cached blob destroys the anchor instead of moving it.
  ///
  /// Consumed by `OfflineComplianceDetector` — see
  /// `docs/OFFLINE_COMPLIANCE_MODEL.md`. Deliberately narrow: it exposes one
  /// timestamp, not the payload, so no new caller can start trusting
  /// unverified claims through this door.
  static Future<DateTime?> get lastAuthenticatedContact async {
    final token = await _read(_tokenKey);
    if (token == null || token.isEmpty) return null;
    final payload = verifyToken(token);
    if (payload == null) return null;
    return _parseUtc(payload['issued_at']);
  }

  // ── Token verification ──────────────────────────────────────────────────

  static String _b64uNormalize(String input) =>
      input.padRight(input.length + ((4 - input.length % 4) % 4), '=');

  /// Verify the `payload.signature` envelope against the embedded license key.
  ///
  /// Returns the decoded payload, or `null` when the signature does not match
  /// or the token is malformed.
  @visibleForTesting
  static Map<String, dynamic>? verifyToken(String token) {
    final parts = token.split('.');
    if (parts.length != 2) return null;

    final hmac = Hmac(sha256, utf8.encode(SdkConfig.licenseKey.trim()));
    final expected = base64Url
        .encode(hmac.convert(utf8.encode(parts[0])).bytes)
        .replaceAll('=', '');
    if (expected != parts[1]) return null;

    try {
      final decoded = utf8.decode(base64Url.decode(_b64uNormalize(parts[0])));
      final json = jsonDecode(decoded);
      return json is Map<String, dynamic> ? json : null;
    } catch (_) {
      return null;
    }
  }

  static DateTime? _parseUtc(Object? value) {
    if (value is! String || value.isEmpty) return null;
    return DateTime.tryParse(value)?.toUtc();
  }

  // ── Device binding (Phase 5 / Phase 7) ─────────────────────────────────

  static const _bindingValidator = LicenseBindingValidator();

  /// The binding verdict from the most recent evaluation of a licence token.
  ///
  /// Published for `TrustAnchorCollector`, which turns it into
  /// `DEVICE_KEY_*` evidence on the existing `TrustAnchor.deviceBinding`
  /// anchor. Deliberately a *read* of a decision licensing already made —
  /// the trust engine does not re-derive it, so the two surfaces cannot
  /// disagree about whether this device is bound.
  static LicenseBindingResult? get bindingResult => _bindingResult;
  static LicenseBindingResult? _bindingResult;

  /// Test seam: clears the published binding verdict between cases.
  @visibleForTesting
  static void resetBindingForTesting() => _bindingResult = null;

  /// Validate a verified token's binding claims against this install.
  ///
  /// Never throws: a platform read that fails yields an observation with
  /// nothing to compare, which produces an indeterminate verdict — never a
  /// fabricated pass and never a fabricated mismatch.
  static Future<LicenseBindingResult> _evaluateBinding(
    Map<String, dynamic> payload,
  ) async {
    try {
      final observation = await ActivationManager.bindingObservation(
        tenantId: payload['tenant_id']?.toString(),
      );
      return _bindingValidator.validate(
        payload: payload,
        observation: observation,
      );
    } catch (_) {
      return const LicenseBindingResult(
        verdict: DeviceBindingVerdict.keyError,
      );
    }
  }

  /// The shared clock high-water mark, reused from Offline Compliance.
  ///
  /// Deliberately the **same** store, not a parallel one: two subsystems
  /// asking "did the clock move backwards?" must not be able to disagree,
  /// and a second mark would be a second thing to tamper with. See
  /// `docs/LICENSE_TRUSTED_TIME_MODEL.md`.
  static const _clockStore = OfflineComplianceStore();

  static const _trustedClock = TrustedClock();

  /// Assess the device clock for a cached-token evaluation.
  ///
  /// The anchor is this token's own `issued_at` — already verified, since
  /// [payload] only exists when `verifyToken` succeeded. A storage failure
  /// yields a `null` high-water mark, which weakens the cross-launch check
  /// but never turns an untrustworthy clock into a trustworthy one: the
  /// anchor comparison needs no local state at all.
  static Future<ClockCredibility> _assessClock(
    Map<String, dynamic> payload,
    DateTime now,
  ) async {
    DateTime? highWaterMark;
    try {
      highWaterMark = await _clockStore.readClockHighWaterMark();
    } catch (_) {
      highWaterMark = null;
    }
    return _trustedClock.assess(
      anchorIssuedAt: _parseUtc(payload['issued_at']),
      now: now,
      clockHighWaterMark: highWaterMark,
    );
  }

  /// Test seam for [_statusFromPayload], the function the clock-rollback
  /// protection lives in.
  ///
  /// Annotated rather than made public so the hardened decision can be
  /// exercised directly — asserting the real production function, not a
  /// re-implementation of it in a test.
  @visibleForTesting
  static LicenseStatus statusFromPayloadForTesting(
    Map<String, dynamic> payload, {
    required bool fromCache,
    ClockCredibility clockCredibility = ClockCredibility.credible,
    LicenseBindingResult? binding,
    DateTime? now,
  }) =>
      _statusFromPayload(
        payload,
        fromCache: fromCache,
        clockCredibility: clockCredibility,
        binding: binding,
        now: now,
      );

  /// Convert a verified token payload into a status, applying expiry + grace.
  ///
  /// ## Clock-rollback protection (License Time Security milestone)
  ///
  /// [clockCredibility] is the [TrustedClock] verdict for this evaluation.
  /// When the clock is **not** credible, a *cached* token may no longer buy
  /// `active` or `grace`: both are the fail-open direction, and the whole
  /// attack was rewinding the device clock past a cached token's
  /// `expires_at` to re-enable an expired licence indefinitely, offline,
  /// forever. See `docs/LICENSE_TIME_SECURITY_AUDIT.md` §2.
  ///
  /// A *fresh* token (`fromCache: false`) is exempt: the server has just
  /// responded, its own `REVOKED`/`SUSPENDED`/`EXPIRED`/`GRACE` verdict is
  /// applied around this call, and the token was minted seconds ago. Penalising
  /// that path would lock out a legitimate user whose clock is merely wrong —
  /// a denial of service in exchange for no security.
  ///
  /// The resulting state is `expired`, which already exists and which every
  /// surface already handles. No new state was introduced, and no existing
  /// state was renamed.
  static LicenseStatus _statusFromPayload(
    Map<String, dynamic> payload, {
    required bool fromCache,
    ClockCredibility clockCredibility = ClockCredibility.credible,
    LicenseBindingResult? binding,
    DateTime? now,
  }) {
    final expiresAt = _parseUtc(payload['expires_at']);
    final graceUntil = _parseUtc(payload['grace_until']);
    final at = (now ?? DateTime.now()).toUtc();

    // A cached token evaluated against an untrustworthy clock cannot be
    // used to claim validity. Deliberately not applied to a fresh bundle.
    final clockBlocksExtension = fromCache && !clockCredibility.isCredible;

    LicenseState state;
    String message;
    if (binding != null && binding.isContradicted) {
      // Identity outranks time, so this is tested before the clock guard:
      // a token belonging to a different device is not "expired here", it
      // is not this device's licence at all. `unlicensed` — never softened
      // to `grace`, and never silently downgraded to a clean status.
      state = LicenseState.unlicensed;
      message = binding.reason ?? 'License is bound to a different device';
    } else if (clockBlocksExtension) {
      state = LicenseState.expired;
      message = 'License could not be verified — '
          '${clockCredibility.reason ?? 'device time is not trustworthy'}';
    } else if (expiresAt != null && at.isBefore(expiresAt)) {
      state = LicenseState.active;
      message = 'License active';
    } else if (graceUntil != null && at.isBefore(graceUntil)) {
      state = LicenseState.grace;
      message = 'License expired — running in offline grace period';
    } else {
      state = LicenseState.expired;
      message = 'License expired';
    }

    return LicenseStatus(
      state: state,
      entitlements: Entitlements.fromJson(
        (payload['entitlements'] as Map?)?.cast<String, dynamic>(),
      ),
      message: message,
      expiresAt: expiresAt,
      graceUntil: graceUntil,
      plan: (payload['plan'] as String?) ?? 'UNKNOWN',
      configVersion: (payload['config_version'] as num?)?.toInt() ?? 0,
      fromCache: fromCache,
    );
  }

  // ── Cache ───────────────────────────────────────────────────────────────

  static Future<String?> _read(String key) async {
    try {
      return await _storage.read(key: key);
    } catch (_) {
      return null;
    }
  }

  /// Seed the seat obtained by email-verified enrollment.
  ///
  /// Writing the token under the same key a normal activation uses is what
  /// makes [initialize] take its heartbeat path instead of trying to activate,
  /// which an enrolled build cannot do — it has no licence key to sign with.
  static Future<void> adoptEnrolledSeat(String activationToken) async {
    if (activationToken.isEmpty) return;
    final existing = await _read(_activationKey);
    if (existing == activationToken) return;
    await _write(_activationKey, activationToken);
  }

  static Future<void> _write(String key, String value) async {
    try {
      await _storage.write(key: key, value: value);
    } catch (_) {
      // Non-fatal: the session continues from memory, next launch re-activates.
    }
  }

  static Future<void> _purge() async {
    for (final key in [_tokenKey, _activationKey]) {
      try {
        await _storage.delete(key: key);
      } catch (_) {
        // Best effort.
      }
    }
  }

  /// Persist the entitlement bundle returned by activate/heartbeat.
  static Future<LicenseStatus> _acceptBundle(
    ActivationResult result, {
    String? activationToken,
  }) async {
    final token = result.payload['entitlement_token'] as String?;
    if (token == null) {
      return LicenseStatus(
        state: LicenseState.unlicensed,
        message: 'Server did not return an entitlement token',
      );
    }
    final payload = verifyToken(token);
    if (payload == null) {
      return const LicenseStatus(
        state: LicenseState.unlicensed,
        message: 'Entitlement token failed signature verification',
      );
    }

    await _write(_tokenKey, token);
    if (activationToken != null) await _write(_activationKey, activationToken);

    final config = result.payload['remote_config'];
    if (config is Map) _lastRemoteConfig = Map<String, dynamic>.from(config);

    // Forward any operator commands delivered on this heartbeat to the
    // dispatcher. Read-only: the entitlement/state logic below is untouched.
    final commands = result.payload['pending_commands'];
    if (commands is List && commands.isNotEmpty) onPendingCommands?.call(commands);

    // Phase 7 — a freshly-issued token is validated for binding too, not
    // only cached ones. The server has just spoken, but what it handed back
    // is still a token: if its claims name a different device, application,
    // tenant or signing identity than the one running here, something
    // between the two is wrong and the honest answer is to refuse rather
    // than to trust the response because it was recent.
    _bindingResult = await _evaluateBinding(payload);

    var next = _statusFromPayload(
      payload,
      fromCache: false,
      binding: _bindingResult,
    );
    // A server-reported GRACE upgrades `expired` to `grace`, but must never
    // reinstate a licence this device is not bound to: the binding failure
    // is about identity, and the server's grace verdict is about time.
    if (result.status == 'GRACE' && !(_bindingResult?.isContradicted ?? false)) {
      next = next.copyWith(
        state: LicenseState.grace,
        message: result.message.isEmpty ? next.message : result.message,
      );
    }
    return next;
  }

  static LicenseStatus _fatal(LicenseState state, String message) =>
      LicenseStatus(state: state, message: message);

  static LicenseState _stateForCode(String code) {
    switch (code) {
      case 'REVOKED':
      case 'DEVICE_REVOKED':
        return LicenseState.revoked;
      case 'SUSPENDED':
        return LicenseState.suspended;
      case 'EXPIRED':
        return LicenseState.expired;
      case 'PENDING':
        return LicenseState.pending;
      case 'SDK_UPGRADE_REQUIRED':
        return LicenseState.upgradeRequired;
      default:
        return LicenseState.unlicensed;
    }
  }

  // ── Public API ──────────────────────────────────────────────────────────

  /// Runs the full attestation cycle and **waits for it** before this
  /// process's first ``/activate`` attempt in a session.
  ///
  /// P0-5 ordering fix: a licence's ``require_app_integrity`` gate is
  /// evaluated by the backend *inside* ``/activate`` — it looks up the most
  /// recent, unconsumed, VALID ``attestation_results`` row for this
  /// (license, device). That row can only exist if attestation already ran.
  /// Before this fix, [AttestationOrchestrator] ran fire-and-forget *after*
  /// activation (see its own class doc — a deliberate choice for its
  /// original purpose, feeding [TrustAnchorCollector]'s scan-time risk
  /// scoring), which meant a licence with the gate turned on would reject
  /// every real device: the SDK never had a proof on file yet.
  ///
  /// Awaited (not fire-and-forget) so the guarantee is real: by the time
  /// [ActivationManager.activate] is called, whatever attestation this
  /// device is capable of producing has already been attempted and, on
  /// success, already recorded server-side. [AttestationOrchestrator.run]
  /// itself never throws and resolves within [SdkConfig.networkTimeout] on
  /// every path (native-unavailable, network failure, non-Android) — the
  /// same fail-soft contract described on that method — so this cannot hang
  /// initialize() indefinitely, and adds no risk for the (default, and
  /// still the common case) licence that never turns the gate on: the
  /// backend simply ignores whatever proof is or is not on file.
  ///
  /// Not underscore-private — `@visibleForTesting`, same convention as
  /// [ActivationManager.resetDeviceBindingForTesting] — so
  /// `attestation_before_activation_ordering_test.dart` can assert on the
  /// ordering directly rather than only inferring it from a full,
  /// unmockable network round trip.
  @visibleForTesting
  static Future<void> attestBeforeActivate() async {
    await AttestationOrchestrator().run();
  }

  /// Bring the license online.
  ///
  /// Order of operations:
  /// 1. If a seat already exists, heartbeat to pick up entitlement, config, and
  ///    kill-switch changes.
  /// 2. Otherwise attest (see [attestBeforeActivate]), then run the full
  ///    challenge–response activation.
  /// 3. If the network is unreachable, fall back to the cached token, which
  ///    remains honoured until its grace window closes.
  static Future<LicenseStatus> initialize() async {
    final activationToken = await _read(_activationKey);

    ActivationResult result;
    if (activationToken != null && activationToken.isNotEmpty) {
      result = await ActivationManager.heartbeat(activationToken);
      // A rotated key or wiped server row invalidates the seat: re-activate.
      if (result.status == 'BAD_ACTIVATION') {
        await attestBeforeActivate();
        result = await ActivationManager.activate();
      }
    } else {
      await attestBeforeActivate();
      result = await ActivationManager.activate();
    }
    // Server-authoritative rejection codes, before this SDK-local status is
    // ever collapsed into the coarser LicenseState below — the raw code is
    // the actual existing security output; see
    // docs/SECURITY_EVENT_PIPELINE.md §"Server-authoritative self-integrity".
    unawaited(SecurityEventCenter.recordActivationOutcome(
      result.status, isInitialActivation: true,
    ));

    // Server spoke and said no — trust it over any cached token.
    if (result.status == 'REVOKED' || result.status == 'DEVICE_REVOKED') {
      await _purge();
      return _publish(_fatal(LicenseState.revoked,
          result.message.isEmpty ? 'License revoked' : result.message));
    }
    if (result.status == 'SUSPENDED' || result.status == 'EXPIRED') {
      return _publish(_fatal(_stateForCode(result.status), result.message));
    }
    if (result.status == 'SDK_UPGRADE_REQUIRED') {
      return _publish(_fatal(LicenseState.upgradeRequired, result.message));
    }
    if (result.status == 'PENDING') {
      final token = result.payload['activation_token'] as String?;
      if (token != null) await _write(_activationKey, token);
      return _publish(LicenseStatus(
        state: LicenseState.pending,
        message: result.message.isEmpty
            ? 'Awaiting administrator approval'
            : result.message,
      ));
    }

    if (result.isSuccess) {
      final token = result.payload['activation_token'] as String? ?? activationToken;
      return _publish(await _acceptBundle(result, activationToken: token));
    }

    // Offline (or a transient server error): fall back to the cached token.
    //
    // This is the path a clock rollback attacks — no server is involved, so
    // the only thing standing between an expired cached token and full
    // entitlements is the device clock. Assess it before trusting it.
    final cached = await _read(_tokenKey);
    if (cached != null) {
      final payload = verifyToken(cached);
      if (payload != null) {
        final now = DateTime.now().toUtc();
        final credibility = await _assessClock(payload, now);
        // The clone path: a token copied to another handset reaches exactly
        // here, because the attacker's device has no network dependency at
        // all once it holds the cached blob. Its own keystore cannot contain
        // the non-exportable key the token names, so the binding check is
        // the only thing that separates it from the real device.
        _bindingResult = await _evaluateBinding(payload);
        final cachedStatus = _statusFromPayload(
          payload,
          fromCache: true,
          clockCredibility: credibility,
          binding: _bindingResult,
          now: now,
        );
        // Record the observation only once the evaluation is done, so this
        // launch's own write cannot mask the rewind it is meant to catch.
        await _clockStore.recordClockObservation(now);
        if (cachedStatus.grantsFeatures) {
          final config = payload['remote_config'];
          if (config is Map) _lastRemoteConfig = Map<String, dynamic>.from(config);
          return _publish(cachedStatus.copyWith(
            message: result.networkFailure
                ? 'Offline — using cached entitlements'
                : cachedStatus.message,
          ));
        }
        return _publish(cachedStatus);
      }
    }

    return _publish(_fatal(
      _stateForCode(result.status),
      result.message.isEmpty ? 'Unable to validate license' : result.message,
    ));
  }

  /// Re-check the license mid-session (e.g. on app resume). Honours the kill
  /// switch: a revoked license immediately drops all entitlements.
  static Future<LicenseStatus> refresh() async {
    if (status.value.state == LicenseState.uninitialized) return initialize();
    final activationToken = await _read(_activationKey);
    if (activationToken == null) return initialize();

    final result = await ActivationManager.heartbeat(activationToken);
    unawaited(SecurityEventCenter.recordActivationOutcome(result.status));

    if (result.status == 'REVOKED' || result.status == 'DEVICE_REVOKED') {
      await _purge();
      return _publish(_fatal(LicenseState.revoked,
          result.message.isEmpty ? 'License revoked' : result.message));
    }
    if (result.status == 'PENDING') {
      return _publish(LicenseStatus(
        state: LicenseState.pending,
        message: result.message.isEmpty
            ? 'Awaiting administrator approval'
            : result.message,
      ));
    }
    if (result.isSuccess) {
      lastRefreshWasNetworkFailure = false;
      return _publish(await _acceptBundle(result, activationToken: activationToken));
    }
    if (result.networkFailure) {
      lastRefreshWasNetworkFailure = true;
      return status.value; // keep current grant
    }
    lastRefreshWasNetworkFailure = false;
    return _publish(_fatal(_stateForCode(result.status), result.message));
  }

  /// Continuous Security Telemetry milestone: whether the most recent
  /// [refresh] failed to reach the backend at all (as opposed to reaching
  /// it and getting a real, non-network answer). `RaspSdk._scheduleHeartbeat`
  /// reads this once per tick to track a heartbeat-failure streak and emit
  /// [SecurityEventType.heartbeatFailed]/[heartbeatRecovered] — see that
  /// method's doc. A plain static flag, not a stream: exactly one reader,
  /// checked exactly once per tick, immediately after the call that set it.
  static bool lastRefreshWasNetworkFailure = false;

  static LicenseStatus _publish(LicenseStatus next) {
    _status.value = next;
    return next;
  }

  /// Drop all cached licensing material. Used by tests and factory reset.
  static Future<void> reset() async {
    await _purge();
    _lastRemoteConfig = const {};
    _status.value = const LicenseStatus.uninitialized();
  }
}
