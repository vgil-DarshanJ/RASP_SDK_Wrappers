import 'dart:convert';
import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'tls_pinset.dart';

/// The result of checking one presented certificate against the active
/// pinset.
enum TlsPinCheckOutcome {
  /// Host is pinned and the certificate matched an accepted pin.
  match,

  /// Host is pinned and the certificate did not match — under
  /// [TlsPinningMode.enforce] this aborts the connection.
  mismatch,

  /// The presented pin is explicitly revoked. Always refused, even in
  /// [TlsPinningMode.monitor], because a revoked pin is a *known-bad*
  /// certificate rather than an unknown one.
  revoked,

  /// No pinset covers this host — nothing to check. Never conflated with
  /// [match].
  notPinned,
}

/// Whether a staged pinset was safe to activate.
enum TlsStagingOutcome {
  /// Live handshake produced a certificate the staged pinset accepts.
  validated,

  /// Live handshake produced a certificate the staged pinset would reject.
  /// The pinset is **not** activated — this is the check that stops a
  /// typo'd pin from severing every device on the next config push.
  wouldBreak,

  /// The host could not be reached at all, so nothing was proven either
  /// way. Not treated as validation.
  unreachable,

  /// Nothing to validate (no pins configured for the host).
  notConfigured,
}

/// Dynamic TLS certificate pinning: stage → validate → activate → enforce,
/// with a recovery path.
///
/// ## Why staging exists
///
/// A pinset arrives inside the signed remote-config bundle
/// (`config['tls_pinning']`), so it already inherits Ed25519 authenticity,
/// version monotonicity, expiry and platform binding from
/// `SignedConfigVerifier` — this class adds no second crypto system and no
/// second delivery channel.
///
/// What signing cannot tell you is whether the pins are *correct*. A
/// perfectly authentic, perfectly signed bundle carrying a mistyped pin
/// would, if enforced immediately, sever every device from the very backend
/// that would deliver the correction. So a newly-arrived pinset is
/// **staged**, validated against a real handshake, and only then activated.
/// A staged pinset that would break the connection is discarded and
/// reported, leaving the previously-active pinset untouched.
///
/// ## Why enforcement can demote itself
///
/// Validation happens at one moment against one endpoint. A pin can still
/// become wrong afterwards (an emergency server-side certificate swap the
/// operator has not yet published). [recordEnforcementFailure] counts
/// consecutive enforcement-caused failures against the backend host and, at
/// [failureBudget], demotes that host to [TlsPinningMode.monitor] and
/// records why. The device keeps working, the operator sees the demotion in
/// telemetry, and the next signed config can correct the pins.
///
/// **This is a deliberate availability/security trade-off and it is stated
/// plainly rather than hidden**: a device that has been unable to reach its
/// backend for [failureBudget] consecutive attempts specifically because of
/// pin mismatches is, from the SDK's own point of view, indistinguishable
/// from a device whose operator made a mistake. Refusing to ever demote
/// would make a mistaken rotation permanently unrecoverable without a
/// store update, which for a banking app is the worse failure. Hosts other
/// than the SDK's own backend are never auto-demoted — see
/// [recordEnforcementFailure].
class TlsPinningController {
  TlsPinningController._();

  static final TlsPinningController instance = TlsPinningController._();

  static const _activeKey = 'rasp_sdk_tls_pinset_active';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  /// In-memory override so a test can drive this without a platform
  /// channel — the same `testValues` seam every other secure-storage
  /// touchpoint in this SDK uses (see `SecureVaultStore.testValues`).
  @visibleForTesting
  static Map<String, String>? testValues;

  /// Consecutive enforcement-caused failures tolerated per host before that
  /// host is demoted to monitor. See the class doc.
  static const int failureBudget = 3;

  TlsPinset _active = TlsPinset.empty;
  TlsPinset? _staged;
  final Map<String, int> _consecutiveFailures = {};
  final List<TlsPinningEvent> _pendingEvents = [];

  /// The pinset currently being enforced.
  TlsPinset get active => _active;

  /// The pinset awaiting validation, if any.
  TlsPinset? get staged => _staged;

  /// The SDK's own backend host, set by `RaspShield` wiring. Only this host
  /// participates in failure-driven demotion.
  String? backendHost;

  /// Drains security-relevant pinning events for the caller to report
  /// through the existing Security Event Center. Clearing on read keeps a
  /// report describing one interval rather than all of history — the same
  /// contract `SecurityEventQueue.drainOverflowNotice` already uses.
  List<TlsPinningEvent> drainEvents() {
    final out = List<TlsPinningEvent>.unmodifiable(_pendingEvents);
    _pendingEvents.clear();
    return out;
  }

  void _record(TlsPinningEvent event) {
    _pendingEvents.add(event);
    // Never logs a pin value's provenance beyond the host and outcome —
    // a pin is not secret, but a log line naming which pin matched on which
    // device is needless fingerprinting surface.
    debugPrint('[RASP-TRACE] TLS-PIN ${event.kind.name} host=${event.host} '
        'mode=${event.mode?.wireName ?? "-"}');
  }

  /// Loads the previously-activated pinset from secure storage.
  ///
  /// Called once during SDK initialization, before any pinned request. A
  /// device that activated a pinset yesterday keeps enforcing it today
  /// without waiting for a fresh config — otherwise every cold start would
  /// have an unpinned window, which is exactly when an attacker on the
  /// network would act.
  Future<void> restore() async {
    final raw = await _read(_activeKey);
    if (raw == null || raw.isEmpty) return;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return;
      final restored =
          TlsPinset.fromMap(decoded.map((k, v) => MapEntry(k.toString(), v)));
      if (restored != null) _active = restored;
    } catch (e) {
      debugPrint('[RASP-TRACE] TLS-PIN restore failed: $e');
    }
  }

  /// Accepts a pinset from a **already-verified** signed config bundle.
  ///
  /// Callers must only pass a bundle that `SignedConfigVerifier` accepted;
  /// this class does not re-verify signatures and must never be handed raw
  /// network input.
  ///
  /// A pinset older than the active one is refused (anti-rollback) — the
  /// signed layer already gates the bundle as a whole, this is defence in
  /// depth for the pinset specifically.
  Future<TlsStagingOutcome> stageFromConfig(
    Map<String, dynamic> verifiedConfig, {
    required int configVersion,
    bool validate = true,
  }) async {
    final incoming = TlsPinset.fromConfig(verifiedConfig, configVersion: configVersion);
    if (!incoming.isConfigured) {
      // An explicitly empty pinset is a legitimate instruction to stop
      // pinning — but only from a NEWER config, never a replayed older one.
      if (configVersion > _active.configVersion && _active.isConfigured) {
        _active = incoming;
        await _persistActive();
        _record(TlsPinningEvent(
          kind: TlsPinningEventKind.pinsetCleared, host: '*',
        ));
      }
      return TlsStagingOutcome.notConfigured;
    }
    if (configVersion < _active.configVersion) {
      _record(TlsPinningEvent(
        kind: TlsPinningEventKind.rollbackRefused, host: '*',
      ));
      return TlsStagingOutcome.notConfigured;
    }

    _staged = incoming;
    _record(TlsPinningEvent(kind: TlsPinningEventKind.staged, host: '*'));
    if (!validate) {
      await _activate(incoming);
      return TlsStagingOutcome.validated;
    }

    final host = backendHost;
    if (host == null) {
      // Nothing to validate against; activate in whatever mode the pinset
      // itself declares. A pinset that declares `enforce` for a host this
      // SDK never talks to cannot break this SDK.
      await _activate(incoming);
      return TlsStagingOutcome.validated;
    }

    final outcome = await validateAgainstLiveHandshake(incoming, host);
    switch (outcome) {
      case TlsStagingOutcome.validated:
        await _activate(incoming);
        _record(TlsPinningEvent(
          kind: TlsPinningEventKind.activated, host: host,
          mode: incoming.forHost(host)?.mode,
        ));
        break;
      case TlsStagingOutcome.wouldBreak:
        // Only THIS host's update is proven unsafe. An unrelated customer
        // host arriving in the same bundle must not be held back by it —
        // keep whatever was previously active for the backend host,
        // adopt everything else new. See the class doc and the live bug
        // this fixes: an earlier version discarded the *entire* incoming
        // pinset here, silently blocking a legitimate, unrelated pin
        // update to a customer host just because the backend's own pin
        // happened to be wrong at the same moment.
        await _activate(replaceHost(incoming, host, _active.forHost(host)));
        _record(TlsPinningEvent(
          kind: TlsPinningEventKind.stagingRejected, host: host,
        ));
        break;
      case TlsStagingOutcome.unreachable:
      case TlsStagingOutcome.notConfigured:
        // Cannot prove THIS host's pins are safe. Demote only this host to
        // monitor — never every enforce-mode host in the bundle. A live
        // bug (found during device acceptance testing) demoted an
        // unrelated, perfectly reachable customer host to monitor purely
        // because the SDK's own backend host could not be reached at that
        // moment; a customer's payment host must never lose enforcement
        // because of a fact about a completely different host.
        await _activate(downgradeHostToMonitor(incoming, host));
        _record(TlsPinningEvent(
          kind: TlsPinningEventKind.activatedUnvalidated, host: host,
          mode: TlsPinningMode.monitor,
        ));
        break;
    }
    return outcome;
  }

  /// [pinset] with only [host]'s entry demoted to monitor (if it was
  /// `enforce`) — every other host is carried through untouched. See the
  /// call site's doc for why this must be scoped to one host. Pure
  /// (no I/O) and `@visibleForTesting` so the scoping itself — the exact
  /// property a real bug violated — can be tested directly rather than only
  /// through the full async staging path.
  @visibleForTesting
  TlsPinset downgradeHostToMonitor(TlsPinset pinset, String host) {
    final key = host.toLowerCase();
    final entry = pinset.hosts[key];
    if (entry == null || entry.mode != TlsPinningMode.enforce) return pinset;
    return TlsPinset(
      configVersion: pinset.configVersion,
      hosts: {...pinset.hosts, key: entry.withMode(TlsPinningMode.monitor)},
    );
  }

  /// [pinset] with [host]'s entry replaced by [replacement] (or removed, if
  /// `null`) — every other host is carried through untouched. Used to
  /// discard an unsafe update to one host without discarding legitimate
  /// updates to every other host arriving in the same bundle. Pure and
  /// `@visibleForTesting` for the same reason as [downgradeHostToMonitor].
  @visibleForTesting
  TlsPinset replaceHost(TlsPinset pinset, String host, TlsHostPinset? replacement) {
    final key = host.toLowerCase();
    final hosts = {...pinset.hosts};
    if (replacement != null) {
      hosts[key] = replacement;
    } else {
      hosts.remove(key);
    }
    return TlsPinset(configVersion: pinset.configVersion, hosts: hosts);
  }

  Future<void> _activate(TlsPinset pinset) async {
    _active = pinset;
    _staged = null;
    _consecutiveFailures.clear();
    await _persistActive();
  }

  /// Opens a real TLS connection to [host] and checks the certificate it
  /// presents against [pinset].
  ///
  /// Uses `SecurityContext(withTrustedRoots: false)` so the callback fires
  /// for *every* certificate, not only ones the platform already distrusts
  /// — a certificate can be validly issued by a trusted CA and still not be
  /// the pinned one, which is precisely the coerced-CA/enterprise-proxy
  /// case pinning exists for. Same reasoning as
  /// `SslPinningService.checkCertificatePin`, which this does not replace.
  Future<TlsStagingOutcome> validateAgainstLiveHandshake(
    TlsPinset pinset,
    String host, {
    int port = 443,
    Duration timeout = const Duration(seconds: 8),
  }) async {
    final hostPinset = pinset.forHost(host);
    if (hostPinset == null || !hostPinset.isConfigured) {
      return TlsStagingOutcome.notConfigured;
    }

    final observed = await observePin(host, port: port, timeout: timeout);
    if (observed == null) return TlsStagingOutcome.unreachable;
    return hostPinset.accepts(observed)
        ? TlsStagingOutcome.validated
        : TlsStagingOutcome.wouldBreak;
  }

  /// Returns the SHA-256 (hex) of the certificate [host] presents, or `null`
  /// when it could not be observed at all.
  @visibleForTesting
  Future<String?> observePin(
    String host, {
    int port = 443,
    Duration timeout = const Duration(seconds: 8),
  }) async {
    final client = HttpClient(context: SecurityContext(withTrustedRoots: false));
    X509Certificate? presented;
    client.badCertificateCallback = (cert, _, _) {
      presented = cert;
      return false; // never trust here; the pin comparison decides
    };
    try {
      final request = await client
          .getUrl(Uri(scheme: 'https', host: host, port: port))
          .timeout(timeout);
      await request.close().timeout(timeout);
    } catch (_) {
      // Handshake refused (expected, since we return false above), offline,
      // DNS failure or timeout — all indistinguishable here, and none of
      // them is a mismatch.
    } finally {
      client.close(force: true);
    }
    final cert = presented;
    if (cert == null) return null;
    return sha256.convert(cert.der).toString();
  }

  /// The enforcement decision for one presented certificate.
  ///
  /// Pure given the active pinset — no I/O — so it can be called from
  /// inside a `badCertificateCallback` without blocking the handshake.
  TlsPinCheckOutcome checkPin(String host, String presentedSha256Hex) {
    final hostPinset = _active.forHost(host);
    if (hostPinset == null || !hostPinset.isConfigured) {
      return TlsPinCheckOutcome.notPinned;
    }
    final role = hostPinset.roleOf(presentedSha256Hex);
    if (role == TlsPinRole.revoked) return TlsPinCheckOutcome.revoked;
    if (role == TlsPinRole.current || role == TlsPinRole.next) {
      return TlsPinCheckOutcome.match;
    }
    return TlsPinCheckOutcome.mismatch;
  }

  /// Whether a connection carrying [presentedSha256Hex] to [host] may
  /// proceed, applying the host's mode.
  ///
  /// A revoked pin is refused in every mode including [TlsPinningMode.monitor]
  /// — monitor exists to avoid breaking devices on an *unknown* certificate
  /// during rollout, not to keep talking to one an operator has explicitly
  /// withdrawn.
  bool allowConnection(String host, String presentedSha256Hex) {
    final outcome = checkPin(host, presentedSha256Hex);
    final mode = _active.forHost(host)?.mode ?? TlsPinningMode.off;

    switch (outcome) {
      case TlsPinCheckOutcome.match:
        _consecutiveFailures.remove(host.toLowerCase());
        return true;
      case TlsPinCheckOutcome.notPinned:
        return true;
      case TlsPinCheckOutcome.revoked:
        _record(TlsPinningEvent(
          kind: TlsPinningEventKind.revokedPinPresented, host: host, mode: mode,
        ));
        return false;
      case TlsPinCheckOutcome.mismatch:
        _record(TlsPinningEvent(
          kind: TlsPinningEventKind.mismatch, host: host, mode: mode,
        ));
        if (mode == TlsPinningMode.enforce) {
          recordEnforcementFailure(host);
          return false;
        }
        return true; // off / monitor: reported, not blocked
    }
  }

  /// Counts one enforcement-caused failure for [host] and demotes that host
  /// to monitor once [failureBudget] consecutive failures have accumulated.
  ///
  /// Only the SDK's own [backendHost] is auto-demoted. A customer's pinned
  /// *payment* host failing repeatedly is a signal to surface, not something
  /// this SDK may quietly relax on the customer's behalf — demoting it could
  /// be exactly what an attacker wants. The backend host is different: it is
  /// the channel through which a corrected pinset arrives, so keeping it
  /// permanently severed removes the only route to recovery.
  void recordEnforcementFailure(String host) {
    final key = host.toLowerCase();
    final next = (_consecutiveFailures[key] ?? 0) + 1;
    _consecutiveFailures[key] = next;
    if (next < failureBudget) return;
    if (backendHost == null || key != backendHost!.toLowerCase()) return;

    final hostPinset = _active.forHost(key);
    if (hostPinset == null || hostPinset.mode != TlsPinningMode.enforce) return;

    _active = TlsPinset(
      configVersion: _active.configVersion,
      hosts: {
        ..._active.hosts,
        key: hostPinset.withMode(TlsPinningMode.monitor),
      },
    );
    _consecutiveFailures[key] = 0;
    _record(TlsPinningEvent(
      kind: TlsPinningEventKind.demotedForRecovery, host: key,
      mode: TlsPinningMode.monitor,
    ));
    // Fire-and-forget: a failed persist must not block the recovery itself.
    _persistActive();
  }

  Future<void> _persistActive() async {
    final encoded = jsonEncode(_active.toMap());
    final values = testValues;
    if (values != null) {
      values[_activeKey] = encoded;
      return;
    }
    try {
      await _storage.write(key: _activeKey, value: encoded);
    } catch (e) {
      debugPrint('[RASP-TRACE] TLS-PIN persist failed: $e');
    }
  }

  Future<String?> _read(String key) async {
    final values = testValues;
    if (values != null) return values[key];
    try {
      return await _storage.read(key: key);
    } catch (e) {
      debugPrint('[RASP-TRACE] TLS-PIN read failed: $e');
      return null;
    }
  }

  @visibleForTesting
  void resetForTests() {
    _active = TlsPinset.empty;
    _staged = null;
    _consecutiveFailures.clear();
    _pendingEvents.clear();
    backendHost = null;
  }
}

/// What happened, for the Security Event Center to report.
enum TlsPinningEventKind {
  staged,
  activated,
  activatedUnvalidated,
  stagingRejected,
  rollbackRefused,
  pinsetCleared,
  mismatch,
  revokedPinPresented,
  demotedForRecovery,
}

class TlsPinningEvent {
  final TlsPinningEventKind kind;
  final String host;
  final TlsPinningMode? mode;

  const TlsPinningEvent({required this.kind, required this.host, this.mode});

  Map<String, Object?> evidence() => {
        'kind': kind.name,
        'host': host,
        if (mode != null) 'mode': mode!.wireName,
      };
}
