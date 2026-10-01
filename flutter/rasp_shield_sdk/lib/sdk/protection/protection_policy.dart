import '../core/core.dart';
import 'protection_action.dart';

/// How the SDK behaves when it cannot reach the backend.
enum OfflinePolicy {
  /// Keep enforcing on locally available evidence. The default: a RASP SDK
  /// that stops protecting the moment the network drops is trivially
  /// defeated by putting the device in airplane mode.
  enforce,

  /// Keep evaluating, but never escalate past [ProtectionAction.monitor]
  /// while offline. For hosts that treat an unverifiable decision as too
  /// risky to act on.
  monitorOnly,

  /// Treat "cannot verify" as itself a risk and apply
  /// [ProtectionPolicy.offlineFallbackAction].
  fail,
}

/// The security rules the SDK enforces, as versioned data.
///
/// ## Backend-authoritative, cached for offline
///
/// A policy is issued by the backend per tenant and per application, and
/// reaches the device through the **existing** activation/heartbeat
/// entitlement bundle — there is no new endpoint and no second delivery
/// channel. The SDK caches the last good policy so it can keep enforcing
/// while offline, and only replaces it with a strictly newer [version].
///
/// ## Why this is not entitlement JSON
///
/// Entitlements answer *what did this customer buy* — they are commercial
/// facts, they change when a contract changes, and they gate whether a
/// detector may run at all. A policy answers *what should happen when a
/// detector fires*, which is a security decision a SOC may want to change
/// this afternoon without touching anyone's contract. Collapsing the two
/// means every threshold tweak looks like a licence change in the audit log.
///
/// [detectorOverrides] can only ever *narrow* what entitlements permit — a
/// policy cannot switch on a detector the customer has not licensed. That is
/// enforced by `ScanRunner`'s gate, which applies the entitlement check
/// first.
class ProtectionPolicy {
  /// Monotonic version. A policy is accepted only when strictly newer than
  /// the cached one, so a replayed older policy cannot downgrade protection.
  final int version;

  /// When the backend issued it.
  final DateTime? issuedAt;

  /// When it stops being trusted. A policy past its expiry falls back to
  /// [ProtectionPolicy.strict] rather than to "no protection" — an expired
  /// security policy must fail closed.
  final DateTime? expiresAt;

  /// Findings below this severity never contribute to a decision. They are
  /// still carried on the [ProtectionResult] — suppressed from the decision,
  /// not hidden from the record.
  final DetectionSeverity minimumSeverity;

  /// Risk score (0–100) an evaluation must reach before anything beyond
  /// [ProtectionAction.allow] is recommended.
  final int minimumRiskScore;

  /// Actions this deployment permits. The engine never recommends one
  /// outside this set — it picks the most severe *enabled* action instead.
  final Set<ProtectionAction> enabledActions;

  /// Per-severity escalation. Missing entries fall back to the built-in
  /// ladder in `ProtectionEngine`.
  final Map<DetectionSeverity, ProtectionAction> severityActions;

  /// Authoritative Protection Engine V1 — per-detector floor, keyed by
  /// `detectorId` (`root_jailbreak`, `frida`, `re_tools`, `tamper`, …). The
  /// highest-resolution override this policy carries: a detector named here
  /// floors the decision at that action whenever it fires and clears the
  /// severity bar, on top of (never instead of) [severityActions] and the
  /// score ladder — `ProtectionEngine.recommendedAction` takes the most
  /// severe of all three, the same "most restrictive wins" composition
  /// [severityActions] already uses. This is what lets a customer policy
  /// express "root always locks the app" or "root only blocks sensitive
  /// operations" (see `docs/ENFORCEMENT_POLICY.md`'s worked examples)
  /// without a second policy engine — it is one more optional map on this
  /// same class, consulted the same way the existing two ladders are.
  ///
  /// Empty by default: a detector absent from this map is governed purely
  /// by severity/score, exactly as before this field existed.
  final Map<String, ProtectionAction> detectorActions;

  /// Detector ids explicitly switched off by policy. Can only narrow what
  /// entitlements already allow.
  final Set<String> disabledDetectors;

  /// What to do when the backend is unreachable.
  final OfflinePolicy offlineBehavior;

  /// Applied when [offlineBehavior] is [OfflinePolicy.fail].
  final ProtectionAction offlineFallbackAction;

  const ProtectionPolicy({
    this.version = 0,
    this.issuedAt,
    this.expiresAt,
    this.minimumSeverity = DetectionSeverity.low,
    this.minimumRiskScore = 0,
    this.enabledActions = const {
      ProtectionAction.allow,
      ProtectionAction.monitor,
      ProtectionAction.warn,
    },
    this.severityActions = const {},
    this.detectorActions = const {},
    this.disabledDetectors = const {},
    this.offlineBehavior = OfflinePolicy.enforce,
    this.offlineFallbackAction = ProtectionAction.warn,
  });

  /// The policy in force before any backend policy has been received.
  ///
  /// Deliberately observe-only: the SDK reports everything and interrupts
  /// nobody until an operator has actually chosen a stance. Shipping a
  /// default that locks apps would make the first install of any integration
  /// a support incident.
  static const ProtectionPolicy monitorOnly = ProtectionPolicy();

  /// Every action available, every finding considered.
  static const ProtectionPolicy strict = ProtectionPolicy(
    enabledActions: {
      ProtectionAction.allow,
      ProtectionAction.monitor,
      ProtectionAction.warn,
      ProtectionAction.stepUp,
      ProtectionAction.block,
      ProtectionAction.lockSession,
      ProtectionAction.lockApp,
    },
  );

  /// `true` when [expiresAt] has passed.
  bool isExpired({DateTime? now}) {
    final expiry = expiresAt;
    if (expiry == null) return false;
    return (now ?? DateTime.now().toUtc()).isAfter(expiry);
  }

  /// The policy that should actually be applied right now.
  ///
  /// Fails **closed**: an expired policy escalates to [strict] rather than
  /// silently continuing to enforce stale, possibly-too-permissive rules.
  ProtectionPolicy effective({DateTime? now}) =>
      isExpired(now: now) ? strict : this;

  /// `true` when [action] is permitted here.
  bool permits(ProtectionAction action) => enabledActions.contains(action);

  /// `true` when policy has switched this detector off.
  bool isDetectorDisabled(String detectorId) =>
      disabledDetectors.contains(detectorId);

  /// The most severe action this policy permits, or [ProtectionAction.allow]
  /// when it somehow permits nothing.
  ProtectionAction get mostSevereEnabled {
    var best = ProtectionAction.allow;
    for (final action in enabledActions) {
      if (action.index > best.index) best = action;
    }
    return best;
  }

  /// Clamps [action] down to the most severe action this policy permits.
  ProtectionAction clamp(ProtectionAction action) {
    if (permits(action)) return action;
    var best = ProtectionAction.allow;
    for (final candidate in enabledActions) {
      if (candidate.index <= action.index && candidate.index > best.index) {
        best = candidate;
      }
    }
    return best;
  }

  ProtectionPolicy copyWith({
    int? version,
    DateTime? issuedAt,
    DateTime? expiresAt,
    DetectionSeverity? minimumSeverity,
    int? minimumRiskScore,
    Set<ProtectionAction>? enabledActions,
    Map<DetectionSeverity, ProtectionAction>? severityActions,
    Map<String, ProtectionAction>? detectorActions,
    Set<String>? disabledDetectors,
    OfflinePolicy? offlineBehavior,
    ProtectionAction? offlineFallbackAction,
  }) {
    return ProtectionPolicy(
      version: version ?? this.version,
      issuedAt: issuedAt ?? this.issuedAt,
      expiresAt: expiresAt ?? this.expiresAt,
      minimumSeverity: minimumSeverity ?? this.minimumSeverity,
      minimumRiskScore: minimumRiskScore ?? this.minimumRiskScore,
      enabledActions: enabledActions ?? this.enabledActions,
      severityActions: severityActions ?? this.severityActions,
      detectorActions: detectorActions ?? this.detectorActions,
      disabledDetectors: disabledDetectors ?? this.disabledDetectors,
      offlineBehavior: offlineBehavior ?? this.offlineBehavior,
      offlineFallbackAction:
          offlineFallbackAction ?? this.offlineFallbackAction,
    );
  }

  /// Parses a policy delivered in the heartbeat's remote-config bundle.
  ///
  /// **Never throws.** A malformed or partial policy yields a policy built
  /// from whatever parsed plus defaults for the rest, because rejecting the
  /// whole document would leave the device with no policy at all — the worst
  /// possible outcome of a backend typo. Unknown action names are skipped
  /// (see [protectionActionFromName]) so a newer backend vocabulary degrades
  /// instead of breaking an older SDK build.
  factory ProtectionPolicy.fromJson(Map<String, dynamic> json) {
    Set<ProtectionAction> parseActions(Object? raw) {
      if (raw is! List) return monitorOnly.enabledActions;
      final parsed = <ProtectionAction>{};
      for (final entry in raw) {
        final action = protectionActionFromName(entry?.toString());
        if (action != null) parsed.add(action);
      }
      // A policy that names only unrecognised actions must not silently
      // disarm the SDK — fall back rather than enabling nothing.
      return parsed.isEmpty ? monitorOnly.enabledActions : parsed;
    }

    DetectionSeverity parseSeverity(Object? raw, DetectionSeverity fallback) {
      for (final severity in DetectionSeverity.values) {
        if (severity.name == raw?.toString()) return severity;
      }
      return fallback;
    }

    DateTime? parseDate(Object? raw) {
      if (raw is! String || raw.isEmpty) return null;
      return DateTime.tryParse(raw)?.toUtc();
    }

    // `as num?` throws on a String, which would break this factory's
    // never-throws contract on exactly the input it exists to survive — a
    // backend typo like {"version": "3"}. Coerce defensively instead, and
    // accept a numeric string rather than discarding a value whose intent is
    // unambiguous.
    int parseInt(Object? raw, int fallback) {
      if (raw is num) return raw.toInt();
      if (raw is String) return int.tryParse(raw.trim()) ?? fallback;
      return fallback;
    }

    final severityActions = <DetectionSeverity, ProtectionAction>{};
    final rawSeverityActions = json['severity_actions'];
    if (rawSeverityActions is Map) {
      rawSeverityActions.forEach((key, value) {
        final action = protectionActionFromName(value?.toString());
        if (action == null) return;
        for (final severity in DetectionSeverity.values) {
          if (severity.name == key.toString()) severityActions[severity] = action;
        }
      });
    }

    OfflinePolicy offline = OfflinePolicy.enforce;
    for (final candidate in OfflinePolicy.values) {
      if (candidate.name == json['offline_behavior']?.toString()) {
        offline = candidate;
      }
    }

    final detectorActions = <String, ProtectionAction>{};
    final rawDetectorActions = json['detector_actions'];
    if (rawDetectorActions is Map) {
      rawDetectorActions.forEach((key, value) {
        final action = protectionActionFromName(value?.toString());
        if (action != null) detectorActions[key.toString()] = action;
      });
    }

    final rawDisabled = json['disabled_detectors'];

    return ProtectionPolicy(
      version: parseInt(json['version'], 0),
      issuedAt: parseDate(json['issued_at']),
      expiresAt: parseDate(json['expires_at']),
      minimumSeverity:
          parseSeverity(json['minimum_severity'], DetectionSeverity.low),
      minimumRiskScore: parseInt(json['minimum_risk_score'], 0),
      enabledActions: parseActions(json['enabled_actions']),
      severityActions: severityActions,
      detectorActions: detectorActions,
      disabledDetectors: rawDisabled is List
          ? rawDisabled.map((e) => e.toString()).toSet()
          : const {},
      offlineBehavior: offline,
      offlineFallbackAction:
          protectionActionFromName(json['offline_fallback_action']?.toString()) ??
              ProtectionAction.warn,
    );
  }

  /// Round-trips with [ProtectionPolicy.fromJson].
  Map<String, Object?> toJson() => {
        'version': version,
        'issued_at': issuedAt?.toIso8601String(),
        'expires_at': expiresAt?.toIso8601String(),
        'minimum_severity': minimumSeverity.name,
        'minimum_risk_score': minimumRiskScore,
        'enabled_actions':
            enabledActions.map((a) => a.wireName).toList(growable: false),
        'severity_actions': {
          for (final entry in severityActions.entries)
            entry.key.name: entry.value.wireName,
        },
        'detector_actions': {
          for (final entry in detectorActions.entries)
            entry.key: entry.value.wireName,
        },
        'disabled_detectors': disabledDetectors.toList(growable: false),
        'offline_behavior': offlineBehavior.name,
        'offline_fallback_action': offlineFallbackAction.wireName,
      };

  @override
  String toString() =>
      'ProtectionPolicy(v$version, minSeverity=${minimumSeverity.name}, '
      'minScore=$minimumRiskScore, actions=${enabledActions.length})';
}
