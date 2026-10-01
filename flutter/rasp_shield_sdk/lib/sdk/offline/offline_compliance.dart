import '../core/core.dart';
import 'trusted_clock.dart';

/// Where the offline-compliance threshold came from, and whether it was
/// authenticated.
///
/// Reuses [ConfigVerificationResult]'s verdict indirectly: the caller maps
/// its existing `SignedConfigVerification` onto this, exactly as
/// `certificateTrustSourceStateFor` already does for the certificate trust
/// store. No second verification model is introduced — see
/// `docs/OFFLINE_COMPLIANCE_MODEL.md`.
enum OfflineThresholdSource {
  /// Delivered inside a configuration that verified as
  /// `ConfigVerificationResult.valid`.
  signed,

  /// The compiled-in default. Used whenever the delivered value could not be
  /// authenticated, and whenever none was delivered at all.
  ///
  /// Deliberately the *same* state for both: an unsigned value and an absent
  /// value are equally untrustworthy, and both must resolve to the safe
  /// default rather than to an attacker-supplied number.
  safeDefault,
}

/// Offline-compliance verdict.
///
/// Six states, never a boolean. The three that matter most are the three the
/// legacy boolean could not tell apart: *connected*, *offline but still
/// inside the allowed window*, and *offline past the allowed window*.
enum OfflineComplianceState {
  /// Authenticated backend contact is recent enough that no offline
  /// allowance has been consumed.
  valid,

  /// No recent contact, but still inside `offline_max_minutes`. **Not a
  /// finding.** This is the normal state for a user on a plane, in a lift,
  /// or on a flaky connection, and it must never produce a threat.
  withinGrace,

  /// The configured offline window has been exceeded. The only state that
  /// becomes a `DetectionResult.detected`.
  expired,

  /// The answer could not be established — no trusted timestamp, or the
  /// device clock moved in a way that makes elapsed time unmeasurable.
  /// **Never resolves to [valid].**
  unknown,

  /// The capability is not in play: the licence does not grant
  /// `offline_compliance`. Not a failure, and not enforcement.
  unavailable,

  /// Reading the stored state failed. **Never resolves to [valid].**
  error,
}

/// The result of one offline-compliance evaluation.
class OfflineComplianceResult {
  final OfflineComplianceState state;

  /// Time since the last *authenticated* backend contact, when measurable.
  /// `null` for [OfflineComplianceState.unknown] / `unavailable` / `error`.
  final Duration? elapsed;

  /// The threshold actually applied.
  final Duration threshold;

  /// Whether [threshold] was authenticated or fell back to the safe default.
  final OfflineThresholdSource thresholdSource;

  /// Why the state is inconclusive, when it is.
  final String? reason;

  const OfflineComplianceResult({
    required this.state,
    required this.threshold,
    required this.thresholdSource,
    this.elapsed,
    this.reason,
  });

  /// `true` only for [OfflineComplianceState.expired] — the single state
  /// that is a security finding.
  bool get isNonCompliant => state == OfflineComplianceState.expired;

  /// `true` when the evaluation reached a real answer.
  bool get isConclusive =>
      state == OfflineComplianceState.valid ||
      state == OfflineComplianceState.withinGrace ||
      state == OfflineComplianceState.expired;

  /// Projection onto the SDK's existing five-state detector vocabulary.
  ///
  /// `withinGrace` maps to [DetectionStatus.secure] deliberately: a user
  /// inside their allowed offline window **is** compliant, and reporting it
  /// as anything else would make every subway ride a security event.
  DetectionStatus get detectionStatus => switch (state) {
        OfflineComplianceState.expired => DetectionStatus.detected,
        OfflineComplianceState.valid => DetectionStatus.secure,
        OfflineComplianceState.withinGrace => DetectionStatus.secure,
        OfflineComplianceState.unknown => DetectionStatus.unknown,
        OfflineComplianceState.unavailable => DetectionStatus.unavailable,
        OfflineComplianceState.error => DetectionStatus.error,
      };
}

/// Evaluates offline compliance from an authenticated anchor.
///
/// ## Trusted time
///
/// [anchorIssuedAt] is the `issued_at` claim of a **verified** entitlement
/// token — server-issued, HMAC-signed with the licence key, and bound to
/// this `device_id` + `bundle_id`. A token is only ever issued by a
/// successful `/activate` or `/heartbeat`, so its existence is itself the
/// proof of authenticated backend contact. See
/// `docs/OFFLINE_COMPLIANCE_AUDIT.md` §3.1.
///
/// Elapsed time is still measured against the device clock, which the user
/// controls. The two dangerous directions are handled asymmetrically, and
/// deliberately — see `docs/OFFLINE_CLOCK_TAMPERING.md`:
///
///  * **Clock moved forward** → elapsed grows → expires *sooner*. Fails
///    closed; allowed to stand.
///  * **Clock moved backward** → elapsed shrinks or goes negative → would
///    *extend* compliance. This is the fail-open direction and is refused:
///    a negative elapsed, or a clock behind the highest value this device
///    has already observed, yields [OfflineComplianceState.unknown].
class OfflineComplianceEvaluator {
  /// The compiled-in safe default, matching the pre-existing
  /// `RemoteConfigManager.offlineMaxMinutes` fallback so behaviour is
  /// unchanged for anyone already relying on it.
  static const Duration safeDefaultThreshold = Duration(minutes: 30);

  /// Beyond this, an elapsed time is treated as unmeasurable rather than
  /// merely large. A device reporting years offline has a broken or
  /// manipulated clock; the honest answer is [OfflineComplianceState.unknown]
  /// rather than a confident verdict derived from a nonsense number.
  ///
  /// Note this is still fail-safe: `unknown` never resolves to `valid`, so
  /// the outcome is "we cannot vouch for this device", not "this device is
  /// fine".
  static const Duration maxPlausibleElapsed = Duration(days: 365);

  const OfflineComplianceEvaluator();

  /// Resolve the threshold, honouring Phase 5: a delivered value is used
  /// **only** when it arrived in an authenticated configuration.
  ///
  /// [deliveredMinutes] is whatever the configuration carried;
  /// [configurationAuthenticated] is `verification.isAuthenticated`, i.e.
  /// `result == ConfigVerificationResult.valid`. Anything else — unsigned,
  /// bad signature, unknown key, expired, replayed, downgraded — falls back
  /// to [safeDefaultThreshold].
  static (Duration, OfflineThresholdSource) resolveThreshold({
    required int? deliveredMinutes,
    required bool configurationAuthenticated,
  }) {
    if (!configurationAuthenticated) {
      return (safeDefaultThreshold, OfflineThresholdSource.safeDefault);
    }
    if (deliveredMinutes == null || deliveredMinutes <= 0) {
      // Absent or nonsensical: same treatment as unsigned. A zero or
      // negative window would mean "never compliant", which is far more
      // likely a malformed payload than a real policy.
      return (safeDefaultThreshold, OfflineThresholdSource.safeDefault);
    }
    return (
      Duration(minutes: deliveredMinutes),
      OfflineThresholdSource.signed,
    );
  }

  /// Evaluate compliance.
  ///
  /// [entitled] — `LicenseManager.allows(Entitlement.offlineCompliance)`.
  /// [anchorIssuedAt] — `issued_at` from a **verified** entitlement token,
  ///   or `null` when no verified token is available.
  /// [now] — the device clock, injected so tests need no real time.
  /// [clockHighWaterMark] — the highest wall-clock value this device has
  ///   previously observed, used to catch a clock moved backwards across
  ///   launches. `null` when none has been recorded yet.
  /// [storageFailed] — `true` when the persisted state could not be read.
  OfflineComplianceResult evaluate({
    required bool entitled,
    required DateTime? anchorIssuedAt,
    required DateTime now,
    required Duration threshold,
    required OfflineThresholdSource thresholdSource,
    DateTime? clockHighWaterMark,
    bool storageFailed = false,
  }) {
    OfflineComplianceResult build(
      OfflineComplianceState state, {
      Duration? elapsed,
      String? reason,
    }) =>
        OfflineComplianceResult(
          state: state,
          elapsed: elapsed,
          threshold: threshold,
          thresholdSource: thresholdSource,
          reason: reason,
        );

    // Phase 6: no entitlement, no enforcement. Checked first so an
    // unentitled customer never even reaches the clock logic.
    if (!entitled) {
      return build(
        OfflineComplianceState.unavailable,
        reason: 'Offline compliance is not licensed for this customer',
      );
    }

    if (storageFailed) {
      return build(
        OfflineComplianceState.error,
        reason: 'Offline-compliance state could not be read',
      );
    }

    if (anchorIssuedAt == null) {
      // No verified token. This is *not* "compliant by default": the device
      // has no proof of any authenticated backend contact at all.
      return build(
        OfflineComplianceState.unknown,
        reason: 'No verified entitlement token — last authenticated backend '
            'contact is unknown',
      );
    }

    final anchor = anchorIssuedAt.toUtc();
    final current = now.toUtc();

    // Rollback detection is NOT duplicated here. `TrustedClock` is the one
    // place the SDK decides whether the device clock is usable, shared with
    // `LicenseManager` — two subsystems asking the same question must not be
    // able to reach different answers. See
    // `docs/LICENSE_TRUSTED_TIME_MODEL.md`.
    final credibility = const TrustedClock().assess(
      anchorIssuedAt: anchor,
      now: current,
      clockHighWaterMark: clockHighWaterMark,
    );
    if (!credibility.isCredible) {
      return build(
        OfflineComplianceState.unknown,
        reason: credibility.reason,
      );
    }

    final elapsed = current.difference(anchor);

    if (elapsed > threshold) {
      return build(OfflineComplianceState.expired, elapsed: elapsed);
    }

    // Inside the window. `valid` vs `withinGrace` is a reporting
    // distinction, not a policy one — neither is a finding. The split point
    // is half the window, so an operator can see a fleet drifting offline
    // before it starts expiring.
    final grace = Duration(microseconds: threshold.inMicroseconds ~/ 2);
    return build(
      elapsed <= grace
          ? OfflineComplianceState.valid
          : OfflineComplianceState.withinGrace,
      elapsed: elapsed,
    );
  }
}
