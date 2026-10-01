/// Whether the device clock can be trusted for a security decision, and why
/// not when it cannot.
enum ClockCredibility {
  /// The clock is consistent with every anchor available. Usable.
  credible,

  /// The clock reads earlier than a server-issued timestamp that is, by
  /// definition, in the past. Only manipulation produces this.
  behindAnchor,

  /// The clock reads earlier than the highest value this device has already
  /// been observed to report — a rewind performed between launches.
  rewound,

  /// The elapsed time since the anchor is too large to be real.
  implausible,

  /// No anchor is available, so nothing can be said either way.
  unknown,
}

extension ClockCredibilityX on ClockCredibility {
  /// `true` only for [ClockCredibility.credible].
  ///
  /// Every other value — including [unknown] — is false. A clock that
  /// cannot be corroborated is not a clock a security decision may lean on.
  bool get isCredible => this == ClockCredibility.credible;

  /// A short, user-safe explanation. `null` when the clock is credible.
  String? get reason => switch (this) {
        ClockCredibility.credible => null,
        ClockCredibility.behindAnchor =>
          'Device clock is earlier than the last server-issued timestamp',
        ClockCredibility.rewound =>
          'Device clock moved backwards since the last observation',
        ClockCredibility.implausible =>
          'Time since the last server contact is implausibly large',
        ClockCredibility.unknown =>
          'No authenticated server timestamp is available',
      };
}

/// The one place the SDK decides whether the device clock is usable.
///
/// ## Why this exists as its own type
///
/// Offline compliance and licence expiry are two different questions
/// (*"has this device checked in recently?"* vs *"has this licence run
/// out?"*) that share one prerequisite: **is the clock telling the truth?**
/// Before this existed, offline compliance answered that carefully and
/// `LicenseManager` did not answer it at all — the inconsistency recorded
/// in `docs/LICENSE_TIME_SECURITY_AUDIT.md` §4.
///
/// Extracting the shared question here is what keeps the project's
/// "one trusted clock, not two" rule true: both callers reach the same
/// verdict from the same anchor, and neither owns rollback logic of its own.
///
/// ## The anchor
///
/// [anchorIssuedAt] is the `issued_at` claim of a **verified** entitlement
/// token — server-stamped, HMAC-signed with the licence key, and only ever
/// issued by a successful `/activate` or `/heartbeat`. Editing it in
/// storage breaks the signature, so tampering removes the anchor rather
/// than moving it.
///
/// ## What this cannot do
///
/// It cannot *prove* the clock is right — only that it is not obviously
/// wrong. A steady drift, or a rollback smaller than the anchor's age, is
/// invisible here. See `docs/LICENSE_CLOCK_PROTECTION.md` for the full
/// statement of limits.
class TrustedClock {
  /// Elapsed times beyond this are treated as unmeasurable rather than
  /// merely large. Matches `OfflineComplianceEvaluator.maxPlausibleElapsed`
  /// deliberately: one threshold, one meaning, both subsystems.
  static const Duration maxPlausibleElapsed = Duration(days: 365);

  const TrustedClock();

  /// Assess [now] against the authenticated [anchorIssuedAt] and the
  /// highest wall-clock value this device has previously reported.
  ///
  /// Forward movement is deliberately **not** penalised: a clock running
  /// fast expires things *sooner*, which is fail-closed and not an attack
  /// worth defending against. Only the fail-open direction — backwards —
  /// is refused.
  ClockCredibility assess({
    required DateTime? anchorIssuedAt,
    required DateTime now,
    DateTime? clockHighWaterMark,
  }) {
    final current = now.toUtc();

    // Checked before the anchor: a rewind between launches is detectable
    // even when no anchor survives, and reporting `rewound` is more
    // actionable than reporting `unknown`.
    if (clockHighWaterMark != null &&
        current.isBefore(clockHighWaterMark.toUtc())) {
      return ClockCredibility.rewound;
    }

    if (anchorIssuedAt == null) return ClockCredibility.unknown;

    final anchor = anchorIssuedAt.toUtc();
    if (current.isBefore(anchor)) return ClockCredibility.behindAnchor;
    if (current.difference(anchor) > maxPlausibleElapsed) {
      return ClockCredibility.implausible;
    }
    return ClockCredibility.credible;
  }
}
