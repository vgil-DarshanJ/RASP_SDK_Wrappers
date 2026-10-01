/// What the SDK decides should happen about a completed protection
/// evaluation.
///
/// ## Who actually performs each action
///
/// This is the distinction that matters most in a commercial RASP SDK, and
/// it is encoded here rather than left to prose:
///
/// | Action        | Enforced by |
/// |---------------|-------------|
/// | [allow]       | nobody — nothing to do |
/// | [monitor]     | **SDK** — telemetry only, no user-visible effect |
/// | [warn]        | **host app** — it owns its own UI |
/// | [stepUp]      | **host app** — only it knows what re-authentication means |
/// | [block]       | **host app** — only it knows which feature is sensitive |
/// | [lockSession] | **host app** — only it owns the session |
/// | [lockApp]     | **SDK** — a full-screen lock the SDK can render itself |
///
/// The SDK never force-quits an application. `terminateApp` deliberately
/// does not exist: killing a banking app mid-transaction is a decision only
/// the bank can make, and an SDK that does it on its own turns a false
/// positive into an outage. [lockApp] is the strongest thing the SDK will do
/// unilaterally, and it is recoverable — the same lock screen the existing
/// `LOCK_APP` remote command already renders, which re-checks via heartbeat
/// and clears itself when the device is healthy again.
///
/// Use [isSdkEnforced] rather than hardcoding the table above.
///
/// Ordered least → most disruptive, so a policy can say "never escalate past
/// [warn] for this build" with an `.index` comparison.
enum ProtectionAction {
  /// Nothing found that clears the policy's thresholds.
  allow,

  /// Record it and move on. No user-visible effect — this is the action for
  /// "worth knowing about, not worth interrupting anyone".
  monitor,

  /// Surface a warning; let the user continue.
  warn,

  /// Require re-authentication (biometric, PIN, OTP) before continuing. The
  /// host app decides what its step-up actually is.
  stepUp,

  /// Disable specific sensitive capabilities — transfers, payments, adding a
  /// payee — while leaving the rest of the app usable.
  block,

  /// End the authenticated session and return the user to sign-in.
  lockSession,

  /// Lock the application behind a full-screen block until the device is
  /// healthy again. The most disruptive action the SDK will take.
  lockApp,
}

/// Which side of the boundary an action falls on.
extension ProtectionActionEnforcement on ProtectionAction {
  /// `true` when the SDK itself carries this out, `false` when the host
  /// application must.
  ///
  /// A host app that ignores every callback still gets [monitor] and
  /// [lockApp]; everything else silently does nothing unless the host wires
  /// it up. That asymmetry is deliberate and documented so an integrator
  /// cannot mistake "the SDK returned block" for "the feature was blocked".
  bool get isSdkEnforced =>
      this == ProtectionAction.monitor ||
      this == ProtectionAction.lockApp ||
      this == ProtectionAction.allow;

  /// `true` when the host application has to act for this to mean anything.
  bool get requiresHostApp => !isSdkEnforced;

  /// Stable wire name, used in policy JSON and telemetry.
  String get wireName => name;
}

/// Parses a [ProtectionAction] from its [ProtectionActionEnforcement.wireName].
///
/// Returns `null` for an unknown name rather than throwing: a policy issued
/// by a newer backend may name an action this SDK build does not have, and
/// the correct response is to ignore that entry, not to reject the whole
/// policy and fall back to no protection at all.
ProtectionAction? protectionActionFromName(String? name) {
  if (name == null) return null;
  for (final action in ProtectionAction.values) {
    if (action.name == name) return action;
  }
  return null;
}
