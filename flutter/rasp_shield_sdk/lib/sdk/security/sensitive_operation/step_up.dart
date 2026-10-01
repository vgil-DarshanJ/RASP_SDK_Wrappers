/// Phase 5 — the generic step-up authentication abstraction.
///
/// ## What the SDK does and does not do
///
/// The SDK **never collects or stores** a password, PIN, or biometric
/// sample — those belong entirely to the host application (and, for
/// biometrics, the platform's own secure APIs). What the SDK produces is a
/// verdict — [SensitiveOperationAction.stepUp] — and what it consumes is a
/// caller-supplied [StepUpResult] describing what already happened. The SDK
/// is the arbiter of *whether* step-up is required and *whether a presented
/// result is still valid*; it is never the thing that performs the
/// authentication.
library;

/// How the host app satisfied a step-up requirement. An open, host-defined
/// string rather than a closed enum — the SDK does not know, and must not
/// need to know, which authentication mechanisms a given host app supports.
/// Common values a host app might use: `'biometric'`, `'device_pin'`,
/// `'host_password'`, `'device_proof'`, `'reattestation'`.
typedef StepUpMethod = String;

/// One caller-supplied step-up outcome.
///
/// Carries only what a decision needs — never a credential, a biometric
/// template, or anything that could reconstruct one. [method] is a label,
/// not a proof; the *proof* that step-up genuinely happened is the host
/// app's own responsibility (e.g. the platform biometric API already
/// returned success before this object is constructed).
class StepUpResult {
  /// Whether the host app's step-up attempt succeeded.
  final bool succeeded;

  /// What mechanism was used. Never a secret — see [StepUpMethod].
  final StepUpMethod method;

  /// When the step-up was completed, UTC. Used to enforce
  /// [StepUpPolicy.validity] — a step-up from ten minutes ago must not
  /// silently authorize an operation now.
  final DateTime completedAt;

  /// Free-form, non-secret detail for the security-event evidence trail
  /// (e.g. `'biometric_strong'` vs `'biometric_weak'`). Never a token, a
  /// PIN, or any value that could be replayed to impersonate the user.
  final String? detail;

  const StepUpResult({
    required this.succeeded,
    required this.method,
    required this.completedAt,
    this.detail,
  });

  /// `true` when [succeeded] and still inside [validity] of [now].
  bool isValid({required Duration validity, DateTime? now}) {
    if (!succeeded) return false;
    final clock = (now ?? DateTime.now()).toUtc();
    final age = clock.difference(completedAt.toUtc());
    return age >= Duration.zero && age <= validity;
  }

  Map<String, Object?> toMap() => {
        'succeeded': succeeded,
        'method': method,
        'completed_at': completedAt.toUtc().toIso8601String(),
        if (detail != null) 'detail': detail,
      };
}

/// Policy for how long a [StepUpResult] remains usable, and how far in the
/// future a completion timestamp may claim to be (clock-skew tolerance,
/// mirroring the same defence-in-depth reasoning `TransactionOperationGuard`
/// already applies to `timestamp`).
class StepUpPolicy {
  /// How long after [StepUpResult.completedAt] the result stays usable.
  final Duration validity;

  const StepUpPolicy({this.validity = const Duration(minutes: 5)});
}
