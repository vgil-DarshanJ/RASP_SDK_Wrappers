/// Phase 5/8 — the authentication half of a sensitive-operation decision,
/// derived from a [StepUpPolicy] and an optional [StepUpResult]. Never
/// derived from a raw credential — see `step_up.dart`.
library;

import 'step_up.dart';

enum OperationAuthenticationState {
  /// This operation's sensitivity does not require step-up.
  notRequired,

  /// Step-up is required and no valid result has been presented.
  required_,

  /// A valid, in-window [StepUpResult] was presented.
  satisfied,

  /// A [StepUpResult] was presented but `succeeded` was `false`.
  failed,

  /// A successful [StepUpResult] was presented but is outside
  /// [StepUpPolicy.validity].
  expired,
}

extension OperationAuthenticationStateX on OperationAuthenticationState {
  String get wireName {
    switch (this) {
      case OperationAuthenticationState.notRequired:
        return 'NOT_REQUIRED';
      case OperationAuthenticationState.required_:
        return 'REQUIRED';
      case OperationAuthenticationState.satisfied:
        return 'SATISFIED';
      case OperationAuthenticationState.failed:
        return 'FAILED';
      case OperationAuthenticationState.expired:
        return 'EXPIRED';
    }
  }
}

/// The **sanctioned** way to compute [OperationAuthenticationState] — Phase
/// 23's security review found that nothing stopped a caller from
/// constructing [SensitiveOperationContext] with `satisfied` set directly,
/// with no real [StepUpResult] behind it at all. That is a trust-boundary
/// limit no SDK API can fully close (a host app's own process can always lie
/// to itself), but this function is what a *correct* integration calls, so
/// a careless one has to actively skip a step to bypass it rather than never
/// having a correct path in the first place. See
/// `docs/SENSITIVE_OPERATION_THREAT_MODEL.md` §"What this does not defend
/// against."
///
/// [stepUpRequired] should be the [SensitiveOperationPolicy]-derived
/// baseline floor for the operation (`floorFor(...) == stepUp`) computed
/// *without* folding in authentication state — evaluating that circularly
/// from this function's own output would be meaningless.
OperationAuthenticationState deriveAuthenticationState({
  required bool stepUpRequired,
  StepUpResult? result,
  StepUpPolicy policy = const StepUpPolicy(),
  DateTime? now,
}) {
  if (!stepUpRequired) return OperationAuthenticationState.notRequired;
  if (result == null) return OperationAuthenticationState.required_;
  if (!result.succeeded) return OperationAuthenticationState.failed;
  if (!result.isValid(validity: policy.validity, now: now)) {
    return OperationAuthenticationState.expired;
  }
  return OperationAuthenticationState.satisfied;
}
