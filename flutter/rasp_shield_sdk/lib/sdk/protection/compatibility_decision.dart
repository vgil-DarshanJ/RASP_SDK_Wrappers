import 'protection_action.dart';
import 'protection_policy.dart';
import 'protection_result.dart';

/// Where a [CompatibilityEngine] decision actually came from — the "reason"
/// half of Phase 2's golden-scenario record, kept as data rather than only a
/// free-text string so a test can assert on it directly.
enum CompatibilitySource {
  /// Both pipelines recommended the same action.
  agreement,

  /// The risk pipeline was stricter; its action was used.
  riskStricter,

  /// The legacy pipeline was stricter (or the risk pipeline was unavailable);
  /// the legacy action was used.
  legacyStricter,

  /// The risk pipeline could not be evaluated this cycle. Legacy — which, by
  /// construction, already ran successfully to reach this point — was used
  /// unmodified.
  riskUnavailable,

  /// Neither pipeline produced a usable result. The documented fail-safe
  /// action was used.
  bothUnavailable,
}

/// The result of reconciling a legacy and a risk-engine [ProtectionResult]
/// into one decision, plus the evidence for why.
class CompatibilityDecision {
  final ProtectionAction action;
  final CompatibilitySource source;

  /// The full result whose [ProtectionResult.recommendedAction] became
  /// [action] — legacy's own result when [source] is [CompatibilitySource.legacyStricter]
  /// or [CompatibilitySource.riskUnavailable]; the risk result when
  /// [CompatibilitySource.riskStricter] or (arbitrarily, since they agree)
  /// [CompatibilitySource.agreement]. `null` only for
  /// [CompatibilitySource.bothUnavailable].
  final ProtectionResult? chosen;

  final ProtectionResult? legacy;
  final ProtectionResult? risk;

  const CompatibilityDecision({
    required this.action,
    required this.source,
    required this.chosen,
    required this.legacy,
    required this.risk,
  });

  /// `true` when [action] is strictly more severe than the legacy
  /// evaluation's own recommendation — i.e. compatibility mode changed what
  /// the app does relative to running legacy alone. `false` when it is equal
  /// (agreement, or risk unavailable) or when there was no legacy result to
  /// compare against.
  bool get escalatedBeyondLegacy =>
      legacy != null && action.index > legacy!.recommendedAction.index;

  Map<String, Object?> toMap() => {
        'action': action.name,
        'source': source.name,
        'legacy_action': legacy?.recommendedAction.name,
        'risk_action': risk?.recommendedAction.name,
        'escalated_beyond_legacy': escalatedBeyondLegacy,
      };

  @override
  String toString() =>
      'CompatibilityDecision(action=${action.name}, source=${source.name})';
}

/// Reconciles the legacy and risk-engine pipelines into one decision that is
/// **provably never less protective than legacy alone**.
///
/// ```
///   legacyResult, riskResult, policy  →  decide()  →  CompatibilityDecision
/// ```
///
/// ## The security invariant this class exists to guarantee
///
/// For every input this class accepts:
///
/// ```
/// decide(...).action.index >= (legacyResult?.recommendedAction.index ?? 0)
/// ```
///
/// i.e. `NEW_ACTION >= LEGACY_ACTION` on [ProtectionAction]'s existing,
/// already-authoritative least→most-disruptive ordering. See
/// `docs/SECURITY_DECISION_INVARIANTS.md` for the full statement and
/// `test/compatibility_decision_invariant_test.dart` for the property tests
/// that check it exhaustively rather than by example.
///
/// ## Rules (Phase 4 of `docs/RISK_PIPELINE_PROMOTION_AUDIT.md`)
///
/// 1. Both pipelines agree → use the shared decision.
/// 2. Risk is stricter → use the stricter (risk) decision.
/// 3. Legacy is stricter → use the stricter (legacy) decision.
/// 4. One side is unavailable (`null`) → never weaken: use whichever side is
///    actually available. If legacy is the available one, this is
///    byte-identical to running legacy alone.
/// 5. Both unavailable → the documented fail-safe: `policy.clamp(warn)`,
///    the same "we could not verify enough to say allow" escalation the
///    risk pipeline's own coverage gate already uses elsewhere in this
///    codebase (`ProtectionEngine.evaluateWithRisk`'s coverage-gate comment).
///
/// Pure: no I/O, no clock read (reasons/timestamps live on the
/// [ProtectionResult]s already passed in), so the same two results always
/// produce the same [CompatibilityDecision].
///
/// **Does not modify [ProtectionEngine.evaluate]/[ProtectionEngine.evaluateWithRisk]
/// in any way** — it only reads their outputs. Neither existing method's
/// semantics changed for this milestone.
///
/// ## Precondition the invariant actually depends on
///
/// The `NEW_ACTION >= LEGACY_ACTION` proof (see
/// `docs/SECURITY_DECISION_INVARIANTS.md` §Proof) relies on [legacy] and
/// [risk] having been computed under the **same** `ProtectionPolicy` that is
/// also passed as [policy] here — because a policy-permitted action is
/// exactly what makes `effective.clamp()` monotonic across the comparison.
/// `SecurityCenterController` satisfies this by construction: it reads
/// `RemoteConfigManager.policy` once per scan and passes that identical
/// instance to `evaluate()`, `evaluateWithRisk()`, and this method. A caller
/// that mixes results computed under different policies is outside the
/// proof and outside this class's contract.
class CompatibilityEngine {
  const CompatibilityEngine();

  /// The fail-safe action when both pipelines are unavailable — rule 5.
  /// Not [ProtectionAction.allow] (that would mean "we learned nothing, so
  /// assume safety") and not [ProtectionAction.lockApp] (a locked-out fleet
  /// from a transient double-failure is its own outage) — `warn` is the
  /// same floor the risk engine's coverage gate already escalates to for
  /// "could not verify enough to trust a clean result."
  static const ProtectionAction _bothUnavailableFallback = ProtectionAction.warn;

  /// Reconciles [legacy] and [risk] under [policy].
  ///
  /// [legacy] should always be supplied when this scan actually ran the
  /// legacy pipeline (which `SecurityCenterController.runScan` always does,
  /// unconditionally, before compatibility mode even applies) — it is
  /// nullable here only so this class's own fail-safe rules (4/5) are
  /// directly testable and so a future caller that genuinely could not run
  /// legacy (never true in this codebase today) still gets a safe answer
  /// instead of a crash.
  CompatibilityDecision decide({
    required ProtectionResult? legacy,
    required ProtectionResult? risk,
    required ProtectionPolicy policy,
  }) {
    final effective = policy.effective();

    if (legacy == null && risk == null) {
      return CompatibilityDecision(
        action: effective.clamp(_bothUnavailableFallback),
        source: CompatibilitySource.bothUnavailable,
        chosen: null,
        legacy: null,
        risk: null,
      );
    }

    if (risk == null) {
      // Rule 4, legacy side available: never weaken by simply not having a
      // risk result — legacy already ran and is used exactly as computed.
      return CompatibilityDecision(
        action: effective.clamp(legacy!.recommendedAction),
        source: CompatibilitySource.riskUnavailable,
        chosen: legacy,
        legacy: legacy,
        risk: null,
      );
    }

    if (legacy == null) {
      // Rule 4, risk side available: legacy could not be evaluated (not a
      // real path today — SecurityCenterController always runs legacy
      // first — kept for API completeness and direct testability). Use
      // whatever risk found; it is the only evidence there is.
      return CompatibilityDecision(
        action: effective.clamp(risk.recommendedAction),
        source: CompatibilitySource.riskUnavailable,
        chosen: risk,
        legacy: null,
        risk: risk,
      );
    }

    // Both available: rules 1-3, one comparison covers all three. Ties
    // (rule 1) and "legacy stricter" (rule 3) both keep legacy — arbitrary
    // but deterministic, and legacy's own detections/reasons stay in the
    // returned result either way when the two agree.
    final legacyAction = legacy.recommendedAction;
    final riskAction = risk.recommendedAction;

    if (riskAction.index > legacyAction.index) {
      return CompatibilityDecision(
        action: effective.clamp(riskAction),
        source: CompatibilitySource.riskStricter,
        chosen: risk,
        legacy: legacy,
        risk: risk,
      );
    }

    final source = riskAction.index == legacyAction.index
        ? CompatibilitySource.agreement
        : CompatibilitySource.legacyStricter;
    return CompatibilityDecision(
      action: effective.clamp(legacyAction),
      source: source,
      chosen: legacy,
      legacy: legacy,
      risk: risk,
    );
  }
}
