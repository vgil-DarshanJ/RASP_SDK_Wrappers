import '../core/core.dart';
import '../protection/protection_action.dart';

/// The default severity → minimum action floor.
///
/// ## Why this exists — the action-ladder reconciliation
///
/// `ProtectionEngine.evaluate()` (legacy) never decides on score alone. It
/// computes **two independent ladders** and takes whichever is stricter:
///
/// ```
/// bySeverity = severityFloor[highestSeverity]   // this table
/// byScore    = scoreLadder(riskScore)
/// action     = max(bySeverity, byScore)
/// ```
///
/// A single `critical`-severity finding therefore floors the action at
/// `lockApp` **even when the aggregate score is low** — one confirmed clone
/// or one confirmed tamper does not need a second detector to agree before
/// the SDK reacts.
///
/// `ProtectionEngine.evaluateWithRisk()` (the risk-engine pipeline) was built
/// with only the posture ladder — `SecurityProfileDefinition.actionFor
/// (posture)` — and no severity floor at all. That omission is what the
/// previous milestone's regression comparison actually found: a `high`- or
/// `critical`-severity finding with an uncorroborated (hence lower-scoring)
/// confidence could recommend a softer action under the new pipeline than
/// under the legacy one, for a reason that had nothing to do with confidence
/// — the floor that would have caught it simply didn't exist on that side.
///
/// This constant is the fix: **one shared table**, consulted by both
/// `ProtectionEngine._defaultSeverityAction` (legacy, unchanged output) and
/// `SecurityProfileDefinition.severityFloor` (new, now present). See
/// `docs/ACTION_LADDER_MIGRATION.md` for the full before/after comparison.
///
/// A profile may still override its own [SecurityProfileDefinition
/// .severityFloor] to be *stricter* (never softer — see
/// `validateProfile`'s monotonicity check) than this default, the same way
/// `ProtectionPolicy.severityActions` already lets a delivered policy
/// override the legacy ladder.
const Map<DetectionSeverity, ProtectionAction> defaultSeverityActionFloor = {
  DetectionSeverity.low: ProtectionAction.monitor,
  DetectionSeverity.medium: ProtectionAction.warn,
  DetectionSeverity.high: ProtectionAction.stepUp,
  DetectionSeverity.critical: ProtectionAction.lockApp,
};

/// Looks up the floor for [severity] in [floor], falling back to
/// [defaultSeverityActionFloor] for any severity a caller's custom table
/// omits — a partial override table must never leave a severity with no
/// floor at all, which would silently drop the protection this constant
/// exists to guarantee.
ProtectionAction severityActionFloor(
  DetectionSeverity? severity,
  Map<DetectionSeverity, ProtectionAction> floor,
) {
  if (severity == null) return ProtectionAction.allow;
  return floor[severity] ?? defaultSeverityActionFloor[severity]!;
}
