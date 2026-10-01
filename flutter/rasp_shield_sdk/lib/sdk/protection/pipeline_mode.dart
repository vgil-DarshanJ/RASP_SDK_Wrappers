/// The staged rollout mode for the risk pipeline promotion.
///
/// ```
///   LEGACY  →  SHADOW  →  COMPATIBILITY  →  AUTHORITATIVE
/// ```
///
/// Ordered least → most promoted, exactly like [ProtectionAction] is ordered
/// least → most disruptive — a rollout can only ever *advance* along this
/// axis by explicit, authenticated configuration; it never advances by
/// accident. See `docs/RISK_PIPELINE_ROLLOUT.md`.
///
/// **`AUTHORITATIVE` (Authoritative Protection Engine V1 milestone).** The
/// prior milestone deliberately stopped at `COMPATIBILITY` and left this
/// value out of the enum entirely, rather than add it unreachable — see
/// that milestone's own note, preserved in git history. This milestone is
/// the explicitly-commissioned "future work" that adds it, governing a
/// **different axis** from the three modes above: `legacy`/`shadow`/
/// `compatibility` decide which *decision* (`ProtectionResult.recommendedAction`)
/// is live; `authoritative` additionally decides whether
/// `EnforcementController` actually *executes* that decision (persists
/// `EnforcementState`, gates the launch screen) rather than merely
/// computing and reporting it. See `docs/ENFORCEMENT_POLICY.md` §Rollout.
///
/// **Still never a default.** [PipelineRolloutConfig.fromConfig] accepts the
/// wire name `"authoritative"` from an already-authenticated configuration
/// document (the same trust boundary `compatibility` already crossed), but
/// every malformed/unauthenticated/unrecognized input continues to resolve
/// to [legacy] — there is no path, accidental or otherwise, by which a
/// device reaches `authoritative` without an operator explicitly naming it
/// in a signed document, or a test explicitly forcing it via
/// `SecurityCenterController`'s existing `forcedPipelineModeForTesting`
/// seam. Nothing in this codebase ships that configuration by default.
enum PipelineMode {
  /// `_protection` (the live decision) is exactly `ProtectionEngine.evaluate()`
  /// — byte-identical to this SDK's behavior before this milestone. The
  /// default, and what every unauthenticated or malformed rollout
  /// configuration resolves to.
  legacy,

  /// Same live decision as [legacy]. The risk-engine pipeline runs (as it
  /// already did by default before this milestone) purely for observation —
  /// `shadowProtection`/`shadowComparison`, never `protection`.
  shadow,

  /// The live decision is [CompatibilityEngine.decide]'s output: the
  /// stricter of the legacy and risk-engine results, never softer than
  /// legacy alone. See `docs/COMPATIBILITY_DECISION_MODEL.md`.
  compatibility,

  /// Everything [compatibility] does, plus: `EnforcementController` actually
  /// applies the resulting `ProtectionAction` — persisting `EnforcementState`
  /// and gating the launch screen — instead of only computing and reporting
  /// what it would do. See `docs/ENFORCEMENT_POLICY.md` and
  /// `docs/ENFORCEMENT_STATE.md`.
  authoritative,
}

/// Semantics and wire parsing for [PipelineMode].
extension PipelineModeX on PipelineMode {
  String get wireName => name;

  /// Ordering helper, matching [PipelineMode]'s declared order.
  int get rank => index;
}

/// The rollout configuration this SDK build is operating under.
class PipelineRolloutConfig {
  final PipelineMode mode;

  const PipelineRolloutConfig({required this.mode});

  /// The safe default: nothing published, or what an unauthenticated
  /// configuration resolves to. Byte-identical to this SDK's pre-milestone
  /// behavior.
  static const PipelineRolloutConfig legacy =
      PipelineRolloutConfig(mode: PipelineMode.legacy);

  /// Parses the `risk_pipeline_rollout` section of a remote-config bundle.
  ///
  /// **Callers must only pass a [config] whose authenticity has already
  /// been established** — the same `certificateGateOpen`-style gate
  /// `TrustAnchorCollector` already applies to `sdkIntegrityManifest` and
  /// the certificate trust store. This parser does not itself verify a
  /// signature; an unauthenticated caller must substitute [legacy] instead
  /// of calling this at all. See `docs/RISK_PIPELINE_ROLLOUT.md` §Safety.
  ///
  /// **Never returns anything other than [legacy] for a malformed or
  /// partial section.** There is no "unknown value defaults to the more
  /// promoted mode" path — an operator typo, a missing field, or a value
  /// this SDK build does not recognize (a future `authoritative`, say) all
  /// resolve to [legacy], the least-promoted, always-safe mode. This is the
  /// concrete answer to this milestone's "avoid a simple insecure
  /// `useNewEngine = true`" instruction: advancing the rollout requires
  /// naming an exact, recognized mode inside an authenticated document —
  /// there is no boolean to flip and no ambiguous value that resolves
  /// upward.
  static PipelineRolloutConfig fromConfig(Map<String, dynamic> config) {
    final section = config['risk_pipeline_rollout'];
    if (section is! Map) return legacy;

    final raw = section['mode'];
    if (raw is! String) return legacy;

    for (final mode in PipelineMode.values) {
      if (mode.wireName == raw) return PipelineRolloutConfig(mode: mode);
    }
    // Unrecognized name (including a future "authoritative") — never
    // resolves upward past what this build actually implements.
    return legacy;
  }
}
