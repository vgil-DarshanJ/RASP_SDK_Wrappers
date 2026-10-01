/// The independent roots of trust this SDK verifies.
///
/// Each anchor answers a *different* question, from a *different* source, so
/// defeating one does not defeat the others. The full per-anchor definition —
/// source, owner, trust class, when it may legitimately change, and its
/// platform limitations — lives in `docs/TRUST_ANCHOR_MODEL.md`; this enum is
/// the code-side vocabulary for it.
enum TrustAnchor {
  /// The package/bundle id the OS says this process runs under.
  applicationId,

  /// The signing certificate the OS verified at install time.
  signingCertificate,

  /// The server-issued licence, and whether it binds to the identity actually
  /// observed here.
  licenseBinding,

  /// This install's device identity and Keystore binding.
  deviceBinding,

  /// The SDK version this build reports, judged against operator policy.
  sdkVersion,

  /// The security configuration/policy currently in force.
  securityConfiguration,

  /// DEBUG / STAGING / PRODUCTION, judged against what policy requires.
  releaseEnvironment,

  /// A live re-read of identity after activation, compared with what was
  /// captured when the seat was established.
  runtimeApplicationIdentity,

  /// Hardware/platform attestation (Google Play Integrity / Apple App
  /// Attest) — a verdict rooted in the device's own attestation mechanism,
  /// server-verified, rather than anything the app itself asserts. See
  /// `docs/ATTESTATION_ARCHITECTURE.md`.
  attestation,

  /// Whether this SDK build's own critical decision logic (TrustEngine,
  /// CorrelationEngine, ProtectionEngine) still behaves the way a signed,
  /// server-delivered manifest of behavioral canaries says it should. See
  /// `docs/SDK_SELF_INTEGRITY.md`.
  sdkIntegrity,
}

/// The trust class an anchor's verification path is rooted in.
///
/// Ranked `hardware > platform > server > local`. An anchor's reported
/// confidence is **capped** by the weakest class in its path — see
/// `TrustEngine`. This is how "is the source authoritative?" becomes a real
/// input to confidence rather than every failure being reported as certain.
enum TrustRoot {
  /// Asserted by the app about itself. Weakest: an attacker who controls the
  /// process controls the claim.
  local,

  /// Asserted by the RASP Shield backend.
  server,

  /// Asserted by the OS, which the app cannot unilaterally override.
  platform,

  /// Rooted in a TEE / secure element. No attestation is implemented today —
  /// present so a future Play Integrity / App Attest verdict has a home.
  hardware,
}

/// Ordering helper for [TrustRoot].
extension TrustRootX on TrustRoot {
  /// Higher is more authoritative.
  int get rank => index;
}

/// The verdict for one [TrustAnchor].
///
/// Deliberately six states, not a boolean. `valid` is the only state meaning
/// "this anchor is satisfied"; every other state is either a failure or an
/// absence of information, and none of them are ever folded into `valid`.
/// Mirrors the discipline `DetectionStatus` already enforces for detectors.
enum TrustAnchorState {
  /// Verified and matching.
  valid,

  /// Verified and **not** matching — the anchor is contradicted. This is the
  /// generic INVALID state as well as the identity/certificate MISMATCH one.
  mismatch,

  /// The anchor was valid but has aged out. Its own state, never folded into
  /// [valid] and never folded into [mismatch] — an expired policy is a
  /// different operational problem from a forged one.
  expired,

  /// The check ran but could not reach a verdict.
  unknown,

  /// The check never ran: wrong platform, not configured, nothing to compare
  /// against yet.
  unavailable,

  /// The check attempted to run and threw.
  error,
}

/// Semantics for [TrustAnchorState].
extension TrustAnchorStateX on TrustAnchorState {
  /// The single state that means "this anchor is satisfied".
  ///
  /// Named as a question rather than exposed as `== valid` comparisons all
  /// over the engine, so the "only one state is safe" rule has exactly one
  /// definition site.
  bool get isSatisfied => this == TrustAnchorState.valid;

  /// The anchor was actively contradicted, as opposed to merely unproven.
  bool get isContradicted =>
      this == TrustAnchorState.mismatch || this == TrustAnchorState.expired;

  /// No verdict was reached. Never safe, never a threat — the same
  /// three-way distinction `DetectionStatus.isIndeterminate` draws.
  bool get isIndeterminate =>
      this == TrustAnchorState.unknown ||
      this == TrustAnchorState.unavailable ||
      this == TrustAnchorState.error;

  /// Stable wire name for telemetry and stored evidence.
  String get wireName => name.toUpperCase();
}
