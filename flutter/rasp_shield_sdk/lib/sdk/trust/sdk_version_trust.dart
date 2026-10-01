import 'trust_anchor.dart';
import 'trust_evidence.dart';

/// A dotted numeric version, compared numerically rather than lexically.
///
/// `'2.10.0'` must sort above `'2.9.0'`; string comparison gets that wrong,
/// and a version comparison that is wrong in the wrong direction would lock
/// legitimate customers out of their own app.
class SdkVersion implements Comparable<SdkVersion> {
  final List<int> parts;

  const SdkVersion(this.parts);

  /// Parses `'2.0.0'`. Returns `null` for anything non-numeric, rather than
  /// guessing — an unparseable version becomes `unknown`, never `blocked`.
  static SdkVersion? tryParse(String? raw) {
    if (raw == null) return null;
    final trimmed = raw.trim();
    if (trimmed.isEmpty) return null;
    final segments = trimmed.split('.');
    final parsed = <int>[];
    for (final segment in segments) {
      final value = int.tryParse(segment);
      if (value == null || value < 0) return null;
      parsed.add(value);
    }
    return parsed.isEmpty ? null : SdkVersion(parsed);
  }

  @override
  int compareTo(SdkVersion other) {
    final length = parts.length > other.parts.length ? parts.length : other.parts.length;
    for (var i = 0; i < length; i++) {
      final a = i < parts.length ? parts[i] : 0;
      final b = i < other.parts.length ? other.parts[i] : 0;
      if (a != b) return a.compareTo(b);
    }
    return 0;
  }

  bool operator <(SdkVersion other) => compareTo(other) < 0;

  @override
  String toString() => parts.join('.');

  @override
  bool operator ==(Object other) =>
      other is SdkVersion && compareTo(other) == 0;

  @override
  int get hashCode => toString().hashCode;
}

/// How an SDK version stands against operator policy.
enum SdkVersionStanding {
  /// At or above the current supported version.
  supported,

  /// Still functional, but scheduled for withdrawal. Reported, never blocking
  /// on its own.
  deprecated,

  /// Below the published minimum.
  unsupported,

  /// Explicitly named in a block list.
  blocked,

  /// No policy delivered, or a version that would not parse.
  unknown,
}

/// The operator-published SDK version policy.
///
/// **Default: nothing is blocked.** The brief is explicit that arbitrary
/// remote blocking must not be implemented without a documented policy, and
/// that legitimate existing applications must not be silently rejected — so a
/// device that has never received a policy reports `supported`, not `unknown`
/// with consequences, and certainly not `blocked`.
class SdkVersionPolicy {
  /// The version customers are expected to be on. Anything at or above this
  /// is [SdkVersionStanding.supported].
  final SdkVersion? currentSupported;

  /// Below this, a build is [SdkVersionStanding.unsupported].
  final SdkVersion? minimumSupported;

  /// At or above [minimumSupported] but below this, a build is
  /// [SdkVersionStanding.deprecated] — a warning window before withdrawal.
  final SdkVersion? deprecatedBelow;

  /// Exact versions withdrawn for a named reason (e.g. a security defect).
  /// An explicit list, never a range, so a block is always a deliberate act.
  final Set<String> blocked;

  const SdkVersionPolicy({
    this.currentSupported,
    this.minimumSupported,
    this.deprecatedBelow,
    this.blocked = const {},
  });

  /// The policy in force before any operator has published one.
  static const SdkVersionPolicy permissive = SdkVersionPolicy();

  bool get isConfigured =>
      currentSupported != null ||
      minimumSupported != null ||
      deprecatedBelow != null ||
      blocked.isNotEmpty;

  /// Reads a policy from a remote-config bundle. Every field is optional and
  /// additive; a bundle with none of them yields [permissive].
  static SdkVersionPolicy fromConfig(Map<String, dynamic> config) {
    SdkVersion? version(String key) {
      final value = config[key];
      return value is String ? SdkVersion.tryParse(value) : null;
    }

    final rawBlocked = config['sdk_versions_blocked'];
    return SdkVersionPolicy(
      currentSupported: version('sdk_version_current'),
      minimumSupported: version('sdk_version_minimum'),
      deprecatedBelow: version('sdk_version_deprecated_below'),
      blocked: rawBlocked is List
          ? {
              for (final entry in rawBlocked)
                if (entry is String && entry.trim().isNotEmpty) entry.trim(),
            }
          : const {},
    );
  }
}

/// Outcome of judging a reported SDK version.
class SdkVersionVerdict {
  final TrustAnchorState state;
  final SdkVersionStanding standing;
  final List<TrustEvidence> evidence;

  const SdkVersionVerdict({
    required this.state,
    required this.standing,
    this.evidence = const [],
  });
}

/// Judges a reported SDK version against [SdkVersionPolicy].
///
/// Pure and deterministic. Note the honest limitation recorded in
/// `docs/TRUST_ANCHOR_MODEL.md` §1.5: a self-reported version is forgeable, so
/// this anchor is operational fleet hygiene rather than an adversarial
/// control, and it is weighted accordingly (`TrustRoot.local`).
class SdkVersionTrustEvaluator {
  const SdkVersionTrustEvaluator();

  SdkVersionVerdict evaluate({
    required String? reportedVersion,
    required SdkVersionPolicy policy,
  }) {
    final raw = reportedVersion?.trim();

    // An explicit block list is matched on the raw string, before parsing, so
    // a version that is blocked but unparseable is still blocked.
    if (raw != null && policy.blocked.contains(raw)) {
      return const SdkVersionVerdict(
        state: TrustAnchorState.mismatch,
        standing: SdkVersionStanding.blocked,
        evidence: [
          TrustEvidence(
            TrustEvidenceCode.sdkVersionBlocked,
            detail: 'this SDK version was withdrawn by policy',
          ),
        ],
      );
    }

    if (!policy.isConfigured) {
      // No policy has been published. Legitimate existing applications must
      // not be punished for that, so this is a pass, not an unknown.
      return const SdkVersionVerdict(
        state: TrustAnchorState.valid,
        standing: SdkVersionStanding.supported,
      );
    }

    final version = SdkVersion.tryParse(raw);
    if (version == null) {
      return const SdkVersionVerdict(
        state: TrustAnchorState.unknown,
        standing: SdkVersionStanding.unknown,
        evidence: [TrustEvidence(TrustEvidenceCode.sdkVersionUnknown)],
      );
    }

    final minimum = policy.minimumSupported;
    if (minimum != null && version < minimum) {
      return const SdkVersionVerdict(
        state: TrustAnchorState.mismatch,
        standing: SdkVersionStanding.unsupported,
        evidence: [
          TrustEvidence(
            TrustEvidenceCode.sdkVersionUnsupported,
            detail: 'below the published minimum supported version',
          ),
        ],
      );
    }

    final deprecatedBelow = policy.deprecatedBelow;
    if (deprecatedBelow != null && version < deprecatedBelow) {
      // Deprecated is a warning, not a failure: the anchor stays `valid` so a
      // scheduled deprecation cannot, by itself, cost a customer their trust
      // level. The evidence code still travels for operator visibility.
      return const SdkVersionVerdict(
        state: TrustAnchorState.valid,
        standing: SdkVersionStanding.deprecated,
        evidence: [TrustEvidence(TrustEvidenceCode.sdkVersionDeprecated)],
      );
    }

    return const SdkVersionVerdict(
      state: TrustAnchorState.valid,
      standing: SdkVersionStanding.supported,
    );
  }
}
