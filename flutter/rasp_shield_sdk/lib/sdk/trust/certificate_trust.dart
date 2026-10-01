import 'trust_anchor.dart';
import 'trust_evidence.dart';

/// The role a signing certificate plays in the customer's rotation lifecycle.
///
/// A customer must be able to rotate a signing key without their existing
/// installed base failing identity verification, and without the SDK silently
/// accepting arbitrary certificates. Three explicit roles is what makes both
/// true at once — see `docs/CERTIFICATE_ROTATION.md`.
enum CertificateRole {
  /// The certificate the customer signs with today. Always accepted.
  current,

  /// The certificate the customer is rotating *to*. Accepted, but reported as
  /// [TrustEvidenceCode.certificateRotationPending] so an operator can see
  /// the rollout progressing rather than discovering it after the fact.
  next,

  /// A certificate explicitly withdrawn. **Never** accepted, and outranks
  /// every other role — a fingerprint listed as revoked is rejected even if a
  /// malformed store also lists it as current.
  revoked,
}

/// The certificates this app will accept, and their roles.
///
/// Replaces the single pinned fingerprint the SDK carried before this
/// milestone (`RepackagingDetector._expectedFingerprint`, one `String?`),
/// which had no way to express a rotation window: a customer rotating keys
/// had a period where genuine new builds failed verification.
///
/// **Additive.** A store built from a single `current` fingerprint behaves
/// exactly as the previous single-pin implementation did.
class CertificateTrustStore {
  /// Accepted, and the expected steady state.
  final Set<String> current;

  /// Accepted during a rotation window, and flagged so the rollout is visible.
  final Set<String> next;

  /// Always rejected.
  final Set<String> revoked;

  const CertificateTrustStore({
    this.current = const {},
    this.next = const {},
    this.revoked = const {},
  });

  /// A store that trusts nothing. Verification against it is
  /// [TrustAnchorState.unavailable] (NOT_CONFIGURED), never `valid` and never
  /// `mismatch` — the same gate `RepackagingDetector` already applies, kept
  /// because reporting "clean" from an unconfigured pin was a real historical
  /// bug in this codebase.
  static const CertificateTrustStore empty = CertificateTrustStore();

  bool get isConfigured =>
      current.isNotEmpty || next.isNotEmpty || revoked.isNotEmpty;

  /// Normalizes a fingerprint to the bare uppercase hex form used throughout.
  ///
  /// Accepts the colon-separated, space-separated and lowercase forms that
  /// `keytool`, `apksigner` and the Play Console each print differently — the
  /// same normalization `RepackagingDetector.configureExpectedCertificate`
  /// already performs, so a value that worked before works now.
  static String normalize(String raw) =>
      raw.replaceAll(RegExp('[:\\s-]'), '').toUpperCase();

  /// Builds a store from a remote-config bundle, tolerating every shape the
  /// backend may deliver.
  ///
  /// Backward compatibility is the point: the existing scalar
  /// `signing_cert_sha256` field continues to populate [current], so a backend
  /// that knows nothing about rotation keeps working unchanged. The list
  /// fields are additive and optional.
  static CertificateTrustStore fromConfig(Map<String, dynamic> config) {
    Set<String> read(String key) {
      final value = config[key];
      if (value is String) {
        final normalized = normalize(value.trim());
        return normalized.isEmpty ? const {} : {normalized};
      }
      if (value is List) {
        return {
          for (final entry in value)
            if (entry is String && entry.trim().isNotEmpty)
              normalize(entry.trim()),
        };
      }
      return const {};
    }

    return CertificateTrustStore(
      current: {...read('signing_cert_sha256'), ...read('signing_certs_current')},
      next: read('signing_certs_next'),
      revoked: read('signing_certs_revoked'),
    );
  }

  /// The role [fingerprint] holds, or `null` when the store does not know it.
  ///
  /// Revoked is checked first and deliberately: a fingerprint that appears in
  /// both `revoked` and `current` — which can only happen through operator
  /// error or a tampered config — must reject, not accept. Fail-closed on
  /// contradiction.
  CertificateRole? roleOf(String fingerprint) {
    final value = normalize(fingerprint);
    if (revoked.contains(value)) return CertificateRole.revoked;
    if (current.contains(value)) return CertificateRole.current;
    if (next.contains(value)) return CertificateRole.next;
    return null;
  }
}

/// The outcome of checking an observed certificate against a trust store.
class CertificateTrustVerdict {
  final TrustAnchorState state;
  final CertificateRole? role;
  final List<TrustEvidence> evidence;

  const CertificateTrustVerdict({
    required this.state,
    this.role,
    this.evidence = const [],
  });
}

/// Checks an observed signing fingerprint against a [CertificateTrustStore].
///
/// Pure and deterministic: no I/O, no clock. The observed value is read
/// elsewhere (the native `getSigningCertSha256` call) precisely so this
/// decision can be unit-tested exhaustively with no device.
class CertificateTrustEvaluator {
  const CertificateTrustEvaluator();

  CertificateTrustVerdict evaluate({
    required String? observedFingerprint,
    required CertificateTrustStore store,
  }) {
    if (!store.isConfigured) {
      // Nothing pinned. Not a pass and not a failure — the check never ran.
      return const CertificateTrustVerdict(
        state: TrustAnchorState.unavailable,
        evidence: [TrustEvidence(TrustEvidenceCode.certificateNotConfigured)],
      );
    }

    final observed = observedFingerprint?.trim();
    if (observed == null || observed.isEmpty) {
      // A pin exists but the platform would not tell us what we are signed
      // with. Never `valid` — inability to read identity is not proof of it.
      return const CertificateTrustVerdict(
        state: TrustAnchorState.unknown,
        evidence: [TrustEvidence(TrustEvidenceCode.certificateUnavailable)],
      );
    }

    switch (store.roleOf(observed)) {
      case CertificateRole.current:
        return const CertificateTrustVerdict(
          state: TrustAnchorState.valid,
          role: CertificateRole.current,
        );
      case CertificateRole.next:
        return const CertificateTrustVerdict(
          state: TrustAnchorState.valid,
          role: CertificateRole.next,
          evidence: [
            TrustEvidence(
              TrustEvidenceCode.certificateRotationPending,
              detail: 'signed with the incoming rotation certificate',
            ),
          ],
        );
      case CertificateRole.revoked:
        return const CertificateTrustVerdict(
          state: TrustAnchorState.mismatch,
          role: CertificateRole.revoked,
          evidence: [
            TrustEvidence(
              TrustEvidenceCode.certificateRevoked,
              detail: 'signed with a withdrawn certificate',
            ),
          ],
        );
      case null:
        return const CertificateTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [
            TrustEvidence(
              TrustEvidenceCode.certificateMismatch,
              detail: 'observed certificate matches no trusted fingerprint',
            ),
          ],
        );
    }
  }
}
