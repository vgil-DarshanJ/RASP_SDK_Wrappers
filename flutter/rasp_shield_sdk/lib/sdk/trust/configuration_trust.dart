import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'config_signing_keys.dart';
import 'signed_config_verifier.dart';
import 'trust_anchor.dart';
import 'trust_evidence.dart';

/// An authenticated-configuration envelope.
///
/// The audit found the existing remote config is versioned and
/// replay-protected but **not cryptographically authenticated**. Rather than
/// inventing a new crypto scheme on the device (which the brief explicitly
/// forbids as a first move), this type defines the *structure* an
/// authenticated config needs, populates every field the backend already
/// supplies, and leaves [integrity] optional and unenforced until a backend
/// can sign — see `docs/SECURITY_CONFIGURATION_TRUST.md` for the trust-root
/// definition that enforcement will require.
///
/// Nothing here embeds a secret. A shared secret compiled into the APK would
/// be extractable and would let an attacker forge exactly the configuration
/// this envelope exists to authenticate, which is why the integrity field is
/// specified as an asymmetric signature over a public key — not an HMAC.
class SecurityConfigEnvelope {
  /// Monotonic version. The existing replay/downgrade defence.
  final int version;

  /// Stable identity of this configuration document.
  final String? configId;

  final DateTime? issuedAt;
  final DateTime? expiresAt;

  /// The configuration itself.
  final Map<String, dynamic> payload;

  /// Detached signature over the canonical payload. **Not verified today** —
  /// present so the wire format is stable before enforcement lands.
  final String? integrity;

  const SecurityConfigEnvelope({
    required this.version,
    this.configId,
    this.issuedAt,
    this.expiresAt,
    this.payload = const {},
    this.integrity,
  });

  /// Parses an envelope out of a remote-config bundle.
  ///
  /// Backward compatible by construction: a bundle carrying none of the
  /// envelope fields yields version 0 with the bundle itself as the payload,
  /// which is exactly how the SDK behaved before this milestone.
  ///
  /// [versionOverride] exists because the backend sends `config_version` as a
  /// **sibling** of `remote_config`, not a member of it (see
  /// `docs/SIGNED_SECURITY_CONFIGURATION_AUDIT.md` §4) — reading it from
  /// [config] alone yields `0` on every real device, which
  /// `ConfigurationTrustEvaluator` reports as `CONFIG_MALFORMED` on every
  /// healthy device. The collector must pass the version it actually holds
  /// (`LicenseStatus.configVersion`) here.
  static SecurityConfigEnvelope fromConfig(
    Map<String, dynamic> config, {
    int? versionOverride,
  }) {
    DateTime? parseUtc(Object? value) {
      if (value is! String || value.isEmpty) return null;
      return DateTime.tryParse(value)?.toUtc();
    }

    final rawVersion = config['config_version'];
    return SecurityConfigEnvelope(
      version: versionOverride ?? (rawVersion is num ? rawVersion.toInt() : 0),
      configId: config['config_id'] is String ? config['config_id'] as String : null,
      issuedAt: parseUtc(config['issued_at']),
      expiresAt: parseUtc(config['expires_at']),
      payload: config,
      integrity:
          config['integrity'] is String ? config['integrity'] as String : null,
    );
  }

  /// A stable fingerprint of the *effective* configuration values.
  ///
  /// Used for runtime mutation detection: the fingerprint is taken when a
  /// configuration is applied, and recomputed later from whatever is actually
  /// in force. A Frida script that pokes the in-memory policy values directly
  /// — bypassing the normal merge path entirely — changes the recomputed
  /// fingerprint without changing the version, which is precisely the case
  /// version monotonicity cannot see.
  ///
  /// Keys are sorted so the fingerprint depends on content, not map ordering.
  /// The `integrity` field is excluded: a signature over a payload cannot be
  /// part of the payload it signs.
  String fingerprint() => fingerprintOf(payload);

  /// [fingerprint] for an arbitrary map. Exposed so a caller can fingerprint
  /// the live in-memory values without constructing an envelope around them.
  static String fingerprintOf(Map<String, dynamic> values) {
    final keys = values.keys.where((k) => k != 'integrity').toList()..sort();
    final canonical = <String, Object?>{
      for (final key in keys) key: _canonical(values[key]),
    };
    return sha256.convert(utf8.encode(jsonEncode(canonical))).toString();
  }

  /// Recursively canonicalizes nested structures so map ordering inside a
  /// nested policy object cannot change the fingerprint either.
  static Object? _canonical(Object? value) {
    if (value is Map) {
      final keys = value.keys.map((k) => k.toString()).toList()..sort();
      return {for (final key in keys) key: _canonical(value[key])};
    }
    if (value is List) return value.map(_canonical).toList();
    return value;
  }
}

/// Outcome of evaluating configuration trust.
class ConfigurationTrustVerdict {
  final TrustAnchorState state;
  final List<TrustEvidence> evidence;

  const ConfigurationTrustVerdict({
    required this.state,
    this.evidence = const [],
  });
}

/// Judges an incoming or in-force configuration.
///
/// Pure: the clock is injected rather than read, so expiry behaviour is
/// exhaustively testable and a stored assessment can be re-explained later.
class ConfigurationTrustEvaluator {
  const ConfigurationTrustEvaluator();

  /// Evaluates the configuration currently in force.
  ///
  /// [heldVersion] is the version the SDK already had; [envelope] describes
  /// what is in force now. [liveFingerprint] is a fingerprint recomputed from
  /// the values actually in memory — when it differs from the envelope's own,
  /// something mutated the configuration outside the normal path.
  ///
  /// Never throws and never crashes the app: a malformed configuration is a
  /// verdict, not an exception.
  ConfigurationTrustVerdict evaluate({
    required SecurityConfigEnvelope? envelope,
    required DateTime now,
    int? heldVersion,
    String? heldConfigId,
    String? liveFingerprint,
    /// Result of cryptographic verification, when it was performed.
    ///
    /// `null` means signature verification did not run at all — the pre-signing
    /// behaviour, preserved byte-for-byte so every rule and test that predates
    /// signed configuration is unaffected.
    SignedConfigVerification? verification,
  }) {
    if (envelope == null) {
      return const ConfigurationTrustVerdict(
        state: TrustAnchorState.unavailable,
        evidence: [TrustEvidence(TrustEvidenceCode.configUnavailable)],
      );
    }

    if (verification != null) {
      return _evaluateVerified(
        envelope: envelope,
        now: now,
        heldVersion: heldVersion,
        heldConfigId: heldConfigId,
        liveFingerprint: liveFingerprint,
        verification: verification,
      );
    }

    final evidence = <TrustEvidence>[];

    // Malformed: a configuration that cannot be ordered against anything
    // cannot be trusted not to be a replay. Same rule RemoteConfigManager
    // already applies to protection policies (`version <= 0` rejected).
    if (envelope.version <= 0) {
      return const ConfigurationTrustVerdict(
        state: TrustAnchorState.mismatch,
        evidence: [
          TrustEvidence(
            TrustEvidenceCode.configMalformed,
            detail: 'configuration carries no orderable version',
          ),
        ],
      );
    }

    // Downgrade / replay. A strictly older version is an attempted rollback to
    // a weaker policy; an identical version re-presented after the fact is a
    // replay. Both are reported, and neither is adopted.
    if (heldVersion != null) {
      if (envelope.version < heldVersion) {
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [
            TrustEvidence(
              TrustEvidenceCode.configDowngrade,
              detail: 'offered configuration is older than the one in force',
            ),
          ],
        );
      }
      // Replay is the *same version number carrying a different document*.
      // The steady state — holding exactly the version that is in force — is
      // not replay, so this needs both ids to compare; without a held id there
      // is nothing to contradict and no claim is made.
      if (envelope.version == heldVersion &&
          heldConfigId != null &&
          heldConfigId.isNotEmpty &&
          envelope.configId != null &&
          envelope.configId != heldConfigId) {
        evidence.add(const TrustEvidence(
          TrustEvidenceCode.configReplay,
          detail: 'a different configuration reuses the version in force',
        ));
      }
    }

    // Mutation: the values actually in force are not the values that were
    // delivered. Checked before expiry so a mutated *and* expired config
    // reports both facts.
    if (liveFingerprint != null && liveFingerprint != envelope.fingerprint()) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.configMutation,
        detail: 'in-force configuration differs from the delivered document',
      ));
    }

    final expiresAt = envelope.expiresAt;
    if (expiresAt != null && !now.isBefore(expiresAt)) {
      evidence.add(const TrustEvidence(TrustEvidenceCode.configExpired));
      return ConfigurationTrustVerdict(
        state: TrustAnchorState.expired,
        evidence: List.unmodifiable(evidence),
      );
    }

    // An issued-at in the future means the device clock and the server clock
    // disagree, or the document was fabricated. Not conclusive either way.
    final issuedAt = envelope.issuedAt;
    if (issuedAt != null && issuedAt.isAfter(now)) {
      evidence.add(const TrustEvidence(
        TrustEvidenceCode.configInvalid,
        detail: 'configuration is issued in the future',
      ));
      return ConfigurationTrustVerdict(
        state: TrustAnchorState.unknown,
        evidence: List.unmodifiable(evidence),
      );
    }

    if (evidence.isEmpty) {
      return const ConfigurationTrustVerdict(state: TrustAnchorState.valid);
    }
    return ConfigurationTrustVerdict(
      state: TrustAnchorState.mismatch,
      evidence: List.unmodifiable(evidence),
    );
  }

  /// The signature-aware path.
  ///
  /// ## Why authenticity is mapped first and the legacy rules still run
  ///
  /// A signature proves *who wrote the document*. It says nothing about
  /// whether the document is the newest one, nor about what happened to the
  /// values after they were applied in memory. So:
  ///
  /// * a cryptographic failure short-circuits — there is no point asking
  ///   whether a forged document is fresh;
  /// * a cryptographic **success** still runs the mutation check, because a
  ///   Frida script that pokes the in-force values changes nothing the
  ///   signature covers;
  /// * `legacyUnsigned` runs the full pre-signing rule set unchanged, then
  ///   records that it was never authenticated.
  ///
  /// Freshness and version policy (`expired`, `notYetValid`, `replay`,
  /// `downgrade`) are decided inside [SignedConfigVerifier] for signed
  /// documents, so they are not re-derived here — one decision site, not two
  /// that can drift apart.
  ConfigurationTrustVerdict _evaluateVerified({
    required SecurityConfigEnvelope envelope,
    required DateTime now,
    required SignedConfigVerification verification,
    int? heldVersion,
    String? heldConfigId,
    String? liveFingerprint,
  }) {
    switch (verification.result) {
      case ConfigVerificationResult.legacyUnsigned:
        // Existing customers keep working exactly as before — but the fact
        // that this configuration was never authenticated travels with the
        // assessment rather than being silently equated with a signed one.
        final legacy = evaluate(
          envelope: envelope,
          now: now,
          heldVersion: heldVersion,
          heldConfigId: heldConfigId,
          liveFingerprint: liveFingerprint,
        );
        return ConfigurationTrustVerdict(
          state: legacy.state,
          evidence: List.unmodifiable([
            ...legacy.evidence,
            const TrustEvidence(
              TrustEvidenceCode.configLegacyUnsigned,
              detail: 'configuration is not cryptographically authenticated',
            ),
          ]),
        );

      case ConfigVerificationResult.valid:
        final evidence = <TrustEvidence>[
          const TrustEvidence(TrustEvidenceCode.configSignatureValid),
        ];
        if (verification.key?.status == ConfigKeyStatus.next) {
          evidence.add(const TrustEvidence(
            TrustEvidenceCode.configKeyRotationPending,
            detail: 'verified with the incoming rotation key',
          ));
        }
        // Authenticity does not cover what happened after the document was
        // applied. This is the one check a signature cannot replace.
        if (liveFingerprint != null &&
            liveFingerprint != envelope.fingerprint()) {
          evidence.add(const TrustEvidence(
            TrustEvidenceCode.configMutation,
            detail: 'in-force configuration differs from the signed document',
          ));
          return ConfigurationTrustVerdict(
            state: TrustAnchorState.mismatch,
            evidence: List.unmodifiable(evidence),
          );
        }
        return ConfigurationTrustVerdict(
          state: TrustAnchorState.valid,
          evidence: List.unmodifiable(evidence),
        );

      case ConfigVerificationResult.invalidSignature:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [TrustEvidence(TrustEvidenceCode.configSignatureInvalid)],
        );

      case ConfigVerificationResult.unknownKey:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [TrustEvidence(TrustEvidenceCode.configUnknownKey)],
        );

      case ConfigVerificationResult.unsupportedAlgorithm:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [
            TrustEvidence(TrustEvidenceCode.configUnsupportedAlgorithm),
          ],
        );

      case ConfigVerificationResult.malformed:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [TrustEvidence(TrustEvidenceCode.configMalformed)],
        );

      case ConfigVerificationResult.replay:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [TrustEvidence(TrustEvidenceCode.configReplay)],
        );

      case ConfigVerificationResult.downgrade:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.mismatch,
          evidence: [TrustEvidence(TrustEvidenceCode.configDowngrade)],
        );

      case ConfigVerificationResult.expired:
        // Its own state, never folded into valid and never into mismatch —
        // an expired policy is a different operational problem from a forged
        // one, and the distinction is what an operator acts on.
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.expired,
          evidence: [TrustEvidence(TrustEvidenceCode.configExpired)],
        );

      case ConfigVerificationResult.notYetValid:
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.unknown,
          evidence: [TrustEvidence(TrustEvidenceCode.configNotYetValid)],
        );

      case ConfigVerificationResult.error:
        // ERROR is never SAFE.
        return const ConfigurationTrustVerdict(
          state: TrustAnchorState.error,
          evidence: [
            TrustEvidence(
              TrustEvidenceCode.configInvalid,
              detail: 'configuration verification could not complete',
            ),
          ],
        );
    }
  }
}
