/// Which platform produced an attestation.
enum AttestationPlatform { android, ios }

/// Which attestation provider produced a result.
///
/// `none` exists so "no provider was even attempted" (e.g. this platform has
/// no attestation implementation) is representable without a nullable
/// provider field scattered through every consumer.
enum AttestationProvider { playIntegrity, appAttest, none }

/// The verdict for one attestation check.
///
/// Seven states, not a boolean — mirrors the discipline every other trust
/// primitive in this SDK already follows (`DetectionStatus`,
/// `TrustAnchorState`, `ConfigVerificationResult`). `valid` is the only state
/// meaning "this attestation may be believed"; every other state is either a
/// failure or an absence of information, and none of them are ever folded
/// into `valid`.
enum AttestationStatus {
  /// Verified: genuine, fresh, correctly bound, and reporting device/app
  /// integrity the caller's policy accepts.
  valid,

  /// Verified as genuine, but the reported integrity verdicts themselves are
  /// bad (e.g. Play Integrity's `deviceRecognitionVerdict` came back empty,
  /// or App Attest's receipt failed) — the attestation mechanism worked and
  /// told us the device/app is not trustworthy.
  invalid,

  /// Was valid once; the assertion/token's validity window has passed.
  expired,

  /// This exact assertion/token (or its nonce) was already consumed —
  /// presented again.
  replayed,

  /// Structurally unusable, or a check could not conclusively resolve
  /// (e.g. issued outside tolerated clock skew).
  unknown,

  /// No attestation was attempted or possible: unsupported platform, no
  /// native implementation registered, Play Services/Secure Enclave
  /// unavailable, or the SDK build has no provider configured.
  unavailable,

  /// The attestation flow (native call, network call, parsing) threw.
  error,
}

/// Semantics for [AttestationStatus].
extension AttestationStatusX on AttestationStatus {
  /// The single state meaning "this attestation may be trusted." One
  /// definition site, so the ERROR/UNKNOWN/UNAVAILABLE-never-VALID fail-safe
  /// rules cannot drift — the same pattern
  /// `TrustAnchorStateX.isSatisfied`/`ConfigVerificationResultX.isAuthenticated`
  /// already use.
  bool get isTrusted => this == AttestationStatus.valid;

  /// No verdict was reached — neither a pass nor a threat signal.
  bool get isIndeterminate =>
      this == AttestationStatus.unknown ||
      this == AttestationStatus.unavailable ||
      this == AttestationStatus.error;

  String get wireName => name.toUpperCase();
}

/// One fact an attestation provider reported about app or device integrity.
///
/// Deliberately a free-form `(category, value)` pair rather than a fixed
/// enum: Play Integrity's verdict vocabulary
/// (`MEETS_DEVICE_INTEGRITY`/`MEETS_BASIC_INTEGRITY`/…) and App Attest's
/// (receipt validity, counter state) are platform-specific and Google/Apple
/// both reserve the right to add new verdict values — an enum here would
/// need editing every time either platform does. The *normalization* layer
/// (`play_integrity_verdict_parser.dart` / `app_attest_verdict_parser.dart`)
/// is where platform-specific meaning is interpreted into [AttestationStatus].
class AttestationEvidence {
  final String category;
  final String value;

  const AttestationEvidence(this.category, this.value);

  Map<String, Object?> toMap() => {'category': category, 'value': value};

  @override
  String toString() => '$category=$value';

  @override
  bool operator ==(Object other) =>
      other is AttestationEvidence &&
      other.category == category &&
      other.value == value;

  @override
  int get hashCode => Object.hash(category, value);
}

/// A platform-neutral attestation verdict — the type every consumer
/// (`TrustEngine`, the backend verification contract, tests) actually works
/// with, regardless of whether it originated from Play Integrity or App
/// Attest.
///
/// ## Never carries a secret
///
/// No raw token, assertion bytes, or key material is ever placed on this
/// class — only normalized facts. The raw provider response is consumed
/// entirely inside the platform-specific parser that produces this object.
class AttestationResult {
  final AttestationPlatform platform;
  final AttestationProvider provider;
  final AttestationStatus status;

  /// Whether the *application* is judged genuine (correct package/bundle id,
  /// correct signing certificate) — Play Integrity's `appIntegrity`, App
  /// Attest's app-identity binding. `null` when the provider did not report
  /// this dimension (e.g. an error before that section was reached).
  final bool? appIntegrity;

  /// Whether the *device* is judged genuine (not rooted/jailbroken, not an
  /// emulator, meets the provider's hardware-integrity bar). `null` when not
  /// reported.
  final bool? deviceIntegrity;

  /// The signing certificate identity the attestation itself observed,
  /// normalized (bare uppercase hex) the same way
  /// `CertificateTrustStore.normalize` already does — so it can be compared
  /// against the same trust store without a second normalization rule.
  final String? signingIdentity;

  /// The package/bundle id the attestation itself observed.
  final String? packageIdentity;

  /// The challenge nonce this attestation was bound to. Central to replay
  /// protection — see `attestation_replay_guard.dart`.
  final String? nonce;

  /// When the provider says this attestation was produced.
  final DateTime? timestamp;

  /// Which App Attest key (iOS) or Play Integrity request context (Android)
  /// produced this — the identifier a key-lifecycle/rotation policy would
  /// key off. `null` for providers with no notion of a persistent key
  /// (Play Integrity has none; App Attest does).
  final String? keyId;

  /// Normalized facts from the provider. Never contains secrets — see the
  /// class doc.
  final List<AttestationEvidence> evidence;

  /// Set for [AttestationStatus.error]/[AttestationStatus.unavailable] —
  /// human-readable, never a raw exception or stack trace that could leak
  /// provider internals.
  final String? error;

  /// How much this verdict should be trusted, reusing the SDK's existing
  /// [DetectionConfidence]-shaped vocabulary is deliberately avoided here to
  /// keep this file free of a `core/` dependency; the trust-engine
  /// integration layer (`trust_engine.dart`) is responsible for mapping this
  /// into `DetectionConfidence` using the same rules every other anchor
  /// uses — see that file. This field is the platform/provider's own
  /// confidence signal where one exists (e.g. Play Integrity does not
  /// provide one; App Attest's receipt does not either) — `null` when the
  /// provider reports none, which is the case for both providers today.
  final double? providerConfidence;

  const AttestationResult({
    required this.platform,
    required this.provider,
    required this.status,
    this.appIntegrity,
    this.deviceIntegrity,
    this.signingIdentity,
    this.packageIdentity,
    this.nonce,
    this.timestamp,
    this.keyId,
    this.evidence = const [],
    this.error,
    this.providerConfidence,
  });

  /// The result for "no provider is configured/available on this platform."
  /// The honest default — never fabricated as `valid`.
  factory AttestationResult.unavailable({
    required AttestationPlatform platform,
    String? reason,
  }) =>
      AttestationResult(
        platform: platform,
        provider: AttestationProvider.none,
        status: AttestationStatus.unavailable,
        error: reason,
      );

  Map<String, Object?> toMap() => {
        'platform': platform.name,
        'provider': provider.name,
        'status': status.wireName,
        'app_integrity': appIntegrity,
        'device_integrity': deviceIntegrity,
        'signing_identity': signingIdentity,
        'package_identity': packageIdentity,
        'nonce': nonce,
        'timestamp': timestamp?.toUtc().toIso8601String(),
        'key_id': keyId,
        'evidence': evidence.map((e) => e.toMap()).toList(),
        if (error != null) 'error': error,
      };

  @override
  String toString() =>
      'AttestationResult(${platform.name}, ${provider.name}, ${status.wireName})';
}
