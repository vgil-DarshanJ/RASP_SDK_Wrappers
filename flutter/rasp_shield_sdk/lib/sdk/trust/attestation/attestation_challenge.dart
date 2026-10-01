/// A server-issued attestation challenge.
///
/// Mirrors the existing activation nonce (`/api/v1/sdk/challenge`,
/// `activation_nonces` table) deliberately: the same "single-use,
/// device+bundle-bound, server-issued, expiring" shape already solves this
/// exact problem for the licensing handshake. Attestation gets its own type
/// (not a reused `String nonce`) because a challenge also carries binding
/// context the caller must present alongside the resulting assertion.
class AttestationChallenge {
  /// Opaque, single-use, server-generated. Never derived from anything a
  /// client controls — see `attestation_router.py::request_challenge`.
  final String nonce;

  /// The bundle id this challenge is bound to. An attestation whose reported
  /// [AttestationResult.packageIdentity] does not match this is a binding
  /// failure, never silently accepted.
  final String bundleId;

  /// The device id this challenge is bound to.
  final String deviceId;

  final DateTime issuedAt;
  final DateTime expiresAt;

  const AttestationChallenge({
    required this.nonce,
    required this.bundleId,
    required this.deviceId,
    required this.issuedAt,
    required this.expiresAt,
  });

  bool isExpired({DateTime? now}) => (now ?? DateTime.now()).toUtc().isAfter(expiresAt.toUtc());

  factory AttestationChallenge.fromJson(Map<String, dynamic> json) => AttestationChallenge(
        nonce: json['nonce'] as String,
        bundleId: json['bundle_id'] as String,
        deviceId: json['device_id'] as String,
        issuedAt: DateTime.parse(json['issued_at'] as String).toUtc(),
        expiresAt: DateTime.parse(json['expires_at'] as String).toUtc(),
      );

  Map<String, Object?> toJson() => {
        'nonce': nonce,
        'bundle_id': bundleId,
        'device_id': deviceId,
        'issued_at': issuedAt.toUtc().toIso8601String(),
        'expires_at': expiresAt.toUtc().toIso8601String(),
      };
}
