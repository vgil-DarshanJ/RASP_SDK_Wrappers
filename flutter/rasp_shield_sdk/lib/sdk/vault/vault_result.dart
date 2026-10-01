/// Secure Vault milestone — the typed result `RaspShield.vault.get()` returns.
///
/// Never `null` for "unavailable/unknown" — see [VaultSecretState]'s doc.
/// Every state carries a [VaultResult.reason] string so a caller (and a
/// support engineer reading a log) always knows *why*, not just *that*
/// something did not come back.
library;

/// Every outcome a vault retrieval can have. Deliberately exhaustive so a
/// caller's `switch` is checked by the compiler, not by remembering to
/// handle "the fifth case nobody thought about".
enum VaultSecretState {
  /// The secret was retrieved and [VaultResult.value] is set.
  available,

  /// Policy denied this device/app/risk combination. Not an error — the
  /// system worked exactly as configured.
  denied,

  /// The version this device would have received has passed its grace
  /// period. A rotation happened; nothing is currently wrong with the app.
  expired,

  /// The version was explicitly revoked (emergency response). Treat this
  /// as urgent — the credential this app was using is no longer trusted.
  revoked,

  /// No secret with this name exists for this application/environment.
  /// Almost always a configuration mistake (typo, wrong environment), not
  /// a security event.
  notConfigured,

  /// The backend could not be reached, or answered with something this
  /// SDK could not interpret. Transient — retry on the next cycle.
  unavailable,
}

extension VaultSecretStateX on VaultSecretState {
  static VaultSecretState fromWire(String? wire) {
    switch (wire) {
      case 'AVAILABLE':
        return VaultSecretState.available;
      case 'DENIED':
        return VaultSecretState.denied;
      case 'EXPIRED':
        return VaultSecretState.expired;
      case 'REVOKED':
        return VaultSecretState.revoked;
      case 'NOT_CONFIGURED':
        return VaultSecretState.notConfigured;
      default:
        return VaultSecretState.unavailable;
    }
  }
}

/// The result of one `RaspShield.vault.get(name)` call.
///
/// [value] is non-null **only** when [state] is
/// [VaultSecretState.available] — checked by [VaultResult.available]'s
/// factory constructor, not left to caller discipline.
class VaultResult {
  final VaultSecretState state;
  final String reason;
  final String secretName;
  final int? version;
  final String? value;
  final DateTime? expiresAt;

  /// Whether the value returned was served from the on-device cache
  /// (network unreachable) rather than a fresh backend response — Phase 23
  /// (Offline Security). A caller that needs to know can check this; most
  /// callers never need to.
  final bool servedFromOfflineCache;

  const VaultResult._({
    required this.state,
    required this.reason,
    required this.secretName,
    this.version,
    this.value,
    this.expiresAt,
    this.servedFromOfflineCache = false,
  });

  factory VaultResult.available({
    required String secretName,
    required String value,
    required int version,
    DateTime? expiresAt,
    bool servedFromOfflineCache = false,
  }) =>
      VaultResult._(
        state: VaultSecretState.available,
        reason: servedFromOfflineCache ? 'OFFLINE_CACHE' : 'OK',
        secretName: secretName,
        version: version,
        value: value,
        expiresAt: expiresAt,
        servedFromOfflineCache: servedFromOfflineCache,
      );

  factory VaultResult.unavailable(String secretName, {String reason = 'UNAVAILABLE'}) =>
      VaultResult._(
        state: VaultSecretState.unavailable,
        reason: reason,
        secretName: secretName,
      );

  factory VaultResult.fromWire(Map<String, Object?> wire) {
    final state = VaultSecretStateX.fromWire(wire['status'] as String?);
    return VaultResult._(
      state: state,
      reason: (wire['reason'] as String?) ?? 'UNKNOWN',
      secretName: (wire['secret_name'] as String?) ?? '',
      version: wire['version'] as int?,
      value: state == VaultSecretState.available ? wire['value'] as String? : null,
      expiresAt: _parseIso(wire['expires_at'] as String?),
    );
  }

  static DateTime? _parseIso(String? raw) {
    if (raw == null) return null;
    try {
      return DateTime.parse(raw).toUtc();
    } catch (_) {
      return null;
    }
  }

  @override
  String toString() =>
      'VaultResult(secret=$secretName, state=$state, reason=$reason, version=$version)';
  // Deliberately never includes `value` — see docs/SECURE_VAULT.md
  // "No Secret Leakage" §: a stray `print(result)`/log interpolation must
  // not become a way to leak the secret it is describing.
}
