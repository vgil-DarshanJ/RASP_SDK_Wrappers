import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// At-rest cache for provisioned vault secrets — Keystore-backed encrypted
/// storage, the same `flutter_secure_storage` configuration
/// `SecureSecurityEventQueueStore`/`RemoteConfigManager` already use. See
/// those classes' docs for the exact, honest guarantee this provides (not
/// "impossible to extract from a fully compromised device" — see
/// `docs/SECURE_VAULT.md`'s threat model).
///
/// One entry per `(secretName, environment)`, keyed so a cached credential
/// never needs to be re-fetched merely to read it back before its own TTL
/// (`VaultResult.expiresAt`, itself policy-driven server-side) expires —
/// minimizing both plaintext-in-memory time and provisioning-request
/// volume without ever caching past what policy allows.
///
/// **Never store plaintext in `SharedPreferences`** — this class exists
/// specifically because that would be Phase 8's forbidden path.
class SecureVaultStore {
  static const _keyPrefix = 'rasp_sdk_vault_';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  const SecureVaultStore();

  /// In-memory override so a test can drive this store with no platform
  /// channel — the same `testValues` seam every other secure-storage
  /// touchpoint in this SDK already uses (see
  /// `SecureSecurityEventQueueStore.testValues`'s doc for exactly why this
  /// is needed, not merely a caught exception).
  @visibleForTesting
  static Map<String, String>? testValues;

  static String _key(String secretName, String environment) =>
      '$_keyPrefix${environment}_$secretName';

  Future<void> save({
    required String secretName,
    required String environment,
    required String value,
    required int version,
    required DateTime expiresAt,
    required bool offlineAllowed,
    required int offlineMaxAgeSeconds,
  }) async {
    final encoded = jsonEncode({
      'value': value,
      'version': version,
      'expires_at': expiresAt.toUtc().toIso8601String(),
      'cached_at': DateTime.now().toUtc().toIso8601String(),
      'offline_allowed': offlineAllowed,
      'offline_max_age_seconds': offlineMaxAgeSeconds,
    });
    final key = _key(secretName, environment);
    final values = testValues;
    if (values != null) {
      values[key] = encoded;
      return;
    }
    try {
      await _storage.write(key: key, value: encoded);
    } catch (e) {
      // A failed cache write must never block the caller — the value this
      // call just fetched is still returned to it; only the NEXT call
      // (which would have reused the cache) pays the cost of a re-fetch.
      debugPrint('[RASP-TRACE] VAULT-STORE persist failed: $e');
    }
  }

  /// Returns the raw cached record, or `null` if there is nothing cached or
  /// it is malformed. Deliberately does **not** itself decide whether the
  /// entry is still usable — a caller has two different questions to ask of
  /// the same record (“is it still fresh enough to skip a network call” vs
  /// “is it still usable now that the network is unreachable”), governed by
  /// different policy fields (`expiresAt` vs `offlineMaxAgeSeconds`), so
  /// `VaultClient` makes that call, not this store.
  Future<CachedVaultEntry?> load({
    required String secretName,
    required String environment,
  }) async {
    final key = _key(secretName, environment);
    final values = testValues;
    String? raw;
    if (values != null) {
      raw = values[key];
    } else {
      try {
        raw = await _storage.read(key: key);
      } catch (e) {
        debugPrint('[RASP-TRACE] VAULT-STORE read failed: $e');
        return null;
      }
    }
    if (raw == null || raw.isEmpty) return null;
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return null;
      return CachedVaultEntry(
        value: decoded['value'] as String,
        version: decoded['version'] as int,
        expiresAt: DateTime.parse(decoded['expires_at'] as String).toUtc(),
        cachedAt: DateTime.parse(decoded['cached_at'] as String).toUtc(),
        offlineAllowed: decoded['offline_allowed'] as bool? ?? false,
        offlineMaxAgeSeconds: decoded['offline_max_age_seconds'] as int? ?? 0,
      );
    } catch (e) {
      debugPrint('[RASP-TRACE] VAULT-STORE decode failed: $e');
      return null;
    }
  }

  Future<void> clear({required String secretName, required String environment}) async {
    final key = _key(secretName, environment);
    final values = testValues;
    if (values != null) {
      values.remove(key);
      return;
    }
    try {
      await _storage.delete(key: key);
    } catch (_) {
      // Nothing further to do.
    }
  }
}

/// One cached, on-device copy of a provisioned secret plus the policy
/// facts needed to decide whether it may still be used.
class CachedVaultEntry {
  final String value;
  final int version;
  final DateTime expiresAt;
  final DateTime cachedAt;
  final bool offlineAllowed;
  final int offlineMaxAgeSeconds;

  const CachedVaultEntry({
    required this.value,
    required this.version,
    required this.expiresAt,
    required this.cachedAt,
    required this.offlineAllowed,
    required this.offlineMaxAgeSeconds,
  });

  /// Fresh enough that a caller need not make a network call at all.
  bool isFresh(DateTime at) => expiresAt.isAfter(at);

  /// Usable as a **last-resort offline fallback** — only when the secret's
  /// own policy explicitly allows offline use, and only within the age
  /// bound that same policy set. A secret whose policy never enabled
  /// offline use returns `false` here even if [isFresh] would say yes,
  /// because [isFresh] governs "skip a redundant network call", not
  /// "network is down, is this still allowed at all" — two different
  /// questions, Phase 23's whole point.
  bool isUsableOffline(DateTime at) {
    if (!offlineAllowed) return false;
    if (offlineMaxAgeSeconds <= 0) return false;
    return at.difference(cachedAt).inSeconds <= offlineMaxAgeSeconds;
  }
}
