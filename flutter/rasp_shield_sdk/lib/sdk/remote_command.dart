import 'dart:convert';

import 'package:flutter/foundation.dart';

/// One operator-issued remote command, as delivered in the heartbeat response's
/// `pending_commands` array (`{id, type, payload}`) by the existing backend.
///
/// This is a pure data holder — parsing only, no behaviour — so it can be
/// unit-tested without a device or network.
@immutable
class RemoteCommand {
  /// The command types this SDK build understands. `WIPE_LOCAL_DATA` is
  /// recognised so it can be acknowledged as unsupported, but is deliberately
  /// **not** executed yet (out of scope).
  static const String forceRescan = 'FORCE_RESCAN';
  static const String showMessage = 'SHOW_MESSAGE';
  static const String lockApp = 'LOCK_APP';
  static const String wipeLocalData = 'WIPE_LOCAL_DATA';

  /// Persistent Remote Lock Enforcement milestone — the one documented
  /// recovery path for a persisted `LOCK_APP`. Reuses the exact same
  /// authenticated-request boundary [lockApp] already goes through
  /// (backend command queue → signed heartbeat → dispatcher) — forging an
  /// unlock is exactly as hard as forging a lock, not easier.
  static const String unlockApp = 'UNLOCK_APP';

  final int id;
  final String type;
  final Map<String, dynamic> payload;

  /// Cryptographic Remote Command Integrity milestone — the fields the
  /// backend's `remote_command_integrity.compute_command_signature` now
  /// binds together. All `null` for a command from a backend that predates
  /// this milestone (never fabricated) — see `RemoteCommandVerifier`, which
  /// treats that as [RemoteCommandVerdict.missing], not a pass.
  final String? deviceId;
  final String? applicationId;
  final String? issuedAt;
  final String? nonce;
  final String? signature;
  final String? expiresAt;

  const RemoteCommand({
    required this.id,
    required this.type,
    this.payload = const {},
    this.deviceId,
    this.applicationId,
    this.issuedAt,
    this.nonce,
    this.signature,
    this.expiresAt,
  });

  /// Whether every integrity field this command needs to be verified is
  /// present (not whether the signature is actually VALID — that is
  /// [RemoteCommandVerifier]'s job).
  bool get hasIntegrityFields =>
      deviceId != null &&
      deviceId!.isNotEmpty &&
      applicationId != null &&
      applicationId!.isNotEmpty &&
      issuedAt != null &&
      issuedAt!.isNotEmpty &&
      nonce != null &&
      nonce!.isNotEmpty &&
      signature != null &&
      signature!.isNotEmpty;

  /// Cryptographic Remote Command Integrity milestone, Phase 14 — a resource
  /// bound on the raw payload, checked before anything else touches it
  /// (canonicalization, digest computation, signature comparison). Without
  /// this, an attacker who can inject or tamper with a plain-HTTP heartbeat
  /// response — the exact threat this milestone's signature defends
  /// against — could still force this device to spend real CPU/memory
  /// canonicalizing and hashing an arbitrarily large payload before the
  /// (ultimately failing) signature check ever runs. Generous relative to
  /// every legitimate payload this SDK actually sends today (`{message}`/
  /// `{title}`/`{reason}`, each well under 2KB) — this is a resource-abuse
  /// ceiling, not a product constraint.
  static const int maxPayloadJsonLength = 8192;

  /// Parse one raw `pending_commands` entry, or `null` if it is malformed
  /// OR exceeds the resource bound above.
  ///
  /// Only the pre-existing shape (`id`, `type`, `payload`) is required to
  /// parse at all — the new integrity fields are read opportunistically.
  /// A command missing them still parses (so a genuinely malformed integrity
  /// field, e.g. one containing the canonical `|` delimiter, is reported by
  /// [RemoteCommandVerifier] as a verification failure, not silently
  /// swallowed here as if the whole command never arrived).
  static RemoteCommand? tryParse(dynamic raw) {
    if (raw is! Map) return null;
    final rawId = raw['id'];
    final id = rawId is int ? rawId : (rawId is num ? rawId.toInt() : null);
    final type = raw['type'];
    if (id == null || type is! String || type.isEmpty) return null;
    final payload = raw['payload'];
    if (payload is Map) {
      try {
        if (jsonEncode(payload).length > maxPayloadJsonLength) return null;
      } catch (_) {
        // Not JSON-encodable at all — malformed, reject rather than guess.
        return null;
      }
    }
    return RemoteCommand(
      id: id,
      type: type,
      payload: payload is Map ? Map<String, dynamic>.from(payload) : const {},
      deviceId: _stringOrNull(raw['device_id']),
      applicationId: _stringOrNull(raw['application_id']),
      issuedAt: _stringOrNull(raw['issued_at']),
      nonce: _stringOrNull(raw['nonce']),
      signature: _stringOrNull(raw['signature']),
      expiresAt: _stringOrNull(raw['expires_at']),
    );
  }

  static String? _stringOrNull(dynamic value) =>
      value is String && value.isNotEmpty ? value : null;
}

/// A SHOW_MESSAGE to surface to the user, carried as observable dispatcher state.
@immutable
class RemoteMessage {
  final int commandId;
  final String? title;
  final String body;

  const RemoteMessage({
    required this.commandId,
    required this.body,
    this.title,
  });
}

/// Whether a LOCK_APP is currently in force, plus the message to show.
@immutable
class RemoteLockState {
  final bool locked;
  final String reason;

  const RemoteLockState._(this.locked, this.reason);
  const RemoteLockState.unlocked() : this._(false, '');
  const RemoteLockState.locked({required String reason}) : this._(true, reason);
}
