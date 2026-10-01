import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'security_event_queue.dart';

/// Real, production [SecurityEventQueueStore] — Keystore-backed encrypted
/// storage, the same `flutter_secure_storage` configuration
/// `RemoteConfigManager`'s protection-policy cache already uses ("the
/// document that decides whether the app locks itself... prefs are
/// world-readable on a rooted device — precisely the device this SDK
/// exists to detect").
///
/// ## The actual guarantee, stated precisely
///
/// This makes the queue survive an ordinary app-process kill (backgrounded
/// and reaped, force-stopped and relaunched, a crash) — [save] is called
/// after every mutation and [load] replays it on the next [restore]. It
/// does **not** guarantee zero loss under every possible platform
/// termination: a `save` that is still in flight (an async platform-channel
/// write) when the OS kills the process without running any shutdown hook
/// can still lose that one write, and an event enqueued and immediately
/// followed by an unclean kill before the write is even issued is lost the
/// same way it always would have been. Never claim more than this — see
/// `docs/CONTINUOUS_SECURITY_TELEMETRY.md`'s "Offline Queue Guarantee"
/// section for the exact wording this mirrors.
class SecureSecurityEventQueueStore implements SecurityEventQueueStore {
  static const _key = 'rasp_sdk_security_event_queue';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  const SecureSecurityEventQueueStore();

  /// In-memory override so a test can drive this store with no platform
  /// channel — the same `testValues` seam
  /// `SecurityEventSequenceStore`/`EnforcementStateStore` already use.
  /// Test-only, never set by production code.
  ///
  /// **Why this exists, not just a caught exception**: a real device with
  /// no plugin registered gets a fast `MissingPluginException` here, same
  /// as everywhere else in this SDK — but a Flutter *widget* test
  /// (`TestWidgetsFlutterBinding`, `defaultTargetPlatform` defaulting to
  /// Android) can instead leave the platform-channel `Future` never
  /// completing, which a `pumpAndSettle()` then waits on for its full
  /// timeout. Every other secure-storage touchpoint in this SDK
  /// (`SecurityEventSequenceStore`, `EnforcementStateStore`,
  /// `RemoteCommandExecutionLedger`) already learned this the same way —
  /// see `remote_command_host_test.dart`'s own setUp comment for the prior
  /// three. This is the fourth, closing the same gap for the newest store.
  @visibleForTesting
  static Map<String, String>? testValues;

  @override
  Future<void> save(List<QueuedSecurityEvent> entries) async {
    final encoded = jsonEncode(entries.map((e) => e.toMap()).toList());
    final values = testValues;
    if (values != null) {
      values[_key] = encoded;
      return;
    }
    try {
      await _storage.write(key: _key, value: encoded);
    } catch (e) {
      // A failed persist must never crash or block the scan/heartbeat that
      // triggered it — the in-memory queue (this call's caller) remains
      // authoritative for the rest of this process's lifetime regardless.
      debugPrint('[RASP-TRACE] SECURITY-EVENT-QUEUE persist failed: $e');
    }
  }

  @override
  Future<List<QueuedSecurityEvent>> load() async {
    final values = testValues;
    final raw = values != null ? values[_key] : await _readReal();
    if (raw == null || raw.isEmpty) return const [];
    try {
      final decoded = jsonDecode(raw);
      if (decoded is! List) return const [];
      final restored = <QueuedSecurityEvent>[];
      for (final item in decoded) {
        if (item is! Map) continue;
        final entry = QueuedSecurityEvent.fromMap(
          item.map((k, v) => MapEntry(k.toString(), v)),
        );
        if (entry != null) restored.add(entry);
      }
      return restored;
    } catch (e) {
      debugPrint('[RASP-TRACE] SECURITY-EVENT-QUEUE restore failed: $e');
      return const [];
    }
  }

  Future<String?> _readReal() async {
    try {
      return await _storage.read(key: _key);
    } catch (e) {
      debugPrint('[RASP-TRACE] SECURITY-EVENT-QUEUE restore failed: $e');
      return null;
    }
  }

  @override
  Future<void> clear() async {
    final values = testValues;
    if (values != null) {
      values.remove(_key);
      return;
    }
    try {
      await _storage.delete(key: _key);
    } catch (_) {
      // Nothing further to do — the next save() overwrites whatever is
      // there anyway.
    }
  }
}
