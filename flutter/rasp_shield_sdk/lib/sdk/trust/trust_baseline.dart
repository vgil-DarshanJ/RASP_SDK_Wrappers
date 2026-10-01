import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// The application identity this install observed when its seat was
/// established.
///
/// Exists to make the post-activation identity re-check possible at all: the
/// audit found identity is verified once, server-side, at activation and never
/// re-checked locally afterwards. Something has to remember what "correct"
/// looked like, and it must survive a restart.
///
/// Stored in Keystore-backed secure storage rather than SharedPreferences for
/// the same reason `RemoteConfigManager` keeps the protection policy there:
/// prefs are world-readable on a rooted device — precisely the device this
/// SDK exists to detect. This is a speed bump, not a guarantee; an attacker
/// with full device control can still rewrite the baseline, at which point the
/// anchor reports agreement with a value they chose. That is why the runtime
/// identity anchor may only ever *withdraw* trust and never confer it (see
/// `docs/TRUST_ANCHOR_MODEL.md` §2.3).
class TrustBaseline {
  final String? applicationId;
  final String? certificateFingerprint;

  const TrustBaseline({this.applicationId, this.certificateFingerprint});

  static const TrustBaseline empty = TrustBaseline();

  bool get isEmpty =>
      (applicationId == null || applicationId!.isEmpty) &&
      (certificateFingerprint == null || certificateFingerprint!.isEmpty);

  Map<String, Object?> toJson() => {
        if (applicationId != null) 'application_id': applicationId,
        if (certificateFingerprint != null)
          'certificate_fingerprint': certificateFingerprint,
      };

  static TrustBaseline fromJson(Map<String, dynamic> json) => TrustBaseline(
        applicationId: json['application_id'] as String?,
        certificateFingerprint: json['certificate_fingerprint'] as String?,
      );
}

/// Persistence for [TrustBaseline].
class TrustBaselineStore {
  static const _key = 'rasp_sdk_trust_baseline';
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
  );

  static TrustBaseline? _cached;

  /// The stored baseline, or [TrustBaseline.empty] when none has been
  /// captured. Never throws: an unreadable store means "no baseline", which
  /// makes the runtime anchor `unavailable` — not a pass.
  static Future<TrustBaseline> read() async {
    final cached = _cached;
    if (cached != null) return cached;
    try {
      final raw = await _storage.read(key: _key);
      if (raw == null || raw.isEmpty) return TrustBaseline.empty;
      final decoded = jsonDecode(raw);
      if (decoded is! Map) return TrustBaseline.empty;
      final baseline = TrustBaseline.fromJson(Map<String, dynamic>.from(decoded));
      _cached = baseline;
      return baseline;
    } catch (_) {
      return TrustBaseline.empty;
    }
  }

  /// Records the baseline, if one is not already recorded.
  ///
  /// **Write-once by design.** Overwriting on every launch would defeat the
  /// anchor entirely: an attacker's repackaged build would simply record its
  /// own identity as the baseline and then agree with itself forever. A
  /// legitimate identity change — a signing-key rotation — is handled by the
  /// certificate trust store's rotation window instead, which is
  /// operator-controlled rather than self-asserted.
  static Future<void> captureIfAbsent(TrustBaseline baseline) async {
    if (baseline.isEmpty) return;
    final existing = await read();
    if (!existing.isEmpty) return;
    try {
      await _storage.write(key: _key, value: jsonEncode(baseline.toJson()));
      _cached = baseline;
    } catch (_) {
      // In-memory copy still serves this session; the next launch retries.
      _cached = baseline;
    }
  }

  /// Clears the stored baseline. Used by factory reset and by tests.
  static Future<void> reset() async {
    _cached = null;
    try {
      await _storage.delete(key: _key);
    } catch (_) {
      // Best effort.
    }
  }
}
