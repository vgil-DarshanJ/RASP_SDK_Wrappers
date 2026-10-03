import '../sdk/detectors/rasp_native_channel.dart';

/// Structured result of a geo/IP-reputation check, carrying which of the
/// independent signals fired rather than collapsing them into one boolean.
///
/// [matchedBlockedCountry] and [isProxy] are genuinely independent: the API
/// response can name a blocked country, flag the connection as a known
/// proxy/VPN exit, both, or neither. Reporting only `isRisk` (the previous
/// public API, still available via [GeoFilterService.isHighRiskIp]) discarded
/// which one — and whether one or two signals agreed — before it ever reached
/// a `DetectionResult`.
class HighRiskIpResult {
  final bool isRisk;

  /// `true` when the resolved country code matched the blocked list.
  final bool matchedBlockedCountry;

  /// `true` when the backend's `proxy` flag reported this connection as a
  /// known proxy/VPN exit.
  final bool isProxy;

  /// `true` when the lookup itself did not complete (network error, timeout,
  /// non-200 response) — distinct from a lookup that ran and found nothing.
  /// Added so [HighRiskIpDetector] can report `UNAVAILABLE` instead of
  /// silently folding "could not check" into "checked, clean" — see
  /// `docs/DETECTOR_FAILURE_HANDLING.md`. [isRisk] stays `false` in both
  /// cases, unchanged, so [GeoFilterService.isHighRiskIp] (the preserved
  /// legacy boolean API) is byte-for-byte unaffected by this field's
  /// existence.
  final bool checkFailed;

  const HighRiskIpResult({
    required this.isRisk,
    required this.matchedBlockedCountry,
    required this.isProxy,
    this.checkFailed = false,
  });

  static const HighRiskIpResult clean = HighRiskIpResult(
    isRisk: false,
    matchedBlockedCountry: false,
    isProxy: false,
  );

  static const HighRiskIpResult unavailable = HighRiskIpResult(
    isRisk: false,
    matchedBlockedCountry: false,
    isProxy: false,
    checkFailed: true,
  );
}

class GeoFilterService {
  /// Check if the current IP belongs to a high-risk country or a known
  /// VPN/Proxy.
  ///
  /// **Preserved** for backward compatibility: same signature, and still
  /// `false` when the check could not run. New callers that want to know
  /// *which* signal fired should use [checkHighRiskIp] instead.
  static Future<bool> isHighRiskIp() async {
    final result = await checkHighRiskIp();
    return result.isRisk;
  }

  /// Structured version of [isHighRiskIp].
  ///
  /// Asks the native engine, which asks the RASP Shield backend
  /// (`GET /v1/ip-risk`, HMAC-signed with the credential given to
  /// `RaspSecurityEventShipper.configure`). The backend uses the request IP
  /// and its own blocked-country list. The device makes no third-party call,
  /// and there is no debug-build skip.
  ///
  /// [HighRiskIpResult.checkFailed] is `true` whenever the engine could not
  /// decide (no credential, request failed, country unknown) or the native
  /// layer did not answer; [HighRiskIpResult.isRisk] stays `false` then, so a
  /// flaky network never blocks a customer. See
  /// `docs/DETECTOR_FAILURE_HANDLING.md`.
  static Future<HighRiskIpResult> checkHighRiskIp() async {
    final raw = await RaspNativeChannel.mapCall('checkHighRiskIp');
    if (raw == null) return HighRiskIpResult.unavailable;
    final signals = <String>{
      for (final entry in (raw['evidence'] as List?) ?? const [])
        if (entry is Map && entry['key'] == 'high_risk_ip_signal') '${entry['value']}',
    };
    switch (raw['status']) {
      case 'DETECTED':
        return HighRiskIpResult(
          isRisk: true,
          matchedBlockedCountry: signals.contains('blocked_country'),
          isProxy: signals.contains('proxy_flag'),
        );
      case 'SECURE':
        return HighRiskIpResult.clean;
      default:
        return HighRiskIpResult.unavailable;
    }
  }
}
