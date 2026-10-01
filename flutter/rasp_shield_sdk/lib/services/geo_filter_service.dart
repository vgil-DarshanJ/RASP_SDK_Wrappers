import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

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

  /// `true` when the API's own `proxy` field reported this connection as a
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
  /// Countries this check blocks. Kept in one place so
  /// [checkHighRiskIp] and any future evidence-reporting stays in sync with
  /// what actually gets flagged.
  static const _blockedCountries = ['KP', 'IR', 'SY'];

  /// Check if the current IP belongs to a high-risk country or a known
  /// VPN/Proxy.
  ///
  /// **Preserved unchanged** for backward compatibility — the previous
  /// milestone's `rasp_service.dart` (dead code, but still compiled) and any
  /// external caller depend on this exact signature and fail-open-on-error
  /// behaviour. New callers that want to know *which* signal fired should use
  /// [checkHighRiskIp] instead.
  static Future<bool> isHighRiskIp() async {
    final result = await checkHighRiskIp();
    return result.isRisk;
  }

  /// Structured version of [isHighRiskIp], reporting which independent
  /// signal(s) contributed to the verdict.
  ///
  /// [isRisk] stays `false` on a failed lookup — a customer with a slow or
  /// unreliable connection must not be *blocked* because an optional geo-IP
  /// lookup timed out (unchanged from the original implementation). What
  /// changed: [HighRiskIpResult.checkFailed] now distinguishes "looked and
  /// found nothing" from "could not look" (network error, timeout, non-200,
  /// or the debug-mode skip below), so [HighRiskIpDetector] reports
  /// `UNAVAILABLE` rather than silently folding a failed check into
  /// `SECURE` — the same class of bug [DeviceFingerprintService] was
  /// already fixed for; this closes the same gap here. See
  /// `docs/DETECTOR_FAILURE_HANDLING.md`.
  static Future<HighRiskIpResult> checkHighRiskIp() async {
    if (kDebugMode) return HighRiskIpResult.unavailable; // Skip in debug

    try {
      final dio = Dio(
        BaseOptions(
          // Hard timeouts so a slow/unreachable network can never hang the scan.
          connectTimeout: const Duration(seconds: 5),
          receiveTimeout: const Duration(seconds: 5),
          sendTimeout: const Duration(seconds: 5),
        ),
      );
      // Using a free IP info API for demonstration
      // In production, use a professional service like ipstack, cloudflare, or maxmind
      final response = await dio.get('https://ipapi.co/json/');

      if (response.statusCode == 200) {
        final data = response.data;
        final country = data['country_code'] as String?;
        final matchedCountry = _blockedCountries.contains(country);
        final isProxy = data['proxy'] == true;
        return HighRiskIpResult(
          isRisk: matchedCountry || isProxy,
          matchedBlockedCountry: matchedCountry,
          isProxy: isProxy,
        );
      }
      return HighRiskIpResult.unavailable;
    } catch (e) {
      // isRisk stays false (never blocks on a flaky network) — checkFailed
      // is what lets the caller tell this apart from a genuine clean result.
      return HighRiskIpResult.unavailable;
    }
  }
}
