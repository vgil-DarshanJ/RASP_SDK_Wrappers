import '../activation_manager.dart';
import '../license_manager.dart';
import '../rasp_sdk.dart';
import 'ai_ask_result.dart';
import 'ai_use_case.dart';

/// `RaspShield.ai` — the developer-facing entry point for the Secure AI
/// Gateway.
///
/// ```dart
/// final result = await RaspShield.ai.ask(
///   'Explain the current security status of this device.',
/// );
/// if (result.ok) {
///   print(result.response);
/// }
/// ```
///
/// Every call is authenticated exactly like a heartbeat — this device's
/// activation token plus a per-request HMAC signature — and reaches the
/// RASP Shield backend's AI Gateway, never a provider directly. There is no
/// parameter here for choosing a provider or model, and no field for
/// supplying risk score, risk level, or security-event evidence: those are
/// entirely the backend's decision and the backend's own authoritative
/// record. See `app/ai/gateway.py`'s module doc for the full trust-boundary
/// design and `docs/AI_GATEWAY.md` for the developer-facing summary.
///
/// A host application never needs to construct this itself — reach it via
/// [RaspShield.ai].
class RaspShieldAi {
  const RaspShieldAi();

  /// When the most recent [ask] call completed, successfully or not. `null`
  /// before the first call this process. Surfaced on [RaspShieldStatus] as
  /// `lastAiRequest`.
  static DateTime? get lastRequestAt => _lastRequestAt;
  static DateTime? _lastRequestAt;

  /// The error code from the most recent *failed* [ask] call, or `null`
  /// when the last call succeeded (or none has been made). Cleared on the
  /// next successful call, not merely overwritten with a blank string, so a
  /// caller can tell "no error" from "error, but I forgot to check the
  /// field name".
  static String? get lastErrorCode => _lastErrorCode;
  static String? _lastErrorCode;

  /// Resets the observed AI status. Test-only.
  static void resetStatusForTesting() {
    _lastRequestAt = null;
    _lastErrorCode = null;
  }

  /// Asks the gateway one question, scoped to [useCase] (defaults to a
  /// general security-status explanation).
  ///
  /// Returns a controlled [AiAskResult] in every case — there is nothing to
  /// `try`/`catch` here. Before the SDK has an activation (no license, not
  /// yet initialized) this returns `NOT_ACTIVATED` immediately without a
  /// network call, exactly like every other post-activation SDK surface.
  Future<AiAskResult> ask(
    String message, {
    AiUseCase useCase = AiUseCase.securityStatus,
  }) async {
    final result = await _ask(message, useCase: useCase);
    _lastRequestAt = DateTime.now().toUtc();
    _lastErrorCode = result.ok ? null : result.errorCode;
    return result;
  }

  Future<AiAskResult> _ask(String message, {required AiUseCase useCase}) async {
    if (useCase == AiUseCase.operatorAssistance) {
      // Never even attempted from a device — the backend would reject it
      // too, but failing fast here avoids a pointless network round trip
      // and states the constraint where a developer will actually read it.
      return AiAskResult.failure(
        'USE_CASE_NOT_PERMITTED',
        'operatorAssistance is only available from the Super Admin console',
      );
    }

    if (!RaspSdk.status.state.grantsFeatures) {
      return AiAskResult.failure(
        'NOT_ACTIVATED',
        'This device has no active license yet',
      );
    }

    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) {
      return AiAskResult.failure(
        'NOT_ACTIVATED',
        'No activation token on file for this device',
      );
    }

    // `ActivationManager.askAi` returns through the same `_interpret()` every
    // other licensing call does: a plain-200 AI response has no `status`
    // field of its own, so it defaults to `'ACTIVE'` there — which is
    // exactly the generic "request succeeded" signal `isSuccess` already
    // checks for. A 4xx/429/403/503 lands in the structured-error branch
    // instead, with the backend's `code` (e.g. `AI_DISABLED`,
    // `TENANT_QUOTA_EXCEEDED`) as `status`.
    final result = await ActivationManager.askAi(
      activationToken: token,
      message: message,
      useCase: useCase.wireName,
    );

    if (!result.isSuccess) {
      return AiAskResult.failure(
        result.status.isEmpty ? 'AI_UNAVAILABLE' : result.status,
        result.message.isEmpty ? 'AI request failed' : result.message,
      );
    }

    final payload = result.payload;
    return AiAskResult(
      ok: true,
      response: (payload['response'] as String?) ?? '',
      requestId: payload['request_id'] as String?,
      provider: payload['provider'] as String?,
      model: payload['model'] as String?,
      policyVersion: payload['policy_version'] as int?,
      riskScore: payload['risk_score'] as int?,
      riskLevel: payload['risk_level'] as String?,
    );
  }
}
