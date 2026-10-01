/// Outcome of one `RaspShield.ai.ask` call.
///
/// A **controlled** result either way — [ok] is `false` for a rejection
/// (AI disabled, quota exceeded, unknown use case, no trust proof) or a
/// network/provider failure, never an uncaught exception. [riskScore]/
/// [riskLevel]/[policyVersion], when present, are the backend's own
/// authoritative values (the same ones `RiskEngine`/policy publishing
/// already produce) carried alongside the prose explanation — never a
/// number the model invented.
class AiAskResult {
  final bool ok;

  /// The AI's prose answer. Empty when [ok] is `false`.
  final String response;

  /// Stable machine code for a non-`ok` result (`AI_DISABLED`,
  /// `TENANT_QUOTA_EXCEEDED`, `DEVICE_RATE_LIMITED`, `USE_CASE_NOT_ALLOWED`,
  /// `NETWORK_ERROR`, …) — never a raw exception message.
  final String? errorCode;
  final String? errorMessage;

  final String? requestId;
  final String? provider;
  final String? model;
  final int? policyVersion;
  final int? riskScore;
  final String? riskLevel;

  const AiAskResult({
    required this.ok,
    this.response = '',
    this.errorCode,
    this.errorMessage,
    this.requestId,
    this.provider,
    this.model,
    this.policyVersion,
    this.riskScore,
    this.riskLevel,
  });

  factory AiAskResult.failure(String code, String message) => AiAskResult(
        ok: false,
        errorCode: code,
        errorMessage: message,
      );

  Map<String, Object?> toMap() => {
        'ok': ok,
        'response': response,
        'error_code': errorCode,
        'error_message': errorMessage,
        'request_id': requestId,
        'provider': provider,
        'model': model,
        'policy_version': policyVersion,
        'risk_score': riskScore,
        'risk_level': riskLevel,
      };

  @override
  String toString() => ok
      ? 'AiAskResult(ok, provider=$provider, risk=$riskScore/$riskLevel)'
      : 'AiAskResult(error=$errorCode: $errorMessage)';
}
