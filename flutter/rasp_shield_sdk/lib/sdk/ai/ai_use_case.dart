/// The safe, backend-allowlisted set of questions `RaspShield.ai.ask` may be
/// asked about. Mirrors `app/ai/gateway.py`'s `USE_CASES` exactly — this is
/// not an SDK-side allowlist the backend re-checks; the backend's is the
/// only one that is actually enforced. This enum exists so a caller gets
/// autocomplete and a compile error for a typo instead of a runtime 400.
///
/// `operatorAssistance` deliberately has no [wireName] a device request can
/// reach — the backend rejects it outright from `/api/v1/sdk/ai/ask`
/// regardless of tenant AI policy; it is reachable only from the Super
/// Admin console's own endpoint. It is listed here anyway so this enum
/// stays the single source of truth for the full use-case vocabulary.
enum AiUseCase {
  /// 1. Security status explanation.
  securityStatus,

  /// 2. Threat explanation.
  threatExplanation,

  /// 3. Device-block explanation.
  deviceBlockExplanation,

  /// 4. Incident summary.
  incidentSummary,

  /// 5. Policy explanation.
  policyExplanation,

  /// 6. Security-event explanation.
  securityEventExplanation,

  /// 7. Security-operator assistance — Super Admin console only.
  operatorAssistance,
}

extension AiUseCaseWireName on AiUseCase {
  String get wireName => switch (this) {
        AiUseCase.securityStatus => 'security_status',
        AiUseCase.threatExplanation => 'threat_explanation',
        AiUseCase.deviceBlockExplanation => 'device_block_explanation',
        AiUseCase.incidentSummary => 'incident_summary',
        AiUseCase.policyExplanation => 'policy_explanation',
        AiUseCase.securityEventExplanation => 'security_event_explanation',
        AiUseCase.operatorAssistance => 'operator_assistance',
      };
}
