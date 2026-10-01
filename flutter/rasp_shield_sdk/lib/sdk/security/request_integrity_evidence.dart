import '../core/core.dart';

/// Maps a request/transaction-integrity failure onto the SDK's existing
/// `DetectionResult` vocabulary (Phase 12 — "request-integrity failures
/// should become normal DetectionResults... do not create another risk
/// engine"). These results flow through the same `RiskEngine` /
/// `CorrelationEngine` / `ProtectionEngine` every detector already uses;
/// nothing here computes a score or an action.
enum RequestIntegrityEvidenceCode {
  requestSignatureInvalid,
  requestReplayed,
  requestNonceInvalid,
  requestBodyTampered,
  requestDeviceMismatch,
  transactionTampered,
}

extension RequestIntegrityEvidenceCodeX on RequestIntegrityEvidenceCode {
  /// Stable wire name — matches the naming style already used across the
  /// trust/rollout enums (`SCREAMING_SNAKE_CASE`).
  String get wireName {
    switch (this) {
      case RequestIntegrityEvidenceCode.requestSignatureInvalid:
        return 'REQUEST_SIGNATURE_INVALID';
      case RequestIntegrityEvidenceCode.requestReplayed:
        return 'REQUEST_REPLAYED';
      case RequestIntegrityEvidenceCode.requestNonceInvalid:
        return 'REQUEST_NONCE_INVALID';
      case RequestIntegrityEvidenceCode.requestBodyTampered:
        return 'REQUEST_BODY_TAMPERED';
      case RequestIntegrityEvidenceCode.requestDeviceMismatch:
        return 'REQUEST_DEVICE_MISMATCH';
      case RequestIntegrityEvidenceCode.transactionTampered:
        return 'TRANSACTION_TAMPERED';
    }
  }
}

/// Builds a [DetectionResult] for one request/transaction-integrity
/// failure. Callers (the host app, or a future SDK-internal wiring step)
/// feed the result into the same detector list every other check
/// contributes to — this function does not itself touch the pipeline.
DetectionResult detectionResultForRequestIntegrityFailure({
  required RequestIntegrityEvidenceCode code,
  required DateTime observedAt,
  String? detail,
}) {
  final evidence = [
    DetectionEvidence(
      key: 'request_integrity_code',
      value: code.wireName,
      note: detail,
    ),
  ];

  return DetectionResult(
    detectorId: 'request_integrity',
    detectorType: DetectorType.custom,
    category: code == RequestIntegrityEvidenceCode.transactionTampered
        ? ThreatCategory.appIntegrity
        : ThreatCategory.networkSecurity,
    status: DetectionStatus.detected,
    severity: DetectionSeverity.critical,
    confidence: DetectionConfidence.veryHigh,
    title: _titleFor(code),
    description: detail ?? _titleFor(code),
    evidence: evidence,
    observedAt: observedAt,
  );
}

String _titleFor(RequestIntegrityEvidenceCode code) {
  switch (code) {
    case RequestIntegrityEvidenceCode.requestSignatureInvalid:
      return 'Request signature invalid';
    case RequestIntegrityEvidenceCode.requestReplayed:
      return 'Request replay detected';
    case RequestIntegrityEvidenceCode.requestNonceInvalid:
      return 'Request nonce invalid or reused';
    case RequestIntegrityEvidenceCode.requestBodyTampered:
      return 'Request body tampered in transit';
    case RequestIntegrityEvidenceCode.requestDeviceMismatch:
      return 'Request signed by a different device';
    case RequestIntegrityEvidenceCode.transactionTampered:
      return 'Transaction integrity check failed';
  }
}
