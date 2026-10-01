/// The runtime security decision layer.
///
/// ```
///   DetectionResult[]  →  RiskEngine  →  RiskAssessment
///                              ↑              ↓
///                     CorrelationEngine   ProtectionEngine  →  ProtectionResult
/// ```
///
/// Everything here is plain Dart with no Flutter import, no I/O and no shared
/// mutable state, so it is unit-testable without a device and safe to call
/// concurrently.
library;

export 'correlation_engine.dart';
export 'correlation_rule.dart';
export 'risk_assessment.dart';
export 'risk_engine.dart';
export 'risk_posture.dart';
export 'security_policy_profile.dart';
export 'severity_action_ladder.dart';
