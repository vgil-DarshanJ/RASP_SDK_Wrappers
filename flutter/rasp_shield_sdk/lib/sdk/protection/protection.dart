/// RASP Shield protection layer — policy, engine, and decision types.
///
/// ```
///   List<DetectionResult> + ProtectionContext + ProtectionPolicy
///                        ↓
///                 ProtectionEngine.evaluate()
///                        ↓
///                   ProtectionResult
///                        ↓
///   allow · monitor · warn · stepUp · block · lockSession · lockApp
/// ```
library;

export 'compatibility_decision.dart';
export 'enforcement_controller.dart';
export 'enforcement_state.dart';
export 'pipeline_mode.dart';
export 'protection_action.dart';
export 'protection_context.dart';
export 'protection_decision_comparison.dart';
export 'protection_engine.dart';
export 'protection_policy.dart';
export 'protection_result.dart';
export 'rollout_observation.dart';
