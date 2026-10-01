/// SDK Core — plain Dart detection models with no UI dependency.
///
/// Import this single file to get every SDK Core type rather than the
/// individual files under `sdk/core/`. Nothing exported here imports
/// `material.dart`, `widgets.dart`, or any other Flutter UI package; every
/// class is safe to use from a pure-Dart context (unit tests, a future
/// server-side reuse, or a non-Flutter host).
library;

export 'detection_confidence.dart';
export 'detection_evidence.dart';
export 'detection_result.dart';
export 'detection_severity.dart';
export 'detection_status.dart';
export 'detector_type.dart';
export 'location_security_state.dart';
export 'threat_category.dart';
