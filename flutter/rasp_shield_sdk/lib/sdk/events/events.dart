/// Security events — structured, integrity-protected, ordered, deduplicated,
/// replay-resistant, privacy-conscious, offline-safe.
///
/// Import this single file to get the whole subsystem, matching `core/core.dart`
/// and `protection/protection.dart`'s existing barrel pattern.
///
/// Design documents: `docs/SECURITY_EVENT_MODEL.md`,
/// `docs/SECURITY_EVENT_INTEGRITY.md`, `docs/SECURITY_EVENT_QUEUE.md`,
/// `docs/SECURITY_EVENT_PRIVACY.md`, `docs/SECURITY_EVENT_PIPELINE.md`,
/// `docs/SECURITY_EVENT_BACKEND_INGEST.md`.
library;

export 'security_event.dart';
export 'security_event_center.dart';
export 'security_event_chain.dart';
export 'security_event_dedup.dart';
export 'security_event_factory.dart';
export 'security_event_pipeline.dart';
export 'security_event_privacy.dart';
export 'security_event_queue.dart';
export 'security_event_reporter.dart';
export 'security_event_sequence.dart';
export 'security_event_test_injector.dart';
export 'security_event_type.dart';
