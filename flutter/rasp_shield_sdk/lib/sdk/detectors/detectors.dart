/// RASP Shield detector layer — the detector contract, the registry, the
/// scan runner, and every detector the SDK ships.
///
/// This is the single detection architecture in the SDK. `SecurityCatalog`
/// (`rasp/security_catalog.dart`) holds presentation metadata and delegates
/// its checks here, so no check is implemented twice.
library;

export 'builtin_detectors.dart';
export 'detector_entitlements.dart';
export 'ios_fallback.dart';
export 'rasp_native_channel.dart';
export 'scan_runner.dart';
export 'security_detector.dart';
export 'security_detector_registry.dart';
