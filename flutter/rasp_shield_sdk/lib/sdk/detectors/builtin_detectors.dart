/// Every detector RASP Shield ships, as real [SecurityDetector]s.
///
/// ## What changed and why
///
/// These checks used to live as `runner:` closures inside
/// `rasp/security_catalog.dart`, mixed in with `IconData`, `Color`, and UI
/// copy. That made them impossible to enumerate, run generically, or unit
/// test without a widget tree — and it meant the SDK could not answer "what
/// detectors exist?" without hardcoding every case.
///
/// The checks now live here, returning plain [DetectionResult]s.
/// `SecurityCatalog` keeps the presentation metadata and delegates its
/// `runner` to these classes, so there is exactly **one** implementation of
/// every check in the SDK rather than two competing ones.
///
/// ## Four outcomes, never two
///
/// Every detector reports a [DetectionStatus]: `secure`, `detected`,
/// `unavailable`, or `error`. A check that could not run is never reported as
/// clean — see [DetectionStatus] for the three real defects that came from
/// collapsing those states into a boolean.
///
/// `unavailable` is expected (wrong platform, nothing configured);
/// `error` is a fault (the platform threw, a handler that should exist did
/// not answer, a control that should apply did not).
///
/// ## Platform reality
///
/// Android is the only platform with native implementations. On every other
/// platform the native-backed detectors report `unavailable`. `debugger` is
/// the sole *partly* pure-Dart check: its build-mode half works everywhere,
/// while its runtime half (JDWP / `TracerPid`) is Android-native and degrades
/// to the build-mode signal alone elsewhere.
library;

import 'package:flutter/foundation.dart';

import '../../services/device_fingerprint_service.dart';
import '../../services/geo_filter_service.dart';
import '../../services/ssl_pinning_service.dart';
import '../core/core.dart';
import '../license_manager.dart';
import '../license_models.dart';
import '../offline/offline_compliance.dart';
import '../offline/offline_compliance_store.dart';
import '../remote_config_manager.dart';
import 'evidence_confidence.dart';
import 'app_intelligence.dart';
import 'app_intelligence_policy.dart';
import 'ios_fallback.dart';
import 'rasp_native_channel.dart';
import 'reputation_provider.dart';
import 'risky_app_evidence.dart';
import 'security_detector.dart';
import 'security_detector_registry.dart';


/// `true` on iOS, where `safe_device` is the only jailbreak/simulator signal
/// available until a native iOS implementation exists.
bool get _isIos => !kIsWeb && defaultTargetPlatform == TargetPlatform.iOS;

/// The platform string stamped onto every [DetectionResult].
///
/// `DetectionResult.platform` exists so a stored `threat_history` row can be
/// attributed to the platform that produced it, but before the cross-platform
/// iOS milestone no detector ever set it — every row on both platforms read
/// `'unknown'`, which made platform-coverage reporting impossible. Stamped in
/// one place (`_BaseDetector._build`) rather than 23.
String get _platformName {
  if (kIsWeb) return 'web';
  return switch (defaultTargetPlatform) {
    TargetPlatform.android => 'android',
    TargetPlatform.iOS => 'ios',
    TargetPlatform.macOS => 'macos',
    TargetPlatform.windows => 'windows',
    TargetPlatform.linux => 'linux',
    TargetPlatform.fuchsia => 'fuchsia',
  };
}

/// iOS jailbreak via the host-supplied [IosFallback.provider], or `null`
/// when not iOS / no provider registered / unreadable. See `ios_fallback.dart`
/// for why this SDK core ships no default implementation.
Future<bool?> _iosJailbreakFallback() async {
  if (!_isIos) return null;
  try {
    return await IosFallback.provider?.isJailbroken();
  } catch (_) {
    return null;
  }
}

/// iOS simulator via the host-supplied [IosFallback.provider], or `null`
/// when not iOS / no provider registered / unreadable.
Future<bool?> _iosSimulatorFallback() async {
  if (!_isIos) return null;
  try {
    return await IosFallback.provider?.isSimulator();
  } catch (_) {
    return null;
  }
}

/// Shared construction helpers so 21 detectors do not repeat the same
/// `DetectionResult` boilerplate 21 times.
abstract class _BaseDetector implements SecurityDetector {
  const _BaseDetector();

  ThreatCategory get category;
  DetectionSeverity get severity;
  String get title;
  String get description;

  /// Shared calculator turning a detector's own evidence into real
  /// confidence, replacing the flat `high` default every detector used to
  /// carry. See `docs/DETECTOR_CONFIDENCE_FLOW.md` and
  /// `docs/CONFIDENCE_MODEL.md`.
  static const _confidenceCalculator = EvidenceConfidenceCalculator();

  DetectionResult _build({
    required DetectionStatus status,
    List<DetectionEvidence> evidence = const [],
    String? reason,
  }) {
    // Built once with the model's default confidence, then re-derived from
    // the evidence actually attached — the calculator only has an opinion for
    // DetectionStatus.detected (see its docs), so every other status keeps
    // its constructor default unchanged.
    final draft = DetectionResult(
      detectorId: detectorId,
      detectorType: detectorType,
      category: category,
      status: status,
      severity: severity,
      title: title,
      description: description,
      evidence: evidence,
      observedAt: DateTime.now().toUtc(),
      platform: _platformName,
      unavailableReason: reason,
    );
    final confidence = _confidenceCalculator.confidenceFor(draft);
    return confidence == draft.confidence
        ? draft
        : draft.copyWith(confidence: confidence);
  }

  /// The check ran and produced a verdict.
  DetectionResult _result({
    required bool threatDetected,
    List<DetectionEvidence> evidence = const [],
  }) =>
      _build(
        status:
            threatDetected ? DetectionStatus.detected : DetectionStatus.secure,
        evidence: evidence,
      );

  /// The check could not run, and that is expected — wrong platform, no
  /// native implementation, nothing configured.
  DetectionResult _unavailable(String reason) =>
      _build(status: DetectionStatus.unavailable, reason: reason);

  /// The check tried to run and failed. Distinct from [_unavailable] because
  /// this one wants investigating, not accepting.
  DetectionResult _error(String reason) =>
      _build(status: DetectionStatus.error, reason: reason);
}

/// A detector whose entire verdict is one native boolean where `true` means
/// "threat found". Covers most of the Android checks.
abstract class _NativeBoolDetector extends _BaseDetector {
  const _NativeBoolDetector();

  /// The `MainActivity.kt` method to invoke.
  String get nativeMethod;

  @override
  Future<DetectionResult> scan() async {
    final flagged = await RaspNativeChannel.boolCall(nativeMethod);
    if (flagged == null) {
      // Three distinct causes, three distinct classifications — none SECURE:
      //  * Android: a handler that should exist did not answer. A fault worth
      //    investigating (ERROR).
      //  * iOS: the channel is registered but does not implement this method,
      //    because the capability has no iOS equivalent. A platform limit
      //    (UNAVAILABLE), not a fault — see docs/IOS_PLATFORM_LIMITATIONS.md.
      //  * Anything else: no native layer at all (UNAVAILABLE).
      if (RaspNativeChannel.isSupportedPlatform) {
        return _error('Native check "$nativeMethod" did not answer on a '
            'platform that implements it');
      }
      return _unavailable(_isIos
          ? 'Not implemented on iOS — no platform equivalent for '
              '"$nativeMethod"'
          : 'Available on Android only');
    }
    return _result(threatDetected: flagged);
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Device integrity
// ═══════════════════════════════════════════════════════════════════════

/// Root/jailbreak. Reports **which** signals fired as evidence, so an analyst
/// sees why rather than an unexplained boolean.
class RootDetector extends _BaseDetector {
  const RootDetector();

  @override
  String get detectorId => 'root_jailbreak';
  @override
  DetectorType get detectorType => DetectorType.root;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.critical;
  @override
  String get title => 'Root / Jailbreak';
  @override
  String get description =>
      'Superuser binaries, root managers, and jailbreak artefacts that break '
      'the OS sandbox.';

  @override
  Future<DetectionResult> scan() async {
    final rooted = await RaspNativeChannel.boolCall('isDeviceRooted');
    if (rooted == null) {
      // iOS has no native implementation yet. `safe_device` is a weaker,
      // single-signal check — trivially hooked, and it does not survive
      // Magisk DenyList, which is exactly why Android moved off it — but it
      // beats reporting a false "secure" on a jailbroken iPhone. Preserved
      // from the pre-migration behaviour; remove it when a real iOS native
      // implementation lands.
      final fallback = await _iosJailbreakFallback();
      if (fallback != null) {
        return _result(
          threatDetected: fallback,
          evidence: const [
            DetectionEvidence(
              key: 'source',
              value: 'safe_device',
              note: 'iOS fallback — weaker than the Android native check',
            ),
          ],
        );
      }
      return _unavailable(RaspNativeChannel.isSupportedPlatform
          ? 'Native root check is unavailable on this build'
          : 'Available on Android only');
    }
    if (!rooted) return _result(threatDetected: false);

    final signals = await RaspNativeChannel.stringListCall('getRootSignals');
    return _result(
      threatDetected: true,
      evidence: [
        for (final signal in signals)
          DetectionEvidence(key: 'root_signal', value: signal),
        DetectionEvidence(
          key: 'signal_count',
          value: signals.length,
          note: 'Independent root indicators that fired',
        ),
      ],
    );
  }
}

/// Emulator / virtual device. Like [RootDetector], reports its signals.
class EmulatorDetector extends _BaseDetector {
  const EmulatorDetector();

  @override
  String get detectorId => 'emulator';
  @override
  DetectorType get detectorType => DetectorType.emulator;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'Emulator Detection';
  @override
  String get description =>
      'QEMU/VirtualBox artefacts, emulator packages, missing sensors, and '
      'generic hardware identifiers.';

  @override
  Future<DetectionResult> scan() async {
    final emulated = await RaspNativeChannel.boolCall('isEmulator');
    if (emulated == null) {
      // Same iOS fallback rationale as RootDetector.
      final fallback = await _iosSimulatorFallback();
      if (fallback != null) {
        return _result(
          threatDetected: fallback,
          evidence: const [
            DetectionEvidence(
              key: 'source',
              value: 'safe_device',
              note: 'iOS fallback — weaker than the Android native check',
            ),
          ],
        );
      }
      return _unavailable(RaspNativeChannel.isSupportedPlatform
          ? 'Native emulator check is unavailable on this build'
          : 'Available on Android only');
    }
    if (!emulated) return _result(threatDetected: false);

    final signals = await RaspNativeChannel.stringListCall('getEmulatorSignals');
    return _result(
      threatDetected: true,
      evidence: [
        for (final signal in signals)
          DetectionEvidence(key: 'emulator_signal', value: signal),
        DetectionEvidence(key: 'signal_count', value: signals.length),
      ],
    );
  }
}

/// Hardware-backed Keystore binding.
///
/// NOTE the native polarity: `verifyDeviceBinding()` returns `true` when
/// binding **failed** despite its name. Preserved exactly as shipped.
class DeviceBindingDetector extends _NativeBoolDetector {
  const DeviceBindingDetector();

  @override
  String get detectorId => 'device_binding';
  @override
  DetectorType get detectorType => DetectorType.root;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get nativeMethod => 'verifyDeviceBinding';
  @override
  String get title => 'Device Binding';
  @override
  String get description =>
      'A hardware-backed Keystore key that ties this install to this device.';
}

/// Screen lock, ADB, SELinux, install source and hardware identity drift,
/// via the existing `DeviceFingerprintService`.
class DeviceFingerprintDetector extends _BaseDetector {
  const DeviceFingerprintDetector();

  @override
  String get detectorId => 'device_fingerprint';
  @override
  DetectorType get detectorType => DetectorType.root;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'Device Fingerprint';
  @override
  String get description =>
      'Screen lock, USB debugging, SELinux state, install source and hardware '
      'identity drift.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }

    // Availability is probed here rather than inferred from the service's
    // answer, because `DeviceFingerprintService.checkDeviceRisk()` catches
    // every exception and returns `isRisk: false` — a clean bill of health
    // for a check that never ran. Probing the underlying native surface
    // first is what separates "device looks fine" from "we could not look".
    // The service is left untouched; only the availability decision moves.
    final probe = await RaspNativeChannel.stringCall('getDeviceFingerprint');
    if (probe == null) {
      return _unavailable(
        'Native device-fingerprint surface did not answer — posture could not '
        'be read',
      );
    }

    try {
      final risk = await DeviceFingerprintService.checkDeviceRisk();
      if (risk.checkFailed) {
        // A platform-side fault (malformed payload, secure-storage failure),
        // not a clean device. Reporting this as SECURE was the exact defect
        // fixed in DeviceFingerprintService — see its checkFailed doc comment.
        return _error(
          'Device fingerprint evaluation failed: '
          '${risk.failureReason ?? "unknown error"}',
        );
      }
      return _result(
        threatDetected: risk.isRisk,
        evidence: [
          for (final check in risk.failedChecks)
            DetectionEvidence(key: 'device_fingerprint_signal', value: check),
          if (risk.failedChecks.isNotEmpty)
            DetectionEvidence(
              key: 'signal_count',
              value: risk.failedChecks.length,
              note: 'Independent posture indicators that fired',
            ),
        ],
      );
    } catch (e) {
      return _error('Fingerprint evaluation failed: $e');
    }
  }
}

/// Parallel Space / Dual App containers.
///
/// Two independent signals (Phase 3 of the overlay/clone hardening
/// milestone):
///
/// 1. `known_clone_container_path` — the original path-substring match
///    against known clone-app data-directory naming. Unchanged.
/// 2. `unexplained_secondary_user` — replaces the old, buggy "any
///    non-primary-user path is a clone" branch. Now cross-checked against
///    `UserManager.isManagedProfile()` so a legitimate work/enterprise
///    profile is `NOT_DETECTED`, not misclassified as a clone.
class CloneDetector extends _BaseDetector with _TwoSignalDetector {
  const CloneDetector();

  @override
  String get detectorId => 'clone';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get nativeMethod => 'getCloneEvidence';
  @override
  String Function(String signal) get evidenceKeyFor => (s) => 'clone_$s';
  @override
  String get title => 'App Clone / Dual Space';
  @override
  String get description =>
      'Cloning containers and abnormal data paths used to run a second copy '
      'of the app, corroborated against legitimate work-profile context.';
}

/// Developer options unlocked.
class DeveloperModeDetector extends _NativeBoolDetector {
  const DeveloperModeDetector();

  @override
  String get detectorId => 'developer_mode';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.low;
  @override
  String get nativeMethod => 'isDeveloperModeEnabled';
  @override
  String get title => 'Developer Mode';
  @override
  String get description => 'Whether Developer options have been unlocked.';
}

/// USB debugging (ADB) enabled.
class AdbEnabledDetector extends _NativeBoolDetector {
  const AdbEnabledDetector();

  @override
  String get detectorId => 'adb_enabled';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get nativeMethod => 'isAdbEnabled';
  @override
  String get title => 'USB Debugging';
  @override
  String get description => 'Whether ADB is enabled on the device.';
}

/// Physical USB connection to a host (cable/dock plugged in), independent of
/// whether ADB debugging is enabled — see `RaspUsbAnalysis`'s doc for why
/// this is a distinct signal from [AdbEnabledDetector]. Reports the same
/// device-count evidence [ScreenCaptureShieldDetector] reports for
/// screenshot events, so an analyst can tell "a cable is plugged in" apart
/// from a bare boolean.
class UsbConnectionDetector extends _BaseDetector {
  const UsbConnectionDetector();

  @override
  String get detectorId => 'usb_connection';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.low;
  @override
  String get title => 'USB Connection';
  @override
  String get description =>
      'Whether the device is currently connected to a host over USB.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }
    final evidence = await RaspNativeChannel.mapCall('getUsbConnectionEvidence');
    if (evidence == null || evidence['supported'] != true) {
      return _unavailable(
        'USB connection detection is not implemented on this platform',
      );
    }
    final connected = evidence['connected'] == true;
    return _result(
      threatDetected: connected,
      evidence: [
        DetectionEvidence(
          key: 'usb_device_count',
          value: evidence['device_count'],
        ),
      ],
    );
  }
}

/// No PIN/pattern/password/biometric configured.
class DeviceLockMissingDetector extends _NativeBoolDetector {
  const DeviceLockMissingDetector();

  @override
  String get detectorId => 'device_lock_missing';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get nativeMethod => 'isDeviceLockMissing';
  @override
  String get title => 'Device Lock';
  @override
  String get description =>
      'Whether a PIN, pattern, password, or biometric lock is configured.';
}

/// No TEE / StrongBox available.
class SecureHardwareDetector extends _NativeBoolDetector {
  const SecureHardwareDetector();

  @override
  String get detectorId => 'secure_hardware_unavailable';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.deviceIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.low;
  @override
  String get nativeMethod => 'isSecureHardwareUnavailable';
  @override
  String get title => 'Hardware-Backed Keystore';
  @override
  String get description =>
      'Whether a Trusted Execution Environment or StrongBox is available.';
}

// ═══════════════════════════════════════════════════════════════════════
// Runtime protection
// ═══════════════════════════════════════════════════════════════════════

/// Frida server, injected agents, instrumentation artefacts.
///
/// Reports the individual signals behind a positive verdict, exactly as
/// [RootDetector] does. The native side no longer answers from a single
/// filename check — it correlates filesystem, memory-map, thread-table,
/// loader-environment and control-port evidence — so which signals fired is
/// what tells an analyst whether they are looking at a stale artefact left on
/// disk or a live agent attached to the process right now.
class FridaDetector extends _BaseDetector {
  const FridaDetector();

  @override
  String get detectorId => 'frida';
  @override
  DetectorType get detectorType => DetectorType.frida;
  @override
  ThreatCategory get category => ThreatCategory.runtimeProtection;
  @override
  DetectionSeverity get severity => DetectionSeverity.critical;
  @override
  String get title => 'Frida / Instrumentation';
  @override
  String get description =>
      'The Frida server, injected agents, and instrumentation artefacts that '
      'hook into the running process.';

  @override
  Future<DetectionResult> scan() async {
    final detected = await RaspNativeChannel.boolCall('detectFrida');
    if (detected == null) {
      return _unavailable(RaspNativeChannel.isSupportedPlatform
          ? 'Native instrumentation check is unavailable on this build'
          : 'Available on Android only');
    }
    if (!detected) return _result(threatDetected: false);

    // Older builds of the native layer have no getFridaSignals handler. An
    // empty list degrades to a bare verdict rather than failing the scan.
    final signals = await RaspNativeChannel.stringListCall('getFridaSignals');
    return _result(
      threatDetected: true,
      evidence: [
        for (final signal in signals)
          DetectionEvidence(key: 'frida_signal', value: signal),
        DetectionEvidence(
          key: 'signal_count',
          value: signals.length,
          note: 'Independent instrumentation indicators that fired',
        ),
      ],
    );
  }
}

/// Debug build or attached debugger.
///
/// Two independent sources, because they answer different questions:
///
/// * [debugMode] (`kDebugMode`) is a **compile-time constant** describing how
///   the APK was built. It works on every platform with no native dependency.
/// * `isDebuggerAttached` is a **runtime** native check — JDWP, and a non-zero
///   `TracerPid` for a native `ptrace` attach.
///
/// Relying on the constant alone — which this detector used to do — meant a
/// release build always reported "no debugger" no matter what was attached to
/// the process, because the constant is false in every release build by
/// definition. Either source firing is a threat; the native one is what makes
/// the check mean anything in production.
///
/// `debuggable_flag` is filtered out of the evidence: it restates the build
/// mode that [debugMode] already reports, and duplicating it would imply two
/// independent findings where there is one.
class DebuggerDetector extends _BaseDetector {
  /// Injectable so a test can assert both branches without a debug build.
  final bool debugMode;

  const DebuggerDetector({required this.debugMode});

  @override
  String get detectorId => 'debugger';
  @override
  DetectorType get detectorType => DetectorType.debugger;
  @override
  ThreatCategory get category => ThreatCategory.runtimeProtection;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'Debugger Attached';
  @override
  String get description =>
      'Whether the app is a debug build or has a debugger attached.';

  @override
  Future<DetectionResult> scan() async {
    // Runtime signals first. `null` means the native layer could not answer
    // (not Android, older build, platform threw) — the build-mode check below
    // still stands on its own, exactly as it did before native support.
    final attached = await RaspNativeChannel.boolCall('isDebuggerAttached');
    final signals = attached == true
        ? await RaspNativeChannel.stringListCall('getDebuggerSignals')
        : const <String>[];

    return _result(
      threatDetected: debugMode || attached == true,
      evidence: [
        if (debugMode)
          const DetectionEvidence(
            key: 'build_mode',
            value: 'debug',
            note: 'Running a debug build',
          ),
        for (final signal in signals)
          if (signal != 'debuggable_flag')
            DetectionEvidence(
              key: 'debugger_signal',
              value: signal,
              note: 'Runtime debugger indicator',
            ),
      ],
    );
  }
}

/// Xposed/LSPosed, Magisk manager, Lucky Patcher, GameGuardian, Substrate.
class ReverseEngineeringToolsDetector extends _NativeBoolDetector {
  const ReverseEngineeringToolsDetector();

  @override
  String get detectorId => 're_tools';
  @override
  DetectorType get detectorType => DetectorType.reverseEngineeringTools;
  @override
  ThreatCategory get category => ThreatCategory.runtimeProtection;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get nativeMethod => 'checkReverseEngineeringTools';
  @override
  String get title => 'Reverse-Engineering Tools';
  @override
  String get description =>
      'Xposed/LSPosed, Magisk, Lucky Patcher, GameGuardian and similar '
      'tampering frameworks installed on the device.';
}

/// Method interception: a resident hooking framework, code mapped from a
/// writable location, unusual writable+executable memory, or tampering with
/// the SDK's own security-critical methods.
///
/// Distinct from [FridaDetector] and [ReverseEngineeringToolsDetector]:
/// dynamic instrumentation (Frida attaching to the process) and installed
/// RE-tool *packages* are different mechanisms from Java-level method
/// hooking, and `RaspHookProbes` (native) observes them independently — no
/// code path is shared between the three.
///
/// Follows [FridaDetector]'s exact two-call shape rather than the native
/// `getHookDetectionResult` map: native's own `severity` (a string) and
/// `confidence` (a 0–100 int) use different vocabularies than this SDK's
/// [DetectionSeverity]/[DetectionConfidence] enums, so re-deriving confidence
/// from the raw signal list — the same hard/soft-mirroring approach already
/// proven for root/emulator/Frida — avoids importing a second, incompatible
/// confidence model. See `docs/UNIFIED_DETECTOR_ENGINE_AUDIT.md` §8.
class HookDetector extends _BaseDetector {
  const HookDetector();

  @override
  String get detectorId => 'hook_detection';
  @override
  DetectorType get detectorType => DetectorType.hook;
  @override
  ThreatCategory get category => ThreatCategory.runtimeProtection;
  @override
  DetectionSeverity get severity => DetectionSeverity.critical;
  @override
  String get title => 'Hooking / Method Interception';
  @override
  String get description =>
      'Resident hooking frameworks, code mapped from writable locations, and '
      'tampering with the SDK\'s own security-critical methods.';

  @override
  Future<DetectionResult> scan() async {
    final detected = await RaspNativeChannel.boolCall('isHookingDetected');
    if (detected == null) {
      return _unavailable(RaspNativeChannel.isSupportedPlatform
          ? 'Native hook-detection check is unavailable on this build'
          : 'Available on Android only');
    }
    if (!detected) return _result(threatDetected: false);

    final signals = await RaspNativeChannel.stringListCall('getHookSignals');
    return _result(
      threatDetected: true,
      evidence: [
        for (final signal in signals)
          DetectionEvidence(key: 'hook_signal', value: signal),
        DetectionEvidence(
          key: 'signal_count',
          value: signals.length,
          note: 'Independent hooking indicators that fired',
        ),
      ],
    );
  }
}

/// Risky-app / risky-environment evidence (Phase C, gap-closure-3
/// milestone). Reads a curated, publicly-documented list of remote-access
/// and instrumentation-framework packages (via `PackageManager`, gated by
/// AndroidManifest's `<queries>` visibility exemption — never a bulk
/// installed-apps scan) plus the same accessibility-service list
/// [AccessibilityAbuseDetector] already reads. Not a malware scanner — see
/// `docs/RISKY_APP_DETECTION.md`.
///
/// Aggregation rule, deliberately simple and stated once: **any**
/// `knownRiskyPackage` evidence makes this detector `detected` at `high`
/// severity/`veryHigh` confidence (strong, named evidence). With **no**
/// `knownRiskyPackage` evidence but **one or more** `suspiciousBehavior`
/// entries, it is `detected` at `medium` severity/`low` confidence — weak,
/// capability-only evidence that many legitimate apps also produce, so it
/// must never be reported with the same weight as a named risky package.
/// `evidence` on the result carries every individual finding either way.
class RiskyAppDetector extends _BaseDetector {
  const RiskyAppDetector();

  @override
  String get detectorId => 'risky_app';
  @override
  DetectorType get detectorType => DetectorType.riskyApp;
  @override
  ThreatCategory get category => ThreatCategory.other;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get title => 'Risky Application / Environment';
  @override
  String get description =>
      'Known remote-access or instrumentation-framework packages, or an '
      'active third-party accessibility service, present on this device.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }

    // mapListCall alone cannot tell "the channel answered with an empty
    // list" from "there is no handler behind the channel at all" — both
    // collapse to `[]`. A liveness probe on a method every real native
    // build already answers (isVpnActive, registered unconditionally in
    // MainActivity's handler) closes that gap: `null` here means the
    // whole channel is unavailable, not that this device is clean.
    final channelAlive = await RaspNativeChannel.boolCall('isVpnActive') != null;
    if (!channelAlive) {
      return _unavailable('Native risky-app evidence channel did not respond');
    }

    List<Map<String, Object?>> raw;
    try {
      raw = await RaspNativeChannel.mapListCall('getRiskyAppEvidence');
    } catch (e) {
      return _error('Risky-app evidence query failed: $e');
    }

    final entries = raw.map(_parseEvidence).whereType<RiskyAppEvidence>().toList();

    final hasQueryError = entries.any((e) => e.status == RiskyAppEvidenceStatus.error);
    final known = entries.where(
      (e) => e.detected && e.category == RiskyAppEvidenceCategory.knownRiskyPackage,
    );
    final suspicious = entries.where(
      (e) => e.detected && e.category == RiskyAppEvidenceCategory.suspiciousBehavior,
    );

    if (known.isEmpty && suspicious.isEmpty && hasQueryError) {
      return _error('One or more risky-app evidence queries failed and no signal was found');
    }

    final evidence = [
      for (final e in known)
        DetectionEvidence(
          key: 'known_risky_package',
          value: e.package,
          note: e.reason,
        ),
      for (final e in suspicious)
        DetectionEvidence(
          key: 'suspicious_accessibility_service',
          value: e.package,
          note: e.reason,
        ),
    ];

    if (known.isNotEmpty) {
      return _result(threatDetected: true, evidence: evidence);
    }
    if (suspicious.isNotEmpty) {
      // Weak, capability-only evidence — reported at reduced confidence via
      // the same evidence-driven calculator every other detector uses
      // (fewer/weaker DetectionEvidence entries -> lower derived confidence),
      // not a second confidence model.
      return _result(threatDetected: true, evidence: evidence);
    }
    return _result(threatDetected: false);
  }

  static RiskyAppEvidence? _parseEvidence(Map<String, Object?> map) {
    final categoryName = map['category'] as String?;
    final category = categoryName == 'KNOWN_RISKY_PACKAGE'
        ? RiskyAppEvidenceCategory.knownRiskyPackage
        : categoryName == 'SUSPICIOUS_BEHAVIOR'
            ? RiskyAppEvidenceCategory.suspiciousBehavior
            : null;
    if (category == null) return null;

    final statusName = map['status'] as String?;
    final detectedFlag = map['detected'] == true;
    final status = statusName == 'ERROR'
        ? RiskyAppEvidenceStatus.error
        : statusName == 'DETECTED' && detectedFlag
            ? RiskyAppEvidenceStatus.detected
            : RiskyAppEvidenceStatus.notDetected;

    return RiskyAppEvidence(
      package: map['package'] as String?,
      category: category,
      reason: (map['reason'] as String?) ?? 'unspecified',
      status: status,
      source: (map['source'] as String?) ?? 'unknown',
      confidence: category == RiskyAppEvidenceCategory.knownRiskyPackage
          ? RiskyAppEvidenceConfidence.strong
          : RiskyAppEvidenceConfidence.weak,
    );
  }
}

/// Malware & Risky-App Intelligence — [ThreatIntelRecord]-backed
/// classification of the same `<queries>`-declared packages [RiskyAppDetector]
/// already checks by presence, now with signing identity and install-source
/// evidence added where the package is actually installed.
///
/// Deliberately a **sibling** to [RiskyAppDetector], not a replacement: that
/// detector's plain "known package present / suspicious accessibility
/// service" signal is unchanged and still fires on its own. This one adds
/// the richer per-package [AppRiskProfile] — reputation classification,
/// signing-identity comparison, install-source — that Phase 9/10 of the
/// milestone this class implements requires, without touching the existing,
/// tested detector at all.
class AppIntelligenceDetector extends _BaseDetector {
  const AppIntelligenceDetector({ReputationProvider? reputationProvider})
      : _reputationProviderOverride = reputationProvider;

  static final ReputationProvider _defaultProvider = LocalReputationProvider();

  final ReputationProvider? _reputationProviderOverride;

  ReputationProvider get reputationProvider =>
      _reputationProviderOverride ?? _defaultProvider;

  @override
  String get detectorId => 'app_intelligence';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.other;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get title => 'Malware & Risky-App Intelligence';
  @override
  String get description =>
      'Signing identity, install source and threat-intelligence '
      'classification for known risky/instrumentation packages present on '
      'this device.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }
    if (!AppIntelligencePolicy.enabled) {
      // Disabled-by-signed-policy is UNAVAILABLE, never SECURE — a device
      // whose operator turned this check off must never be reported as "no
      // risky apps found" when nothing was actually evaluated.
      return _unavailable('Disabled by signed remote policy');
    }

    final channelAlive = await RaspNativeChannel.boolCall('isVpnActive') != null;
    if (!channelAlive) {
      return _unavailable('Native app-intelligence channel did not respond');
    }

    List<Map<String, Object?>> raw;
    try {
      raw = await RaspNativeChannel.mapListCall('getAppIntelligence');
    } catch (e) {
      return _error('App-intelligence query failed: $e');
    }

    final profiles = <AppRiskProfile>[];
    var hadQueryError = false;
    for (final row in raw) {
      if (row['query_error'] == true) {
        hadQueryError = true;
        continue;
      }
      profiles.add(buildProfile(row, reputationProvider));
    }

    if (profiles.isEmpty && hadQueryError) {
      return _error('Every app-intelligence query failed for an installed '
          'package');
    }

    final malicious = profiles.where(
      (p) => p.classification == AppRiskClassification.knownMalicious,
    );
    final highRisk = profiles.where(
      (p) => p.classification == AppRiskClassification.highRisk,
    );
    final suspicious = profiles.where(
      (p) => p.classification == AppRiskClassification.suspicious,
    );

    final evidence = [
      for (final p in [...malicious, ...highRisk, ...suspicious])
        for (final reason in p.evidence)
          DetectionEvidence(key: reason, value: p.package),
    ];

    final threatDetected =
        malicious.isNotEmpty || highRisk.isNotEmpty || suspicious.isNotEmpty;
    return _result(threatDetected: threatDetected, evidence: evidence);
  }

  /// Pure, deterministic: builds one [AppRiskProfile] from a native
  /// intelligence row and a reputation lookup. Public and static so tests
  /// can exercise the classification rules directly, without a platform
  /// channel — matching every other detector's pure-classification-layer
  /// testing convention in this SDK.
  static AppRiskProfile buildProfile(
    Map<String, Object?> row,
    ReputationProvider provider,
  ) {
    final package = row['package'] as String? ?? '';
    final signingSha256 = row['signing_sha256'] as String?;
    final installerPackage = row['installer_package'] as String?;
    final installSource = InstallSourceX.classify(installerPackage);

    final record = provider.lookup(
      package: package,
      certificateSha256: signingSha256,
    );

    final evidence = <String>[];
    AppRiskClassification classification;
    IntelConfidence confidence;
    var signingMismatch = false;

    if (record == null) {
      classification = AppRiskClassification.unknown;
      confidence = IntelConfidence.low;
      evidence.add('no_reputation_record');
    } else {
      classification = record.classification;
      confidence = record.confidence;
      evidence.add(record.threatClass);
      if (record.threatClass == 'unexpected_signing_identity') {
        signingMismatch = true;
        evidence.add('signing_mismatch');
      }
    }

    if (installSource == InstallSource.sideloaded ||
        installSource == InstallSource.unknownSource) {
      evidence.add('untrusted_install_source');
      // An untrusted source alone never manufactures a threat classification
      // out of nothing — see the milestone's own instruction: one sensitive
      // signal is not malware. It can only escalate an ALREADY-suspicious
      // finding, never promote unknown/clean on its own.
      if (classification == AppRiskClassification.suspicious) {
        classification = AppRiskClassification.highRisk;
      }
    }

    return AppRiskProfile(
      package: package,
      versionName: row['version_name'] as String?,
      versionCode: (row['version_code'] as num?)?.toInt(),
      installSource: installSource,
      observedCertificateSha256: signingSha256,
      signingMismatch: signingMismatch,
      classification: classification,
      confidence: confidence,
      evidence: evidence,
      matchedRecord: record,
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════
// App integrity
// ═══════════════════════════════════════════════════════════════════════

/// The app binary has been modified since signing.
class TamperDetector extends _NativeBoolDetector {
  const TamperDetector();

  @override
  String get detectorId => 'tamper';
  @override
  DetectorType get detectorType => DetectorType.tamper;
  @override
  ThreatCategory get category => ThreatCategory.appIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get nativeMethod => 'isAppTampered';
  @override
  String get title => 'App Tampering';
  @override
  String get description =>
      'Whether the app has been modified from its original signed package.';
}

/// Signing-certificate / repackaging check.
///
/// ## Why this reports NOT_CONFIGURED instead of "secure"
///
/// The native `verifySignature()` compares the running build's certificate
/// against an expected fingerprint supplied by `setExpectedSigningCert`. That
/// setter was **never called from Dart**, so the expected value was always
/// null, so the native check always took its `?: return false` branch and
/// reported "no threat" on every device, forever. The control looked green
/// and verified nothing.
///
/// Rather than leave a dead check presenting as a passing one, this detector
/// reports [DetectionResult.unavailableReason] when no fingerprint has been
/// configured, and only trusts the native verdict once one has. Configure it
/// by calling [configureExpectedCertificate] with the value the backend
/// already stores per app (`registered_apps.signing_cert_sha256`, delivered
/// in the SDK config bundle).
///
/// Server-side pinning at `/api/v1/sdk/activate` is unaffected and remains
/// the authoritative anti-repackaging control — see
/// `sdk_router._enforce_certificate`. This is the on-device companion to it.
class RepackagingDetector extends _BaseDetector {
  const RepackagingDetector();

  static String? _expectedFingerprint;

  /// Supplies the fingerprint the running build must match. Passing `null`
  /// or blank clears it, which puts this detector back into NOT_CONFIGURED.
  static Future<void> configureExpectedCertificate(String? fingerprint) async {
    final normalized = (fingerprint ?? '')
        .replaceAll(RegExp(r'[:\s-]'), '')
        .toUpperCase();
    _expectedFingerprint = normalized.isEmpty ? null : normalized;
    // Push it to native, where verifySignature() compares against it. The
    // handler reads `call.arguments as? String`, so the fingerprint is the
    // argument, not a wrapper map.
    if (_expectedFingerprint != null) {
      await RaspNativeChannel.boolCall(
        'setExpectedSigningCert',
        _expectedFingerprint,
      );
    }
  }

  /// Whether an expected fingerprint has been supplied.
  static bool get isConfigured => _expectedFingerprint != null;

  /// Test seam — clears any configured pin.
  static void resetForTests() => _expectedFingerprint = null;

  @override
  String get detectorId => 'repackage';
  @override
  DetectorType get detectorType => DetectorType.signatureMismatch;
  @override
  ThreatCategory get category => ThreatCategory.appIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get title => 'Signature / Repackaging';
  @override
  String get description =>
      'Whether this build is signed by the expected certificate.';

  @override
  Future<DetectionResult> scan() async {
    if (!isConfigured) {
      return _unavailable(
        'NOT_CONFIGURED — no expected signing certificate supplied to the SDK, '
        'so on-device repackaging detection cannot run. Server-side pinning at '
        'activation is unaffected.',
      );
    }
    final mismatch = await RaspNativeChannel.boolCall('verifySignature');
    if (mismatch == null) {
      return _unavailable(RaspNativeChannel.isSupportedPlatform
          ? 'Native signature check is unavailable on this build'
          : 'Available on Android only');
    }
    return _result(threatDetected: mismatch);
  }
}

/// Installed from somewhere other than an official store.
class UntrustedInstallSourceDetector extends _NativeBoolDetector {
  const UntrustedInstallSourceDetector();

  @override
  String get detectorId => 'untrusted_install_source';
  @override
  DetectorType get detectorType => DetectorType.repackage;
  @override
  ThreatCategory get category => ThreatCategory.appIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get nativeMethod => 'isUntrustedInstallSource';
  @override
  String get title => 'Installation Source';
  @override
  String get description =>
      'Whether the installing package is an official app store.';
}

// ═══════════════════════════════════════════════════════════════════════
// Network security
// ═══════════════════════════════════════════════════════════════════════

/// Active VPN transport / tun interfaces.
class VpnDetector extends _NativeBoolDetector {
  const VpnDetector();

  @override
  String get detectorId => 'vpn';
  @override
  DetectorType get detectorType => DetectorType.vpn;
  @override
  ThreatCategory get category => ThreatCategory.networkSecurity;
  @override
  DetectionSeverity get severity => DetectionSeverity.low;
  @override
  String get nativeMethod => 'isVpnActive';
  @override
  String get title => 'VPN Connection';
  @override
  String get description =>
      'Whether traffic is routed through a VPN tunnel or tun/ppp/tap '
      'interface.';
}

/// System proxy / certificate-interception setup.
class MitmDetector extends _BaseDetector {
  const MitmDetector();

  @override
  String get detectorId => 'mitm';
  @override
  DetectorType get detectorType => DetectorType.proxy;
  @override
  ThreatCategory get category => ThreatCategory.networkSecurity;
  @override
  DetectionSeverity get severity => DetectionSeverity.high;
  @override
  String get title => 'SSL / MITM Detection';
  @override
  String get description =>
      'System proxies and certificate-pinning failures indicating traffic '
      'interception.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }

    // `SslPinningService.isMitmDetected()` ORs a native proxy check with a
    // TLS probe and returns `false` from both `catch` blocks, so a platform
    // failure was indistinguishable from "no interception found". The native
    // half is therefore checked here, where a null reply is visible.
    final nativeProxy = await RaspNativeChannel.boolCall('isMitmDetected');
    if (nativeProxy == null) {
      return _unavailable(
        'Native proxy check did not answer — interception status unknown',
      );
    }
    if (nativeProxy) {
      return _result(
        threatDetected: true,
        evidence: const [
          DetectionEvidence(key: 'source', value: 'native_proxy_check'),
        ],
      );
    }

    // No system proxy. The TLS-pinning probe is a genuine network operation:
    // its failure modes are ordinary connectivity, so a negative result here
    // is a real "nothing found" rather than a swallowed fault.
    try {
      final mitm = await SslPinningService.isMitmDetected();
      return _result(
        threatDetected: mitm,
        evidence: mitm
            ? const [
                DetectionEvidence(key: 'source', value: 'tls_pinning_probe'),
              ]
            : const [],
      );
    } catch (e) {
      return _error('MITM probe failed: $e');
    }
  }
}

/// Public-IP reputation and geo risk.
class HighRiskIpDetector extends _BaseDetector {
  const HighRiskIpDetector();

  @override
  String get detectorId => 'high_risk_ip';
  @override
  DetectorType get detectorType => DetectorType.highRiskIp;
  @override
  ThreatCategory get category => ThreatCategory.networkSecurity;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'IP Reputation';
  @override
  String get description =>
      'Whether the public IP falls in a high-risk region or known '
      'proxy/anonymizer range.';

  @override
  Future<DetectionResult> scan() async {
    try {
      final result = await GeoFilterService.checkHighRiskIp();
      if (result.checkFailed) {
        return _unavailable('IP reputation lookup did not complete');
      }
      return _result(
        threatDetected: result.isRisk,
        evidence: [
          if (result.matchedBlockedCountry)
            const DetectionEvidence(
              key: 'high_risk_ip_signal', value: 'blocked_country'),
          if (result.isProxy)
            const DetectionEvidence(
              key: 'high_risk_ip_signal', value: 'proxy_flag'),
        ],
      );
    } catch (e) {
      return _error('IP reputation lookup failed: $e');
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Privacy & screen
// ═══════════════════════════════════════════════════════════════════════

/// Parsed form of one `{signal, status, detected, reason?}` map returned by
/// `getOverlayEvidence`/`getCloneEvidence`. Shared by both detectors — see
/// docs/OVERLAY_CLONE_SECURITY_AUDIT.md for why the two independent signals
/// each detector reports are never merged into one boolean natively.
class _TwoSignalEvidence {
  final String signal;
  final DetectionStatus status;
  final bool detected;
  final String? reason;

  const _TwoSignalEvidence({
    required this.signal,
    required this.status,
    required this.detected,
    this.reason,
  });

  static _TwoSignalEvidence? parse(Map<String, Object?> map) {
    final signal = map['signal'] as String?;
    if (signal == null) return null;
    final statusName = map['status'] as String?;
    final status = switch (statusName) {
      'DETECTED' => DetectionStatus.detected,
      'NOT_DETECTED' => DetectionStatus.secure,
      'UNKNOWN' => DetectionStatus.unavailable, // no separate UNKNOWN DetectionStatus exists
      'ERROR' => DetectionStatus.error,
      _ => null,
    };
    if (status == null) return null;
    return _TwoSignalEvidence(
      signal: signal,
      status: status,
      detected: map['detected'] == true,
      reason: map['reason'] as String?,
    );
  }
}

/// Shared aggregation for a two-independent-signal native detector
/// (overlay, clone): DETECTED wins if either signal fired; otherwise ERROR
/// only when nothing else could be concluded; otherwise SECURE — an
/// individual signal's UNKNOWN/ERROR sub-state is never hidden (it stays
/// visible in `evidence`), but does not by itself make the whole detector
/// inconclusive when the other signal did reach a real verdict.
mixin _TwoSignalDetector on _BaseDetector {
  String get nativeMethod;
  String Function(String signal) get evidenceKeyFor;

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }
    final channelAlive = await RaspNativeChannel.boolCall('isVpnActive') != null;
    if (!channelAlive) {
      return _unavailable('Native evidence channel did not respond');
    }

    List<Map<String, Object?>> raw;
    try {
      raw = await RaspNativeChannel.mapListCall(nativeMethod);
    } catch (e) {
      return _error('Evidence query failed: $e');
    }
    final entries = raw.map(_TwoSignalEvidence.parse).whereType<_TwoSignalEvidence>().toList();
    if (entries.isEmpty) {
      return _error('No evidence entries returned');
    }

    final detected = entries.where((e) => e.detected);
    final evidence = [
      for (final e in entries)
        DetectionEvidence(
          key: evidenceKeyFor(e.signal),
          value: e.detected,
          note: e.reason ?? e.signal,
        ),
    ];

    if (detected.isNotEmpty) {
      return _result(threatDetected: true, evidence: evidence);
    }
    final anyConclusiveClean = entries.any((e) => e.status == DetectionStatus.secure);
    if (anyConclusiveClean) {
      return _result(threatDetected: false, evidence: evidence);
    }
    // Nothing detected and nothing conclusively clean either — every entry
    // is UNKNOWN/ERROR. Reported as ERROR, never as a silent SECURE.
    return _error('No signal reached a conclusive verdict');
  }
}

/// Another app drawing over this one (tapjacking).
///
/// Two independent signals (Phase 2 of the overlay/clone hardening
/// milestone), never merged into one confidence number natively — evidence
/// carries both, and `EvidenceConfidenceCalculator` derives confidence from
/// how many independently corroborate:
///
/// 1. `system_alert_window_holder` — the original static permission scan
///    (capability, not state).
/// 2. `touch_obscured` — `MotionEvent.FLAG_WINDOW_IS_OBSCURED`, Android's
///    own runtime tapjacking primitive. `UNKNOWN` before any touch has
///    been observed, never silently treated as "not obscured".
class OverlayDetector extends _BaseDetector with _TwoSignalDetector {
  const OverlayDetector();

  @override
  String get detectorId => 'overlay';
  @override
  DetectorType get detectorType => DetectorType.overlay;
  @override
  ThreatCategory get category => ThreatCategory.privacyScreen;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get nativeMethod => 'getOverlayEvidence';
  @override
  String Function(String signal) get evidenceKeyFor => (s) => 'overlay_$s';
  @override
  String get title => 'Overlay Attack';
  @override
  String get description =>
      'Other apps drawing over this one via SYSTEM_ALERT_WINDOW, '
      'corroborated by Android\'s runtime touch-obscured signal.';
}

/// Third-party accessibility services able to read and drive the app.
class AccessibilityDetector extends _NativeBoolDetector {
  const AccessibilityDetector();

  @override
  String get detectorId => 'accessibility';
  @override
  DetectorType get detectorType => DetectorType.accessibility;
  @override
  ThreatCategory get category => ThreatCategory.privacyScreen;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get nativeMethod => 'isAccessibilityAbused';
  @override
  String get title => 'Accessibility Abuse';
  @override
  String get description =>
      'Third-party accessibility services that can read screen content and '
      'act on the user\'s behalf.';
}

/// Screen-capture blocking.
///
/// Unlike every other detector this one *applies* a control rather than
/// observing a condition: it sets the secure-window flag. A failure to apply
/// it is the threat.
/// Whether this device has contacted its backend recently enough to satisfy
/// the customer's offline policy.
///
/// Restores the `offline_compliance` entitlement as a first-class unified
/// capability — it previously existed only in the unreachable
/// `RaspService`. See `docs/OFFLINE_COMPLIANCE_MODEL.md`.
///
/// Every input is injected so the whole detector is testable with no
/// storage, no clock and no network:
///  * the trusted anchor comes from `LicenseManager.lastAuthenticatedContact`
///    (a *verified* entitlement token's server-issued `issued_at`);
///  * the threshold is only honoured when the configuration that carried it
///    authenticated (`ConfigVerificationResult.valid`);
///  * `withinGrace` is reported SECURE, so a user offline inside their
///    allowed window is never a finding.
class OfflineComplianceDetector extends _BaseDetector {
  /// `LicenseManager.allows(Entitlement.offlineCompliance)` at scan time.
  final bool entitled;

  /// `offline_max_minutes` as delivered by configuration, or `null`.
  final int? deliveredThresholdMinutes;

  /// `verification.isAuthenticated` for the configuration that delivered it.
  final bool configurationAuthenticated;

  /// Injectable clock. Defaults to the device clock.
  final DateTime Function() clock;

  /// Injectable anchor source. Defaults to the verified entitlement token.
  final Future<DateTime?> Function() anchorSource;

  final OfflineComplianceStore store;

  OfflineComplianceDetector({
    required this.entitled,
    this.deliveredThresholdMinutes,
    this.configurationAuthenticated = false,
    DateTime Function()? clock,
    Future<DateTime?> Function()? anchorSource,
    this.store = const OfflineComplianceStore(),
  })  : clock = clock ?? DateTime.now,
        anchorSource =
            anchorSource ?? (() => LicenseManager.lastAuthenticatedContact);

  @override
  String get detectorId => 'offline_compliance';
  @override
  DetectorType get detectorType => DetectorType.custom;
  @override
  ThreatCategory get category => ThreatCategory.appIntegrity;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'Offline Compliance';
  @override
  String get description =>
      'Whether this device has completed an authenticated backend check-in '
      'within the period the customer\'s policy allows.';

  @override
  Future<DetectionResult> scan() async {
    final (threshold, thresholdSource) =
        OfflineComplianceEvaluator.resolveThreshold(
      deliveredMinutes: deliveredThresholdMinutes,
      configurationAuthenticated: configurationAuthenticated,
    );

    final now = clock();
    bool storageFailed;
    DateTime? highWaterMark;
    DateTime? anchor;
    try {
      storageFailed = await store.readFailed();
      highWaterMark = storageFailed ? null : await store.readClockHighWaterMark();
      anchor = await anchorSource();
    } catch (e) {
      return _error('Offline-compliance evaluation failed: $e');
    }

    final result = const OfflineComplianceEvaluator().evaluate(
      entitled: entitled,
      anchorIssuedAt: anchor,
      now: now,
      threshold: threshold,
      thresholdSource: thresholdSource,
      clockHighWaterMark: highWaterMark,
      storageFailed: storageFailed,
    );

    // Record the observation *after* evaluating, so this scan's own write
    // cannot mask the very rewind it is meant to detect.
    if (!storageFailed) {
      await store.recordClockObservation(now);
    }

    final evidence = <DetectionEvidence>[
      DetectionEvidence(
        key: 'offline_state',
        value: result.state.name,
        note: result.reason,
      ),
      DetectionEvidence(
        key: 'threshold_minutes',
        value: threshold.inMinutes,
        note: thresholdSource == OfflineThresholdSource.signed
            ? 'From authenticated configuration'
            : 'Safe default — delivered value was absent or unauthenticated',
      ),
      if (result.elapsed != null)
        DetectionEvidence(
          key: 'minutes_since_authenticated_contact',
          value: result.elapsed!.inMinutes,
        ),
    ];

    return switch (result.detectionStatus) {
      DetectionStatus.detected =>
        _result(threatDetected: true, evidence: evidence),
      DetectionStatus.secure =>
        _result(threatDetected: false, evidence: evidence),
      DetectionStatus.unavailable =>
        _unavailable(result.reason ?? 'Offline compliance is not licensed'),
      DetectionStatus.unknown => _build(
          status: DetectionStatus.unknown,
          evidence: evidence,
          reason: result.reason,
        ),
      DetectionStatus.error =>
        _error(result.reason ?? 'Offline-compliance state unavailable'),
    };
  }
}

class ScreenCaptureShieldDetector extends _BaseDetector {
  const ScreenCaptureShieldDetector();

  @override
  String get detectorId => 'screenshot_protection';
  @override
  DetectorType get detectorType => DetectorType.screenshot;
  @override
  ThreatCategory get category => ThreatCategory.privacyScreen;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'Screen Capture Shield';
  @override
  String get description =>
      'The secure-window flag that blocks screenshots and screen recording.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }

    // Reads the REAL window state; does not write it.
    //
    // FLAG_SECURE is established once at `MainActivity.onCreate()` (see
    // docs/ONEPLUS_FLAG_SECURE_PRODUCTION_FIX.md). This scan therefore
    // *verifies* rather than re-applies — applying the flag mid-session to
    // an already-rendering Flutter surface is what stalled the compositor
    // on OnePlus/Android 16, and re-applying it on every scan would
    // reintroduce exactly that transition.
    //
    // `isScreenshotBlockingActive` now returns the live
    // `window.attributes.flags & FLAG_SECURE` read-back rather than a
    // Kotlin bookkeeping boolean, so the three cases stay honestly apart:
    //
    //   null  → the real state could not be read     → UNAVAILABLE
    //   false → the flag is genuinely NOT set        → ERROR (a control that
    //                                                  should work, does not)
    //   true  → the secure-window flag IS set        → SECURE
    //
    // Reporting the false case as ERROR rather than SECURE is the point:
    // screenshots are not being blocked, and previously that looked green.
    final applied =
        await RaspNativeChannel.boolCall('isScreenshotBlockingActive');
    if (applied == null) {
      return _unavailable(
        'Screen-capture protection is not implemented on this platform',
      );
    }
    if (!applied) {
      return _error(
        'Screen-capture protection could not be enabled — screenshots and '
        'screen recording are NOT blocked',
      );
    }

    // Real screenshot-EVENT detection (Remote Security Control Plane
    // milestone), layered on top of the existing prevention state-check
    // above — a distinct native capability (Activity.ScreenCaptureCallback,
    // API 34+), not a re-derivation of it. Drained once per scan
    // (RaspSecurityChannelHandler.drainScreenshotEventEvidence): any
    // screenshot captured since the previous scan surfaces here as a real,
    // evidenced detection, which SecurityEventCenter.recordDetections then
    // turns into a normal `detection`-typed security event — the SDK's one
    // event pipeline, not a second one. See that native method's doc for
    // exactly why this is UNAVAILABLE below API 34 rather than
    // approximated, and why there is no equivalent for screen
    // recording/casting — no Android API observes those for a passive app.
    final eventEvidence =
        await RaspNativeChannel.mapCall('getScreenshotEventEvidence');
    final eventSupported = eventEvidence?['supported'] == true;
    final eventDetected = eventEvidence?['detected'] == true;
    if (eventSupported && eventDetected) {
      return _result(
        threatDetected: true,
        evidence: [
          const DetectionEvidence(key: 'flag_secure', value: true),
          const DetectionEvidence(key: 'screenshot_event', value: true),
          DetectionEvidence(
            key: 'screenshot_event_count',
            value: eventEvidence!['count'],
          ),
        ],
      );
    }

    return _result(
      threatDetected: false,
      evidence: [
        const DetectionEvidence(key: 'flag_secure', value: true),
        if (eventSupported)
          const DetectionEvidence(key: 'screenshot_event', value: false),
      ],
    );
  }
}

/// Real signal for "is content on this device potentially being mirrored,
/// cast, or presented on another screen right now" — `DisplayManager`-backed
/// (`RaspSecurityChannelHandler.externalDisplayState`), Android only.
///
/// **Honest limit, stated once here rather than re-derived at every call
/// site**: this reports the PRESENCE of a non-default display (an external
/// monitor, a Wi-Fi/Cast/Miracast receiver, a `Presentation` target) — it
/// cannot prove this app's own content is actually being rendered there,
/// because Android does not expose that distinction to an app that has not
/// itself created a `Presentation` on that display. It is real evidence, not
/// a guess, but it is a presence signal, not a screen-sharing confirmation —
/// see docs/SCREEN_CAPTURE_PROTECTION.md's capability matrix.
class ExternalDisplayDetector extends _BaseDetector {
  const ExternalDisplayDetector();

  @override
  String get detectorId => 'external_display';
  @override
  DetectorType get detectorType => DetectorType.screenshot;
  @override
  ThreatCategory get category => ThreatCategory.privacyScreen;
  @override
  DetectionSeverity get severity => DetectionSeverity.medium;
  @override
  String get title => 'External Display / Mirroring';
  @override
  String get description =>
      'Detects a connected external, wireless, or presentation display — a '
      'possible screen-mirroring or casting surface.';

  @override
  Future<DetectionResult> scan() async {
    if (!RaspNativeChannel.isSupportedPlatform) {
      return _unavailable('Available on Android only');
    }
    final state = await RaspNativeChannel.mapCall('getExternalDisplayState');
    if (state == null || state['supported'] != true) {
      return _unavailable(
        'External-display detection is not implemented on this platform',
      );
    }
    final detected = state['external_display_detected'] == true;
    final count = state['external_display_count'];
    return _result(
      threatDetected: detected,
      evidence: [
        DetectionEvidence(key: 'external_display_count', value: count),
      ],
    );
  }
}

// ═══════════════════════════════════════════════════════════════════════
// Registry
// ═══════════════════════════════════════════════════════════════════════

/// The detectors RASP Shield ships, in a stable order.
///
/// [debugMode] is threaded in rather than read from `kDebugMode` here so the
/// whole set is constructible in a test.
List<SecurityDetector> builtinDetectors({required bool debugMode}) => [
      // Device integrity
      const RootDetector(),
      const EmulatorDetector(),
      const DeviceBindingDetector(),
      const DeviceFingerprintDetector(),
      const CloneDetector(),
      const DeveloperModeDetector(),
      const AdbEnabledDetector(),
      const UsbConnectionDetector(),
      const DeviceLockMissingDetector(),
      const SecureHardwareDetector(),
      // Runtime protection
      const FridaDetector(),
      DebuggerDetector(debugMode: debugMode),
      const ReverseEngineeringToolsDetector(),
      const HookDetector(),
      const RiskyAppDetector(),
      const AppIntelligenceDetector(),
      // App integrity
      const TamperDetector(),
      const RepackagingDetector(),
      const UntrustedInstallSourceDetector(),
      // Offline compliance — entitlement- and signature-gated inside the
      // detector, so an unlicensed customer gets UNAVAILABLE rather than
      // enforcement. See docs/OFFLINE_COMPLIANCE_MODEL.md.
      OfflineComplianceDetector(
        entitled: LicenseManager.allows(Entitlement.offlineCompliance),
        deliveredThresholdMinutes: RemoteConfigManager.offlineMaxMinutes,
        configurationAuthenticated: RemoteConfigManager.isConfigAuthenticated,
      ),
      // Network security
      const VpnDetector(),
      const MitmDetector(),
      const HighRiskIpDetector(),
      // Privacy & screen
      const OverlayDetector(),
      const AccessibilityDetector(),
      const ScreenCaptureShieldDetector(),
      const ExternalDisplayDetector(),
    ];

/// A registry preloaded with [builtinDetectors].
SecurityDetectorRegistry defaultRegistry({required bool debugMode}) {
  final registry = SecurityDetectorRegistry();
  for (final detector in builtinDetectors(debugMode: debugMode)) {
    registry.register(detector);
  }
  return registry;
}
