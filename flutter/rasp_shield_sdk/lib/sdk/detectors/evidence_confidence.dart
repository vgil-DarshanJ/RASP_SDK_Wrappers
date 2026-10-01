import '../core/core.dart';

/// Derives real [DetectionConfidence] from the evidence a detector already
/// produced, instead of the flat `high` every detector defaulted to.
///
/// ## Why this exists
///
/// `DetectionResult` defaults to `confidence: high` for backward
/// compatibility, and `_BaseDetector._build()` never overrode it — so every
/// detection, from a single spoofable Build field to a five-signal Frida
/// verdict, carried identical weight. See `docs/DETECTOR_CONFIDENCE_FLOW.md`
/// for the full trace.
///
/// This calculator is pure and deterministic: the same evidence list always
/// produces the same confidence. No randomness, no ML, no network, no backend
/// dependency — exactly the model the milestone brief requires.
///
/// ## Mirrors native classification, does not re-derive it
///
/// The hard/soft signal sets below are **copied from the native pure-logic
/// layer** (`RaspEmulatorAnalysis.hardSignals`, `RaspSignalAnalysis.
/// softFridaSignals`), the same way `RiskEngine.detectorWeights` already
/// mirrors the backend scorer's weights. This is a documented duplication,
/// not a guess — each set is covered by the 186 existing native tests on the
/// Kotlin side, and mismatches are guarded by
/// `evidence_confidence_test.dart` here. No native file is touched.
class EvidenceConfidenceCalculator {
  const EvidenceConfidenceCalculator();

  /// Evidence keys that carry one repeated signal id per entry, keyed by the
  /// detector that produces them. A detector not in this map has no known
  /// signal-family model and falls back to [_fallbackConfidence].
  static const Map<String, String> _signalKeyByDetector = {
    'root_jailbreak': 'root_signal',
    'emulator': 'emulator_signal',
    'frida': 'frida_signal',
    'debugger': 'debugger_signal',
    'device_fingerprint': 'device_fingerprint_signal',
    'high_risk_ip': 'high_risk_ip_signal',
    'mitm': 'source',
    'hook_detection': 'hook_signal',
  };

  /// Bookkeeping evidence keys that describe the evidence rather than being a
  /// signal themselves — never counted toward confidence.
  static const Set<String> _nonSignalKeys = {'signal_count'};

  /// Emulator signals treated as hard by `RaspEmulatorAnalysis.hardSignals`.
  static const Set<String> _hardEmulatorSignals = {
    'emulator_file', 'emulator_package', 'qemu_prop', 'qemu_boot_prop',
    'virtual_device_prop', 'no_accelerometer', 'emulator_carrier',
    'build_hardware',
  };

  /// Frida signals treated as soft by `RaspSignalAnalysis.softFridaSignals`.
  /// Everything else in the Frida signal set is hard.
  static const Set<String> _softFridaSignals = {
    'frida_thread_glib', 'frida_port_open',
  };

  /// Hook signals treated as soft by `RaspHookAnalysis.softHookSignals`.
  /// `hook_framework_lib` and `hook_native_method` are hard — the latter
  /// observes the hook's own mechanism (an ART method reporting itself as
  /// `native` when it should not), the strongest signal this detector has.
  static const Set<String> _softHookSignals = {
    'hook_rwx_mapping', 'hook_suspicious_lib_path',
  };

  // Root has no hard/soft split natively — `RaspRootAnalysis.isRooted()` is
  // `isNotEmpty()`, because a `su` binary or Magisk artefact has no innocent
  // explanation on a retail handset. Every root signal counts as hard here,
  // for the same reason.

  /// Computes confidence for one [DetectionResult] from its own evidence.
  ///
  /// Returns the result's existing confidence unchanged for statuses where
  /// confidence is not meaningful — `secure`, `unavailable`, `unknown`,
  /// `error` all keep whatever they were constructed with, since this
  /// calculator only has an opinion about *detected threats*.
  DetectionConfidence confidenceFor(DetectionResult result) {
    if (result.status != DetectionStatus.detected) return result.confidence;

    final signalKey = _signalKeyByDetector[result.detectorId];
    if (signalKey == null) return _fallbackConfidence(result);

    final signals = _valuesFor(result, signalKey);
    if (signals.isEmpty) {
      // The detector is one of the four known families but reported no
      // signal list this time (e.g. a future native change starts answering
      // with a bare boolean). Falls back rather than assuming certainty.
      return DetectionConfidence.medium;
    }

    switch (result.detectorId) {
      case 'root_jailbreak':
        return _rootConfidence(signals);
      case 'emulator':
        return _emulatorConfidence(signals);
      case 'frida':
        return _fridaConfidence(signals);
      case 'debugger':
        return _debuggerConfidence(signals);
      case 'device_fingerprint':
        return _deviceFingerprintConfidence(signals);
      case 'high_risk_ip':
        return _highRiskIpConfidence(signals);
      case 'mitm':
        return _mitmConfidence(signals);
      case 'hook_detection':
        return _hookConfidence(signals);
      default:
        // Unreachable — signalKey came from this same map — kept explicit
        // rather than `!` so a future edit to the map cannot silently throw.
        return DetectionConfidence.medium;
    }
  }

  /// Every root signal is hard by the native model. Confidence scales with
  /// how many independent families corroborate, capped at [veryHigh] for
  /// three or more — matching `confidenceFromSources`'s existing curve.
  DetectionConfidence _rootConfidence(List<String> signals) {
    if (signals.length == 1) return DetectionConfidence.medium;
    if (signals.length == 2) return DetectionConfidence.high;
    return DetectionConfidence.veryHigh;
  }

  DetectionConfidence _emulatorConfidence(List<String> signals) {
    final hard = signals.where(_hardEmulatorSignals.contains).length;
    final soft = signals.length - hard;
    if (hard >= 2) return DetectionConfidence.veryHigh;
    if (hard == 1) {
      return soft >= 1 ? DetectionConfidence.veryHigh : DetectionConfidence.high;
    }
    // Soft-only — mirrors the native verdict threshold (needs ≥2 to convict
    // at all), so a soft-only detection here is inherently borderline.
    if (soft >= 2) return DetectionConfidence.medium;
    return DetectionConfidence.low;
  }

  DetectionConfidence _fridaConfidence(List<String> signals) {
    final hard = signals.where((s) => !_softFridaSignals.contains(s)).length;
    final soft = signals.length - hard;
    if (hard >= 2) return DetectionConfidence.veryHigh;
    if (hard == 1) {
      return soft >= 1 ? DetectionConfidence.veryHigh : DetectionConfidence.high;
    }
    if (soft >= 2) return DetectionConfidence.medium;
    return DetectionConfidence.low;
  }

  /// [signals] here are always genuine runtime indicators (`jdwp_connected`,
  /// `waiting_for_debugger`, `tracer_pid`): `DebuggerDetector.scan()` already
  /// filters `debuggable_flag` out before it becomes `debugger_signal`
  /// evidence — see `builtin_detectors.dart`'s `if (signal !=
  /// 'debuggable_flag')` — so it can never reach this method. The
  /// `build_mode`-only case (a debug build with no attached debugger) never
  /// carries a `debugger_signal` entry at all, so it is handled by
  /// [_fallbackConfidence] via the "no signal key produced any values"
  /// path above, landing on the same [DetectionConfidence.medium] this
  /// method would give a bare posture signal — the two paths agree without
  /// duplicating logic.
  DetectionConfidence _debuggerConfidence(List<String> signals) {
    if (signals.length >= 2) return DetectionConfidence.veryHigh;
    // tracer_pid alone is the load-bearing native signal (a real ptrace
    // observation) — treated as high on its own, same weight as a single
    // hard Frida or emulator signal.
    return DetectionConfidence.high;
  }

  /// `DeviceFingerprintDetector` reports up to five independent posture
  /// facts (screen lock, ADB, SELinux, install source, hardware-identity
  /// change) as `device_fingerprint_signal` evidence — see
  /// `DeviceFingerprintService.checkDeviceRisk()`. No native hard/soft split
  /// exists for these; each is an equally-weighted, independently-derived
  /// fact, so the model mirrors root's pure corroboration-count curve.
  DetectionConfidence _deviceFingerprintConfidence(List<String> signals) {
    if (signals.length == 1) return DetectionConfidence.medium;
    if (signals.length == 2) return DetectionConfidence.high;
    return DetectionConfidence.veryHigh;
  }

  /// `HighRiskIpDetector` can report at most two independent signals
  /// (`blocked_country`, `proxy_flag`) — see
  /// `GeoFilterService.checkHighRiskIp()`. With a ceiling of two, `veryHigh`
  /// is unreachable by construction; two agreeing signals is the strongest
  /// this detector can ever corroborate itself, hence `high`.
  DetectionConfidence _highRiskIpConfidence(List<String> signals) {
    if (signals.length >= 2) return DetectionConfidence.high;
    return DetectionConfidence.medium;
  }

  /// `MitmDetector` attaches exactly one `source` evidence item per positive
  /// result — `native_proxy_check` or `tls_pinning_probe` are mutually
  /// exclusive branches in `MitmDetector.scan()`, so multiple can never fire
  /// in the same scan and this can never reach `veryHigh` on corroboration
  /// count. Both sources are direct, hard-to-forge observations (an actual
  /// system proxy configuration, or a real TLS handshake probe) rather than a
  /// spoofable flag, which is why this is `high` rather than the generic
  /// fallback's `medium` — a single strong signal, per the confidence
  /// model's own "ONE strong signal → HIGH" rule.
  DetectionConfidence _mitmConfidence(List<String> signals) =>
      DetectionConfidence.high;

  /// Mirrors `_fridaConfidence`'s hard/soft curve exactly, against
  /// `_softHookSignals`. `hook_native_method` and `hook_framework_lib` are
  /// hard; `hook_rwx_mapping` and `hook_suspicious_lib_path` are soft —
  /// mirroring `RaspHookAnalysis.softHookSignals`, which itself mirrors the
  /// native verdict threshold (`hookVerdict`: 1 hard, or 2 soft, to convict
  /// at all), so a soft-only detection here is inherently the weakest case
  /// the native layer would even report as a threat.
  DetectionConfidence _hookConfidence(List<String> signals) {
    final hard = signals.where((s) => !_softHookSignals.contains(s)).length;
    final soft = signals.length - hard;
    if (hard >= 2) return DetectionConfidence.veryHigh;
    if (hard == 1) {
      return soft >= 1 ? DetectionConfidence.veryHigh : DetectionConfidence.high;
    }
    if (soft >= 2) return DetectionConfidence.medium;
    return DetectionConfidence.low;
  }

  /// Confidence for a detected threat with no known signal-family model —
  /// either a boolean-only detector (`re_tools`, `mitm`, `overlay`, …, via
  /// `_NativeBoolDetector`, which carries zero evidence) or an
  /// evidence-bearing one this calculator has not been taught about yet
  /// (e.g. `TamperDetector`'s single `reason` string).
  ///
  /// Counts evidence generically, excluding bookkeeping keys. This is
  /// deliberately conservative: without knowing which evidence items are
  /// independent signal families versus restatements of the same fact, more
  /// evidence items cannot be assumed to mean more independent corroboration
  /// — so this never exceeds [DetectionConfidence.high], reserving
  /// [DetectionConfidence.veryHigh] for the four families whose independence
  /// this calculator actually understands.
  DetectionConfidence _fallbackConfidence(DetectionResult result) {
    final meaningful = result.evidence
        .where((e) => !_nonSignalKeys.contains(e.key))
        .length;
    if (meaningful == 0) {
      // A boolean-only positive: one native yes/no, nothing to weigh. This is
      // a real, if modest, positive result — never LOW, which would suggest
      // the detector barely noticed. It genuinely detected something; it just
      // cannot corroborate itself further. See docs/CONFIDENCE_MODEL.md §2.3.
      return DetectionConfidence.medium;
    }
    if (meaningful >= 2) return DetectionConfidence.high;
    return DetectionConfidence.medium;
  }

  /// Values of every evidence entry under [key] in [result].
  static List<String> _valuesFor(DetectionResult result, String key) => [
        for (final e in result.evidence)
          if (e.key == key) e.value.toString(),
      ];
}
