import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/core/core.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

/// Every detector id the Kotlin engine can report must have a specific
/// descriptor (title, category, severity) — never the generic "Security Check".
///
/// The ids are read from the engine's source (RaspLeanSession.kt and the probe
/// files it references), so a detector added to the engine without a
/// descriptor here fails this test. The engine is found at
/// ../../../rashield-sdk-publish (this workspace's layout) or $RASP_ENGINE_SRC.
void main() {
  final engineDir = Directory(
    Platform.environment['RASP_ENGINE_SRC'] ??
        '../../../rashield-sdk-publish/src/main/kotlin/com/shieldsdk/rasp',
  );

  Set<String> engineDetectorIds() {
    final session = File('${engineDir.path}/RaspLeanSession.kt');
    if (!session.existsSync()) {
      fail('Engine source not found at ${session.absolute.path}; set RASP_ENGINE_SRC.');
    }
    final src = session.readAsStringSync();
    final ids = <String>{};
    // add(config.someFlag, "literal_id") { ... }
    for (final m in RegExp(r'add\(config\.\w+,\s*"([a-z_]+)"\)').allMatches(src)) {
      ids.add(m.group(1)!);
    }
    // add(config.someFlag, RaspXxxProbes.DETECTOR_ID) { ... }
    for (final m in RegExp(r'add\(config\.\w+,\s*(Rasp\w+)\.DETECTOR_ID\)').allMatches(src)) {
      final probe = File('${engineDir.path}/${m.group(1)}.kt').readAsStringSync();
      final id = RegExp(r'const val DETECTOR_ID = "([a-z_]+)"').firstMatch(probe);
      expect(id, isNotNull, reason: 'no DETECTOR_ID constant in ${m.group(1)}.kt');
      ids.add(id!.group(1)!);
    }
    // The four basic controls: RaspCheckResult("id", ...) in controlResults().
    for (final m in RegExp(r'RaspCheckResult\("([a-z_]+)"').allMatches(src)) {
      ids.add(m.group(1)!);
    }
    return ids;
  }

  test('every detector id in the engine has a non-generic descriptor', () {
    final ids = engineDetectorIds();
    // Guard against the parsing silently matching nothing.
    expect(ids, containsAll(<String>['root_jailbreak', 'hook_detection', 'malware_reputation', 'screenshot_protection']));
    expect(ids.length, greaterThanOrEqualTo(37));

    final generic = ids.where((id) => RaspDetectorDescriptor.forId(id).isGeneric).toList()..sort();
    expect(generic, isEmpty, reason: 'detector ids that would show as "Security Check": $generic');
    for (final id in ids) {
      expect(RaspDetectorDescriptor.forId(id).title, isNot('Security Check'), reason: id);
    }
  });

  test('an unknown id still falls back to the generic descriptor', () {
    expect(RaspDetectorDescriptor.forId('not_a_detector').isGeneric, isTrue);
    expect(RaspDetectorDescriptor.forId('not_a_detector').title, 'Security Check');
  });

  test('Task 3a-3c detectors use the dashboard title, category and severity', () {
    const expected = <String, (String, ThreatCategory, DetectionSeverity)>{
      'mock_location': ('Mock Location', ThreatCategory.deviceIntegrity, DetectionSeverity.high),
      'time_spoofing': ('Time Spoofing', ThreatCategory.deviceIntegrity, DetectionSeverity.medium),
      'unsafe_wifi': ('Unsafe Wi-Fi', ThreatCategory.networkSecurity, DetectionSeverity.medium),
      'screen_recording': ('Screen Recording', ThreatCategory.privacyScreen, DetectionSeverity.high),
      'vishing_call': ('Call During App Use', ThreatCategory.privacyScreen, DetectionSeverity.high),
      'sim_change': ('SIM Change', ThreatCategory.deviceIntegrity, DetectionSeverity.high),
      'third_party_keyboard': ('Third-party Keyboard', ThreatCategory.privacyScreen, DetectionSeverity.medium),
      'task_hijack': ('Task Hijacking', ThreatCategory.appIntegrity, DetectionSeverity.high),
      'device_state_attestation': ('Device State Attestation', ThreatCategory.deviceIntegrity, DetectionSeverity.high),
      'malware_reputation': ('Known Malware Installed', ThreatCategory.deviceIntegrity, DetectionSeverity.critical),
    };
    expected.forEach((id, value) {
      final d = RaspDetectorDescriptor.forId(id);
      expect((d.title, d.category, d.severity), value, reason: id);
    });
  });

  test('category headings match the dashboard wording', () {
    expect(ThreatCategory.deviceIntegrity.heading, 'Device Integrity');
    expect(ThreatCategory.privacyScreen.heading, 'Privacy & Screen');
    expect(ThreatCategory.values.map((c) => c.heading).toSet().length, ThreatCategory.values.length);
  });
}
