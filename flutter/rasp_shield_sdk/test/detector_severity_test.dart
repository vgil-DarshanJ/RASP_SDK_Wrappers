// F-26: descriptor severities equal the backend's canonical table.
// Real: RaspDetectorDescriptor and test/fixtures/detector_severities.json
// (exported from BE/src/detectors/severity.ts with `npm run
// export:severities`). When the backend checkout is in this workspace, the
// fixture is also compared with it.
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rasp_shield/sdk/lean_session.dart';

void main() {
  final copy = (jsonDecode(File('test/fixtures/detector_severities.json').readAsStringSync())
      as Map<String, dynamic>)['severities'] as Map<String, dynamic>;

  test('every engine descriptor has the backend severity', () {
    for (final id in RaspDetectorDescriptor.knownIds) {
      expect(copy.containsKey(id), isTrue, reason: '$id is not in the backend table');
      expect(RaspDetectorDescriptor.forId(id).severity.name, copy[id], reason: id);
    }
  });

  final backend = File('../../../FROUNTEND_BACKEND_RASPOWN/BE/src/detectors/severity.ts');
  test('the fixture matches the backend table', () {
    final source = backend.readAsStringSync();
    final start = source.indexOf('DETECTOR_SEVERITY');
    final table = source.substring(start, source.indexOf('};', start));
    final be = {
      for (final m in RegExp(r'^\s+([a-z_]+): "(critical|high|medium|low)",', multiLine: true).allMatches(table)) m.group(1)!: m.group(2)!,
    };
    expect(be.length, greaterThan(40));
    expect(copy, be);
  }, skip: backend.existsSync() ? false : 'backend checkout not in this workspace');
}
