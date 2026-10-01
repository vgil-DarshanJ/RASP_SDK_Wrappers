import 'package:flutter/foundation.dart';

import 'app_intelligence.dart';

/// Looks up a package against threat intelligence.
///
/// ## Architecture
///
/// ```
/// ReputationProvider (abstract)
///     ├── LocalReputationProvider — this SDK's own curated database (built)
///     └── (future) an external provider a customer configures — NOT built
///                  this phase; the abstraction exists so one can be added
///                  without touching any caller.
/// ```
///
/// The SDK never depends on an external service to function: every risky-app
/// finding possible today comes from [LocalReputationProvider] alone. A
/// future external provider would be consulted as *additional* corroborating
/// evidence, never as a replacement — see `docs/MALWARE_RISK_INTELLIGENCE.md`
/// §"Reputation architecture" for why local-first is the permanent default,
/// not a placeholder for a real backend.
abstract class ReputationProvider {
  /// Look up one package (and, if known, its observed signing certificate).
  /// Returns `null` when this provider has no record — never a synthetic
  /// [AppRiskClassification.clean] record standing in for "no data".
  ThreatIntelRecord? lookup({required String package, String? certificateSha256});

  /// A short, stable name for this provider, used as
  /// [AppRiskProfile]-adjacent evidence (`source`) and in security events —
  /// e.g. `'rasp_local_db'`.
  String get name;
}

/// The SDK's built-in, offline-first reputation database.
///
/// Deliberately **not** loaded from remote config: threat intelligence is
/// data a customer's signed policy can *filter or act on* (see
/// `ApiProtectionPolicy`'s precedent for what signed config may govern), but
/// the record set itself ships compiled into the SDK, exactly like the
/// existing `knownRiskyPackages` native list this extends. An attacker with
/// control of the network cannot inject entries by forging a config
/// response, because there is no code path that would ever read one from
/// there.
///
/// A customer wanting their own deny-list adds packages to
/// [customerDenylist] via [LocalReputationProvider.withCustomerEntries] at
/// `RaspShield.initialize()` time — host-app code the customer controls and
/// ships in their own build, not remote data.
class LocalReputationProvider implements ReputationProvider {
  @override
  String get name => 'rasp_local_db';

  final Map<String, List<ThreatIntelRecord>> _byPackage;

  LocalReputationProvider._(this._byPackage);

  /// The default, production database — the same seven remote-access /
  /// instrumentation-framework packages the native `<queries>` declaration
  /// and `knownRiskyPackages` map have carried since the Anti-Bypass phase,
  /// now expressed as full [ThreatIntelRecord]s instead of a bare name+tag
  /// pair. Extending this list requires ALSO adding the package to the
  /// plugin's `<queries>` block — see [app_intelligence.dart]'s library doc
  /// — so the two are kept in one place,
  /// `RaspSecurityChannelHandler.knownRiskyPackages`, and this Dart list
  /// mirrors it. A test (`app_intelligence_test.dart`) asserts the two never
  /// drift apart.
  static final List<ThreatIntelRecord> defaultDatabase = [
    const ThreatIntelRecord(
      package: 'com.teamviewer.quicksupport.market',
      threatClass: 'remote_access_tool',
      classification: AppRiskClassification.highRisk,
      confidence: IntelConfidence.high,
      source: 'rasp_local_db',
      description: 'TeamViewer QuickSupport — legitimate remote-support '
          'tool, high risk when present alongside a banking session because '
          'it can grant screen/input control to a remote party.',
    ),
    const ThreatIntelRecord(
      package: 'com.teamviewer.host.market',
      threatClass: 'remote_access_tool',
      classification: AppRiskClassification.highRisk,
      confidence: IntelConfidence.high,
      source: 'rasp_local_db',
      description: 'TeamViewer Host — persistent unattended remote access.',
    ),
    const ThreatIntelRecord(
      package: 'com.anydesk.anydeskandroid',
      threatClass: 'remote_access_tool',
      classification: AppRiskClassification.highRisk,
      confidence: IntelConfidence.high,
      source: 'rasp_local_db',
      description: 'AnyDesk remote desktop client.',
    ),
    const ThreatIntelRecord(
      package: 'com.rsupport.mobizen.remote',
      threatClass: 'remote_access_tool',
      classification: AppRiskClassification.highRisk,
      confidence: IntelConfidence.high,
      source: 'rasp_local_db',
      description: 'Mobizen remote control / screen mirroring.',
    ),
    const ThreatIntelRecord(
      package: 'com.remotepc.rpcmobile',
      threatClass: 'remote_access_tool',
      classification: AppRiskClassification.highRisk,
      confidence: IntelConfidence.high,
      source: 'rasp_local_db',
      description: 'RemotePC mobile remote-access client.',
    ),
    const ThreatIntelRecord(
      package: 'de.robv.android.xposed',
      threatClass: 'instrumentation_framework',
      classification: AppRiskClassification.knownMalicious,
      confidence: IntelConfidence.confirmed,
      source: 'rasp_local_db',
      description: 'Xposed framework — runtime code injection into every '
          'app on the device, including this one.',
    ),
    const ThreatIntelRecord(
      package: 'com.saurik.substrate',
      threatClass: 'instrumentation_framework',
      classification: AppRiskClassification.knownMalicious,
      confidence: IntelConfidence.confirmed,
      source: 'rasp_local_db',
      description: 'Cydia Substrate — native/Java hooking framework.',
    ),
  ];

  /// Builds the production provider from [defaultDatabase] plus any
  /// customer-supplied entries. [customerDenylist] is validated the same way
  /// as the built-in set — an entry with a malformed package name is dropped
  /// with a debug log, never allowed to throw and take down initialization.
  factory LocalReputationProvider({
    List<ThreatIntelRecord> customerDenylist = const [],
  }) {
    final all = [...defaultDatabase, ...customerDenylist];
    final byPackage = <String, List<ThreatIntelRecord>>{};
    for (final record in all) {
      if (record.package.isEmpty) {
        debugPrint('[RASP-TRACE] APP-INTEL dropped a record with an empty '
            'package name from ${record.source}');
        continue;
      }
      (byPackage[record.package] ??= []).add(record);
    }
    return LocalReputationProvider._(byPackage);
  }

  @visibleForTesting
  factory LocalReputationProvider.forTests(List<ThreatIntelRecord> records) =>
      LocalReputationProvider._({
        for (final r in records) r.package: [r],
      });

  @override
  ThreatIntelRecord? lookup({
    required String package,
    String? certificateSha256,
  }) {
    final candidates = _byPackage[package];
    if (candidates == null || candidates.isEmpty) return null;

    // A record scoped to a specific certificate must match it; a
    // package-only record (certificateSha256 == null) matches regardless of
    // signer. Certificate-scoped records are checked first so a
    // counterfeit-reference entry (see `docs/MALWARE_THREAT_MODEL.md`
    // §"Counterfeit detection") outranks a looser package-only one for the
    // same package.
    for (final r in candidates) {
      if (r.certificateSha256 != null &&
          r.certificateSha256 == certificateSha256) {
        return r;
      }
    }
    for (final r in candidates) {
      if (r.certificateSha256 == null) return r;
    }
    // Every candidate is certificate-scoped and none matched — this is
    // itself the counterfeit signal: a known package name whose observed
    // signer matches no record this database expected. Returned as a
    // synthetic record so callers get one consistent return type rather
    // than a second "did the certificate not match" out-parameter.
    final reference = candidates.first;
    return ThreatIntelRecord(
      package: package,
      certificateSha256: certificateSha256,
      threatClass: 'unexpected_signing_identity',
      classification: AppRiskClassification.suspicious,
      confidence: IntelConfidence.medium,
      source: name,
      description: 'Package name matches a known entry '
          '(${reference.threatClass}) but the observed signing certificate '
          'does not match any expected certificate for it.',
    );
  }
}
