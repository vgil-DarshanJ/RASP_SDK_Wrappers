/// RASP Shield Malware & Risky-App Intelligence — normalized data model.
///
/// ## What this is not
///
/// Not a malware scanner and not a general installed-app inventory. Android
/// 11+ package-visibility rules mean an ordinary app can only see packages it
/// explicitly declares in its manifest's `<queries>` block (or a handful of
/// implicit exemptions that do not apply here) — see
/// `docs/INSTALLED_APP_SECURITY.md` for the full platform audit. This SDK
/// does not request `QUERY_ALL_PACKAGES`: that is a sensitive Play Store
/// permission requiring Google justification, normally rejected for a
/// consumer banking app, and would turn "risky-app intelligence" into "we
/// can see everything on your phone" — a far larger privacy footprint than
/// the capability needs.
///
/// So every package this SDK can ever say anything about is one **already
/// named in the plugin's `<queries>` declarations** — a small, curated,
/// auditable list (see `RaspSecurityChannelHandler.knownRiskyPackages`),
/// never expanded at runtime by remote policy. Signed policy can change how
/// findings for those packages are *treated* (thresholds, actions); it
/// cannot make a new package visible, because `<queries>` is compiled into
/// the APK.
///
/// ## Classification vocabulary
///
/// Six tiers, deliberately ordered from most to least conclusive. `UNKNOWN`
/// is never the same as `CLEAN` — a package this SDK cannot classify is
/// exactly that, not a clean bill of health.
library;

/// How confident a classification is, independent of severity — a
/// `KNOWN_MALICIOUS` verdict from a hash match is `confirmed`; the same
/// verdict inferred from permission + source alone is not.
enum IntelConfidence { confirmed, high, medium, low }

/// The classification tiers a package can receive.
enum AppRiskClassification {
  /// Positively identified against threat intelligence (a named package the
  /// local database ships as a confirmed remote-access/instrumentation tool,
  /// or a customer-supplied deny-list entry).
  knownMalicious,

  /// Strong combined evidence (untrusted source + sensitive capability +
  /// signing anomaly) without a positive intelligence match.
  highRisk,

  /// One or two moderate signals — worth surfacing, not worth blocking.
  suspicious,

  /// Evaluated, found nothing intelligence or evidence points to. A genuine
  /// positive result, not a default.
  clean,

  /// Present and inspected, but this SDK's local intelligence has no
  /// opinion about it. **Never treated as [clean].**
  unknown,

  /// Could not be evaluated at all (channel unavailable, query threw). Also
  /// never treated as [clean].
  unavailable,
}

extension AppRiskClassificationX on AppRiskClassification {
  String get wireName => switch (this) {
        AppRiskClassification.knownMalicious => 'KNOWN_MALICIOUS',
        AppRiskClassification.highRisk => 'HIGH_RISK',
        AppRiskClassification.suspicious => 'SUSPICIOUS',
        AppRiskClassification.clean => 'CLEAN',
        AppRiskClassification.unknown => 'UNKNOWN',
        AppRiskClassification.unavailable => 'UNAVAILABLE',
      };

  /// Only these two are ever treated as "nothing to report" by policy —
  /// [unknown] and [unavailable] are deliberately excluded so neither can be
  /// mistaken for a clean result by a caller that only checks this.
  bool get isBenign => this == AppRiskClassification.clean;
}

/// How an installed package reached the device, where Android exposes it.
///
/// `installer` comes from `PackageManager.getInstallSourceInfo` (API 30+) /
/// `getInstallerPackageName` (fallback) — the *store or app that requested
/// the install*, which Android itself does not fully trust either: it can be
/// spoofed by any app with `INSTALL_PACKAGES`-adjacent tooling on a rooted
/// device, or simply be absent for a package installed via `adb install`.
/// Treat this as evidence, never as proof.
enum InstallSource {
  playStore,
  knownTrustedSource,
  unknownSource,
  sideloaded,

  /// The platform could not report an installer at all — API level, OEM
  /// package-installer variant, or a query failure. Distinct from
  /// [unknownSource] (asked and got a blank/unrecognized answer) — this
  /// means the ask itself did not succeed.
  unavailable,
}

extension InstallSourceX on InstallSource {
  String get wireName => switch (this) {
        InstallSource.playStore => 'PLAY_STORE',
        InstallSource.knownTrustedSource => 'KNOWN_TRUSTED_SOURCE',
        InstallSource.unknownSource => 'UNKNOWN_SOURCE',
        InstallSource.sideloaded => 'SIDELOADED',
        InstallSource.unavailable => 'UNAVAILABLE',
      };

  /// Package installers Android itself ships/recognizes as legitimate
  /// distribution channels, beyond the Play Store itself. Kept short and
  /// named, not "everything that isn't obviously bad" — an empty/unknown
  /// installer string is [InstallSource.unknownSource], not this.
  static const Set<String> trustedInstallerPackages = {
    'com.android.vending', // Play Store itself
    'com.amazon.venezia', // Amazon Appstore
    'com.sec.android.app.samsungapps', // Galaxy Store
    'com.huawei.appmarket', // Huawei AppGallery
    'com.xiaomi.market', // Xiaomi GetApps
  };

  static InstallSource classify(String? installerPackage) {
    if (installerPackage == null) return InstallSource.unavailable;
    if (installerPackage.isEmpty) return InstallSource.unknownSource;
    if (installerPackage == 'com.android.vending') return InstallSource.playStore;
    if (trustedInstallerPackages.contains(installerPackage)) {
      return InstallSource.knownTrustedSource;
    }
    // adb / package installer UI / a sideloading app itself.
    const sideloadMarkers = {
      'com.google.android.packageinstaller',
      'com.android.packageinstaller',
      'null', // some OEMs report the literal string for adb installs
    };
    if (sideloadMarkers.contains(installerPackage)) return InstallSource.sideloaded;
    return InstallSource.unknownSource;
  }
}

/// One normalized threat-intelligence record — the local database's unit of
/// truth. Mirrors `app/licensing/malware_intelligence.py::ThreatIntelRecord`
/// field-for-field; this is data, not logic, so there is no cross-language
/// canonicalization to keep in step, only a shared shape.
///
/// ## What a hash match does and does not prove
///
/// [certificateSha256] identifies a **signing identity**, not a specific APK
/// build — the same signer can sign many legitimate updates. A match means
/// "this signing identity is the one the record is about", not "this exact
/// file is malicious". Treat [description] as the actual claim being made,
/// and this field as how that claim is matched against a device.
class ThreatIntelRecord {
  final String package;

  /// SHA-256 of the signing certificate this record is about, hex lowercase.
  /// `null` for a record that only ever matches by package name.
  final String? certificateSha256;

  /// e.g. `'remote_access_tool'`, `'instrumentation_framework'`,
  /// `'known_spyware'`, `'counterfeit_reference'`. Free-form but stable —
  /// used as an event evidence field, so renaming one is a behavior change.
  final String threatClass;

  final AppRiskClassification classification;
  final IntelConfidence confidence;

  /// e.g. `'rasp_local_db'`, `'customer_denylist'`. Never a vendor name this
  /// SDK cannot actually attest to.
  final String source;

  final String description;

  /// Marks a record that exists ONLY to exercise the live test/acceptance
  /// pipeline — see `docs/MALWARE_THREAT_MODEL.md`. Such a record is never
  /// shipped in the production default database; a caller assembling the
  /// effective database is responsible for excluding it outside test builds.
  final bool testOnly;

  const ThreatIntelRecord({
    required this.package,
    this.certificateSha256,
    required this.threatClass,
    required this.classification,
    required this.confidence,
    required this.source,
    required this.description,
    this.testOnly = false,
  });

  Map<String, Object?> toMap() => {
        'package': package,
        'certificate_sha256': certificateSha256,
        'threat_class': threatClass,
        'classification': classification.wireName,
        'confidence': confidence.name,
        'source': source,
        'description': description,
      };
}

/// Everything this SDK was able to establish about one installed,
/// `<queries>`-visible package — the unit returned to a caller and the unit
/// a security event is built from.
///
/// Deterministic by construction: built from [ThreatIntelRecord] lookups and
/// pure classification rules over observed package metadata, so evaluating
/// the same installed state twice yields an identical profile.
class AppRiskProfile {
  final String package;
  final String? versionName;
  final int? versionCode;
  final InstallSource installSource;

  /// SHA-256 of the observed signing certificate, or `null` when it could
  /// not be read.
  final String? observedCertificateSha256;

  /// `true` when [observedCertificateSha256] does not match any certificate
  /// a matched [ThreatIntelRecord] expected for this package name —
  /// "known package identity, unexpected signer". Never asserted when there
  /// is no intelligence record to compare against; see
  /// `docs/MALWARE_THREAT_MODEL.md` for why an unexplained certificate alone
  /// is not counterfeit evidence.
  final bool signingMismatch;

  final AppRiskClassification classification;
  final IntelConfidence confidence;

  /// Short, stable reason codes — e.g. `'known_risky_package'`,
  /// `'untrusted_install_source'`, `'signing_mismatch'`,
  /// `'sensitive_permission'`. Never free text and never a full permission
  /// dump — see the privacy section of `docs/INSTALLED_APP_SECURITY.md`.
  final List<String> evidence;

  final ThreatIntelRecord? matchedRecord;

  const AppRiskProfile({
    required this.package,
    this.versionName,
    this.versionCode,
    required this.installSource,
    this.observedCertificateSha256,
    this.signingMismatch = false,
    required this.classification,
    required this.confidence,
    required this.evidence,
    this.matchedRecord,
  });

  Map<String, Object?> toMap() => {
        'package': package,
        'version_name': versionName,
        'version_code': versionCode,
        'install_source': installSource.wireName,
        'signing_mismatch': signingMismatch,
        'classification': classification.wireName,
        'confidence': confidence.name,
        'evidence': evidence,
        'threat_class': matchedRecord?.threatClass,
      };
}
