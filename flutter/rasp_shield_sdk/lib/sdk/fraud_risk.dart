/// Session risk and transaction API types (Task 8.1).
///
/// The SDK only recommends ([RaspSessionRisk.verdict],
/// [RaspSessionRisk.stepUpRecommended]); the host app decides what to do.
/// Account, session and beneficiary ids are hashed by the native engine
/// (HMAC-SHA256 with the per-application salt) as soon as they arrive and
/// are never stored or sent; only the hashes leave the device.
library;

/// Session lifecycle event reported with `RaspLeanSession.reportSession`.
enum RaspSessionEvent { login, resume, logout }

/// Session risk verdict. UNKNOWN when inputs could not be decided.
enum RaspRiskVerdict { low, medium, high, unknown }

/// The session risk computed by the native engine on its last tick.
class RaspSessionRisk {
  /// 0-100 from groups with a detection; `null` when nothing was scored.
  final int? score;

  /// The score if every undecided group were a detection.
  final int? maxPossibleScore;
  final RaspRiskVerdict verdict;
  final bool stepUpRecommended;
  final List<String> firedGroups;
  final List<String> undecidedGroups;
  final List<String> contributingDetectors;
  final bool highRiskTransactionMode;

  /// `null` before the first evaluation.
  final DateTime? evaluatedAt;

  const RaspSessionRisk({
    required this.score,
    required this.maxPossibleScore,
    required this.verdict,
    required this.stepUpRecommended,
    this.firedGroups = const [],
    this.undecidedGroups = const [],
    this.contributingDetectors = const [],
    this.highRiskTransactionMode = false,
    this.evaluatedAt,
  });

  static const notEvaluated = RaspSessionRisk(
    score: null,
    maxPossibleScore: null,
    verdict: RaspRiskVerdict.unknown,
    stepUpRecommended: false,
  );

  /// Decodes the native map; anything unreadable gives UNKNOWN, never LOW.
  static RaspSessionRisk fromWire(Object? raw) {
    if (raw is! Map) return notEvaluated;
    List<String> strings(Object? v) => v is List ? v.map((e) => '$e').toList(growable: false) : const [];
    final verdictName = '${raw['verdict']}'.toLowerCase();
    final evaluatedAtMillis = (raw['evaluatedAtMillis'] as num?)?.toInt() ?? 0;
    return RaspSessionRisk(
      score: (raw['score'] as num?)?.toInt(),
      maxPossibleScore: (raw['maxPossibleScore'] as num?)?.toInt(),
      verdict: RaspRiskVerdict.values.firstWhere((v) => v.name == verdictName, orElse: () => RaspRiskVerdict.unknown),
      stepUpRecommended: raw['stepUpRecommended'] == true,
      firedGroups: strings(raw['firedGroups']),
      undecidedGroups: strings(raw['undecidedGroups']),
      contributingDetectors: strings(raw['contributingDetectors']),
      highRiskTransactionMode: raw['highRiskTransactionMode'] == true,
      evaluatedAt: evaluatedAtMillis > 0 ? DateTime.fromMillisecondsSinceEpoch(evaluatedAtMillis, isUtc: true) : null,
    );
  }
}

class RaspSessionReport {
  final String accountHash;
  final String sessionHash;
  final RaspSessionEvent event;
  final RaspSessionRisk risk;

  /// `true` when a signed event was handed to the backend sender.
  final bool sentToBackend;

  const RaspSessionReport({
    required this.accountHash,
    required this.sessionHash,
    required this.event,
    required this.risk,
    required this.sentToBackend,
  });
}

/// The signed transaction binding. [canonical] is
/// `rasp-txn-v1|<amount>|<currency>|<beneficiaryHash>|<nonce>|<timestampMillis>|<counter>`,
/// signed by the device key (ECDSA P-256, DER, Base64). Your server can
/// verify it with the public key registered for [deviceKeyId]. Only
/// [bindingSha256] goes to the RASP backend, never the amount.
class RaspSignedTransaction {
  final String canonical;
  final String signatureBase64;
  final int counter;
  final String nonce;
  final DateTime timestamp;
  final String beneficiaryHash;
  final String bindingSha256;
  final String deviceKeyId;
  final RaspSessionRisk risk;

  const RaspSignedTransaction({
    required this.canonical,
    required this.signatureBase64,
    required this.counter,
    required this.nonce,
    required this.timestamp,
    required this.beneficiaryHash,
    required this.bindingSha256,
    required this.deviceKeyId,
    required this.risk,
  });

  static RaspSignedTransaction fromWire(Map<String, Object?> raw) => RaspSignedTransaction(
        canonical: raw['canonical'] as String,
        signatureBase64: raw['signature'] as String,
        counter: (raw['counter'] as num).toInt(),
        nonce: raw['nonce'] as String,
        timestamp: DateTime.fromMillisecondsSinceEpoch((raw['timestampMillis'] as num).toInt(), isUtc: true),
        beneficiaryHash: raw['beneficiaryHash'] as String,
        bindingSha256: raw['bindingSha256'] as String,
        deviceKeyId: raw['deviceKeyId'] as String,
        risk: RaspSessionRisk.fromWire(raw['risk']),
      );
}

class RaspTransactionReport {
  final RaspSignedTransaction transaction;
  final String channel;
  final bool sentToBackend;

  const RaspTransactionReport({required this.transaction, required this.channel, required this.sentToBackend});
}

/// Why a session/transaction call failed. [code]: `INVALID_ARGUMENT` (bad
/// amount, currency, channel or id), `UNAVAILABLE` (session risk off, no
/// salt, no active session, device key or signing unavailable, no native
/// side). The message never contains the raw ids.
class RaspFraudApiException implements Exception {
  final String code;
  final String message;

  const RaspFraudApiException(this.code, this.message);

  @override
  String toString() => 'RaspFraudApiException($code): $message';
}
