/// A single supporting fact behind a `DetectionResult`.
///
/// A detector rarely has just one boolean to report — it usually knows *why*
/// it fired (which su binary path, which package signer mismatch, which
/// process name looked like a Frida gadget). `DetectionEvidence` is how that
/// detail travels with the result instead of being flattened into a single
/// opaque string, so a dashboard can show it verbatim, an AI narrative can
/// quote it, and a test can assert on it precisely.
///
/// Deliberately plain: [value] is `Object?` rather than a typed union, so
/// evidence can carry a `String`, `bool`, `num`, or a nested
/// `Map<String, Object?>` without this class needing a variant per shape.
class DetectionEvidence {
  /// Machine-readable name of the fact, e.g. `'su_binary_path'`,
  /// `'signing_cert_fingerprint'`, `'frida_port'`. Stable across app
  /// versions so tooling can key off it.
  final String key;

  /// The fact itself. Plain Dart values only (`String`, `bool`, `num`,
  /// `List`, `Map`) so this class remains trivially serializable.
  final Object? value;

  /// Optional human-readable one-liner for surfaces that render evidence as
  /// prose rather than a key/value pair (e.g. an AI risk card).
  final String? note;

  /// Creates a single piece of supporting evidence.
  const DetectionEvidence({
    required this.key,
    required this.value,
    this.note,
  });

  /// Plain-map form for logging, telemetry payloads, or JSON encoding.
  Map<String, Object?> toMap() => {
        'key': key,
        'value': value,
        if (note != null) 'note': note,
      };

  @override
  String toString() => note != null ? '$key=$value ($note)' : '$key=$value';
}
