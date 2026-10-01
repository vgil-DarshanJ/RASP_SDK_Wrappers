import 'dart:convert';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';

import '../device/canonical_field.dart';

/// A field name that must never be committed to a transaction digest.
class TransactionPrivacyError extends ArgumentError {
  TransactionPrivacyError(super.message);
}

/// A typed banking transaction — the business intent the user approved.
///
/// ## Why this exists when `SecureTransactionContext` already did
///
/// The existing [SecureTransactionContext] takes an untyped
/// `Map<String, Object?>`, which is exactly right as a generic building
/// block and exactly wrong as the public banking API: nothing stopped a PIN,
/// an OTP or a full account number being placed in it and permanently
/// committed to a digest. This type names the fields a payment actually
/// needs, and refuses the ones it must never carry.
///
/// ## Privacy
///
/// Credentials are **rejected, not hashed**. A digest is a public
/// commitment — anyone who can guess the input can confirm it — and the
/// input space of a 4-digit PIN or a 6-digit OTP is exhaustible in
/// microseconds. Hashing one would give a false impression of protection.
/// Account numbers and IBANs are refused for a different reason: they are
/// not secrets, but they are personal data with no business accumulating in
/// a security ledger. Pass the tokenized reference your own systems already
/// use.
@immutable
class RaspTransaction {
  /// The bank's own identifier for this operation. Also the idempotency key:
  /// reusing it for *different* content is reported as tampering, reusing it
  /// for identical content as a duplicate.
  final String transactionId;

  /// `transfer`, `beneficiary_add`, `bill_payment`, … Chosen by the
  /// integrator; matched against signed policy's `protected_types`.
  final String transactionType;

  /// Decimal **string**, never a double.
  ///
  /// `1000.10` is not exactly representable in binary floating point, so two
  /// sides that both "have the amount" can serialize it differently and
  /// produce different digests — a legitimate payment rejected with no
  /// visible cause. A string removes the class of bug entirely.
  final String? amount;

  final String? currency;

  /// Tokenized beneficiary reference — never a raw account number or IBAN.
  final String? beneficiaryRef;

  /// Tokenized source-account reference.
  final String? sourceRef;

  /// Anything else this integration genuinely needs bound, subject to the
  /// same privacy rules.
  final Map<String, Object?> businessFields;

  RaspTransaction({
    required this.transactionId,
    required this.transactionType,
    this.amount,
    this.currency,
    this.beneficiaryRef,
    this.sourceRef,
    this.businessFields = const {},
  }) {
    assertNoSecretFields(businessFields);
  }

  /// Field-name patterns that may never be digested.
  static final RegExp _forbidden = RegExp(
    r'pin\b|\botp\b|password|passcode|cvv|cvc|secret|security_code|'
    r'card_number|pan\b|account_number|iban\b|token\b|credential',
    caseSensitive: false,
  );

  /// Throws [TransactionPrivacyError] if any field name looks like a
  /// credential or a raw account identifier. Mirrors Python's
  /// `assert_no_secret_fields`, so an integration is refused identically on
  /// both sides rather than accepted on one and rejected on the other.
  static void assertNoSecretFields(Map<String, Object?> fields) {
    for (final name in fields.keys) {
      if (_forbidden.hasMatch(name)) {
        throw TransactionPrivacyError(
          "Field '$name' must not be part of a transaction digest. Use a "
          "tokenized reference (e.g. 'beneficiaryRef') instead of a "
          'credential or a raw account identifier.',
        );
      }
    }
  }

  /// Canonical decimal string for an amount. Mirrors Python's
  /// `normalize_amount`: trailing zeros stripped so `1000.00`, `1000.0` and
  /// `1000` all agree.
  static String normalizeAmount(String? amount) {
    final text = (amount ?? '').trim();
    if (text.isEmpty) return '';
    if (!RegExp(r'^-?\d+(\.\d+)?$').hasMatch(text)) {
      throw ArgumentError('amount "$amount" is not a plain decimal string');
    }
    if (!text.contains('.')) return text;
    var t = text.replaceFirst(RegExp(r'0+$'), '');
    if (t.endsWith('.')) t = t.substring(0, t.length - 1);
    return t.isEmpty ? '0' : t;
  }

  /// Versioned domain separator, byte-identical to Python's
  /// `transaction_protection.DOMAIN`.
  static const String domain = 'RASP-TX-PROOF-v1';

  /// The exact string the digest is taken over.
  ///
  /// Business fields are JSON-encoded with **sorted keys and no whitespace**,
  /// so map insertion order — which differs between languages and between
  /// runs — can never change the digest.
  String canonicalString() {
    CanonicalField.assertSafe('transaction_id', transactionId);
    CanonicalField.assertSafe('transaction_type', transactionType);
    final amt = normalizeAmount(amount);
    CanonicalField.assertSafe('amount', amt);
    CanonicalField.assertSafe('currency', currency ?? '');
    CanonicalField.assertSafe('beneficiary_ref', beneficiaryRef ?? '');
    CanonicalField.assertSafe('source_ref', sourceRef ?? '');

    assertNoSecretFields(businessFields);
    final sortedKeys = businessFields.keys.toList()..sort();
    final business = jsonEncode({
      for (final k in sortedKeys) k: businessFields[k],
    });
    CanonicalField.assertSafe('business_fields', business);

    return [
      domain,
      transactionType,
      transactionId,
      amt,
      (currency ?? '').toUpperCase(),
      beneficiaryRef ?? '',
      sourceRef ?? '',
      business,
    ].join('|');
  }

  /// SHA-256 of [canonicalString], lowercase hex. This is what the API proof
  /// binds, and what the bank's backend independently recomputes from the
  /// fields it is about to act on.
  String digest() =>
      sha256.convert(utf8.encode(canonicalString())).toString();

  /// The transaction as the bank's verification endpoint expects it.
  /// Deliberately carries no proof material — the proof rides in the request
  /// headers, and this is only the business content.
  Map<String, Object?> toVerificationPayload() => {
        'transaction_id': transactionId,
        'transaction_type': transactionType,
        if (amount != null) 'amount': amount,
        if (currency != null) 'currency': currency,
        if (beneficiaryRef != null) 'beneficiary_ref': beneficiaryRef,
        if (sourceRef != null) 'source_ref': sourceRef,
        if (businessFields.isNotEmpty) 'business_fields': businessFields,
      };
}

/// Where a transaction sits in its lifecycle.
///
/// Deliberately distinguishes **proof state** from **financial completion**.
/// RASP Shield can say a transaction is [verified] — authentic, unmodified,
/// unreplayed. It can never say a payment succeeded; only the bank's own
/// backend knows that, and conflating the two would be the most dangerous
/// possible misreading of this API.
enum TransactionState {
  created,
  prepared,
  proved,
  submitted,
  verified,
  expired,
  replayed,
  tampered,
  cancelled,
  rejected,
}

extension TransactionStateX on TransactionState {
  String get wireName => name.toUpperCase();

  /// True only for states where the proof was cryptographically accepted.
  /// Never implies the money moved.
  bool get proofAccepted => this == TransactionState.verified;
}
