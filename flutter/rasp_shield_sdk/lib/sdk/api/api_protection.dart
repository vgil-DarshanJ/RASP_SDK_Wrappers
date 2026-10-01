import 'dart:convert';
import 'dart:math';

import 'package:dio/dio.dart';
import 'package:flutter/foundation.dart';

import '../activation_manager.dart';
import '../device_identity.dart';
import '../license_manager.dart';
import 'api_protection_policy.dart';
import 'api_request_proof.dart';

/// The outcome of trying to protect one request.
///
/// A failure is never silent and never fabricates a proof: the caller is
/// told which precondition was missing so an integrator can fix it, rather
/// than discovering at the API gateway that requests are unsigned.
enum ApiProtectionOutcome {
  /// A full proof was attached.
  protected,

  /// The host/path is not configured as protected by signed policy — the
  /// request is deliberately left untouched.
  notProtected,

  /// Protection was wanted but this device has no activation token yet
  /// (not activated, or activation is PENDING/BLOCKED/REVOKED).
  notActivated,

  /// Protection was wanted but signed policy has disabled it.
  disabledByPolicy,
}

/// The headers to attach, plus why.
@immutable
class ProtectedRequest {
  final ApiProtectionOutcome outcome;
  final Map<String, String> headers;
  final String? requestId;

  const ProtectedRequest({
    required this.outcome,
    this.headers = const {},
    this.requestId,
  });

  bool get isProtected => outcome == ApiProtectionOutcome.protected;
}

/// **RASP Shield API Protection** — cryptographic request trust for the
/// customer's own API.
///
/// ## What problem this solves
///
/// TLS proves the *channel* is private. A bearer token proves *someone*
/// holding that token sent the request. Neither proves the request came
/// from the legitimate app, on the legitimate device, unmodified. A token
/// lifted from a rooted phone works perfectly from an attacker's laptop,
/// and TLS will happily protect that attacker's connection.
///
/// This layer binds each protected request to the application, the device,
/// the activation, the session, and the request's own bytes — so the bank's
/// API can tell the two apart.
///
/// ## What it is not
///
/// It does not make a compromised client impossible to compromise. An
/// attacker with full control of a rooted device running a debugger can
/// still cause the *legitimate* app to sign a request they chose. What it
/// removes is the far cheaper and far more common attack: lifting
/// credentials and replaying, modifying or relocating requests off-device.
/// The server stays authoritative, and the risk/integrity state of the
/// device travels with the verdict so policy can refuse a proof that is
/// cryptographically perfect but comes from a device that should not be
/// trusted.
///
/// ## Usage
///
/// The recommended integration is automatic — one line at startup, then
/// ordinary Dio calls:
///
/// ```dart
/// await RaspShield.initialize();
/// RaspShield.api.protect(myDio);        // customer's own Dio
///
/// await myDio.post('/payments', data: {...});   // signed automatically
/// ```
///
/// Manual signing stays available for a non-Dio client:
///
/// ```dart
/// final p = await RaspShield.api.protectRequest(
///   method: 'POST', url: Uri.parse('https://api.bank.com/payments'),
///   bodyBytes: utf8.encode(jsonEncode(payload)),
/// );
/// if (p.isProtected) request.headers.addAll(p.headers);
/// ```
class RaspShieldApi {
  /// Const so it can back `RaspShield.api`, mirroring `RaspShield.ai`.
  /// Instance methods delegate to the statics below, so both
  /// `RaspShield.api.protect(dio)` and `RaspShieldApi.protectDio(dio)` work
  /// and there is only one implementation of each.
  const RaspShieldApi();

  /// Attach automatic protection to the host app's own [Dio].
  /// See [RaspShieldApi.protectDio].
  void protect(Dio dio) => protectDio(dio);

  /// Build a proof for one request manually.
  /// See [RaspShieldApi.buildProof].
  Future<ProtectedRequest> protectRequest({
    required String method,
    required Uri url,
    List<int> bodyBytes = const [],
  }) =>
      buildProof(method: method, url: url, bodyBytes: bodyBytes);

  static final Random _rng = Random.secure();

  /// The end-user session token to bind requests to, if the host app has
  /// one. Set it after login, clear it on logout.
  ///
  /// Only its SHA-256 ever leaves the device — see
  /// [ApiRequestProof.sessionBinding]. This SDK never transmits, stores or
  /// logs the token itself, so binding to a session does not hand the
  /// bank's session secret to RASP Shield.
  static String? sessionToken;

  /// Cryptographically-random hex from the same secure RNG this layer uses.
  ///
  /// Internal to the SDK, not part of the customer-facing surface: the
  /// transaction layer mints its nonce and request id through this rather
  /// than standing up a second `Random.secure()`, so there is one source of
  /// randomness for proofs and no chance of one of them quietly being seeded
  /// from a weaker generator.
  static String randomHex(int bytes) {
    final b = List<int>.generate(bytes, (_) => _rng.nextInt(256));
    return b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
  }

  /// Build a proof for one request.
  ///
  /// Returns [ApiProtectionOutcome.notProtected] — leaving the request
  /// untouched — when signed policy does not cover this host/path. That
  /// default matters: a customer adopting this SDK must not discover that
  /// every unrelated third-party call in their app suddenly carries RASP
  /// headers.
  static Future<ProtectedRequest> buildProof({
    required String method,
    required Uri url,
    List<int> bodyBytes = const [],
  }) async {
    if (!ApiProtectionPolicy.enabled) {
      return const ProtectedRequest(
          outcome: ApiProtectionOutcome.disabledByPolicy);
    }
    if (!ApiProtectionPolicy.covers(host: url.host, path: url.path)) {
      return const ProtectedRequest(outcome: ApiProtectionOutcome.notProtected);
    }

    final token = await LicenseManager.activationToken;
    if (token == null || token.isEmpty) {
      // Deliberately does NOT fall back to an unsigned request silently —
      // the caller is told, so an integrator sees "not activated" rather
      // than a mystery 401 from their own gateway.
      return const ProtectedRequest(outcome: ApiProtectionOutcome.notActivated);
    }

    final deviceId = await DeviceIdentity.get();
    final applicationId = await ActivationManager.bundleId();
    final timestamp =
        (DateTime.now().toUtc().millisecondsSinceEpoch ~/ 1000).toString();
    final nonce = randomHex(16);
    final requestId = randomHex(16);

    final canonical = ApiRequestProof.canonicalRequest(
      method: method,
      host: url.host,
      path: url.path,
      query: url.query,
      bodyBytes: bodyBytes,
      timestamp: timestamp,
      nonce: nonce,
      requestId: requestId,
      sessionToken: sessionToken,
    );

    final signature = ApiRequestProof.sign(
      activationToken: token,
      canonicalRequestString: canonical,
    );

    return ProtectedRequest(
      outcome: ApiProtectionOutcome.protected,
      requestId: requestId,
      headers: ApiRequestProof.headers(
        timestamp: timestamp,
        nonce: nonce,
        requestId: requestId,
        signature: signature,
        deviceId: deviceId,
        applicationId: applicationId,
        licenseKeyHash: ActivationManager.licenseKeyHash,
      ),
    );
  }

  /// Attach automatic protection to the host app's own [Dio].
  ///
  /// Adds an interceptor, never replaces the client's adapter or its other
  /// interceptors — the customer's existing networking (base URL, auth
  /// headers, retries, logging) keeps working exactly as before. This is
  /// also why the SDK does not create a second HTTP stack of its own: the
  /// bank's Dio already carries their auth and their configuration, and a
  /// parallel stack would silently diverge from it.
  ///
  /// Requests to hosts/paths that signed policy does not cover pass through
  /// completely untouched.
  static void protectDio(Dio dio) {
    dio.interceptors.add(_ApiProtectionInterceptor());
  }
}

class _ApiProtectionInterceptor extends Interceptor {
  @override
  Future<void> onRequest(
    RequestOptions options,
    RequestInterceptorHandler handler,
  ) async {
    try {
      final url = options.uri;
      // The bytes signed must be the bytes sent. Dio serializes `data` to
      // the wire later, so anything other than an already-encoded string or
      // byte list cannot be hashed reliably here — for those, encode the
      // body yourself (or send a String) rather than have this layer sign a
      // guess at what Dio will produce.
      final body = _bodyBytes(options.data);
      if (body == null) {
        if (ApiProtectionPolicy.covers(host: url.host, path: url.path)) {
          debugPrint('[RASP-TRACE] API-PROOF skipped ${url.host}${url.path}: '
              'body type ${options.data.runtimeType} cannot be hashed '
              'deterministically — pass a String or List<int>');
        }
        return handler.next(options);
      }

      final proof = await RaspShieldApi.buildProof(
        method: options.method,
        url: url,
        bodyBytes: body,
      );
      if (proof.isProtected) {
        options.headers.addAll(proof.headers);
        debugPrint('[RASP-TRACE] API-PROOF attached ${options.method} '
            '${url.host}${url.path} request_id=${proof.requestId}');
      } else if (proof.outcome != ApiProtectionOutcome.notProtected) {
        debugPrint('[RASP-TRACE] API-PROOF not attached '
            '${url.host}${url.path}: ${proof.outcome.name}');
      }
    } catch (e) {
      // Never break the host app's networking because this layer failed.
      // An unprotected request reaching a gateway that requires a proof is
      // rejected there, which is the safe direction for this to fail in.
      debugPrint('[RASP-TRACE] API-PROOF error: $e');
    }
    return handler.next(options);
  }

  /// The exact bytes Dio will send, or null when they cannot be known here.
  static List<int>? _bodyBytes(dynamic data) {
    if (data == null) return const [];
    if (data is String) return utf8.encode(data);
    if (data is List<int>) return data;
    if (data is Map || data is List) {
      // Dio's default JSON encoding for these is `jsonEncode`, so this
      // matches what actually goes on the wire.
      try {
        return utf8.encode(jsonEncode(data));
      } catch (_) {
        return null;
      }
    }
    return null;
  }
}
