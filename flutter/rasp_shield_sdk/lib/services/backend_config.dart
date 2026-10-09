/// Backend endpoints for the RASP SDK and in-app AI agent.
///
/// The default is the demo server on its public IP, so `flutter build apk`
/// with no `--dart-define` produces an APK that anyone can install and run
/// against the live demo over any network — no rebuild, no flags.
///
/// Cleartext HTTP to this host is allowed explicitly by
/// `android/app/src/main/res/xml/network_security_config.xml`; Android's
/// TLS-only default still applies to every other domain. Put a real
/// domain + TLS in front of this deployment before it is anything but a demo.
///
/// No tunnel, proxy or extra tooling is involved: the SDK talks to this origin
/// directly over the network.
///
/// Override for a different backend:
///
/// ```
/// # A production deployment behind a real domain + TLS
/// flutter build apk --dart-define=RASP_BACKEND_URL=https://api.yourbank.com
/// # A LAN host
/// flutter build apk --dart-define=RASP_BACKEND_URL=http://192.168.1.10:7010
/// # USB-only, via `adb reverse tcp:7010 tcp:7010`
/// flutter run --dart-define=RASP_BACKEND_URL=http://127.0.0.1:7010
/// # A Cloudflare quick tunnel — only for a backend that is NOT publicly
/// # routable. Ephemeral: a new hostname on every cloudflared restart.
/// flutter build apk --dart-define=RASP_BACKEND_URL=https://<tunnel>.trycloudflare.com
/// ```
///
/// Points at the API port (7010): `/api/v1/sdk` (challenge, activate,
/// heartbeat) and `/api/v1/security` (telemetry) are only served there. The
/// customer-portal (7011) and visitor (7012) ports return 404 for those paths,
/// so pointing this at either produces "cannot reach licensing server".
///
/// This constant belongs to the DEMO APP, not to the SDK. The SDK itself takes
/// its origin from `SdkConfig.configure(backendUrl: …)`, which `main()` calls
/// once — so a customer embedding the SDK supplies their own endpoint and never
/// inherits this value.
class BackendConfig {
  /// Root origin of the RASP backend, with no trailing slash. Empty unless
  /// the build passes `--dart-define=RASP_BACKEND_URL=https://…`: no server
  /// address (and no cleartext default) is compiled into the package (F-21),
  /// so an unconfigured build reaches no backend at all.
  static const String baseUrl = String.fromEnvironment('RASP_BACKEND_URL');

  /// Whether a backend origin was supplied at build time.
  static bool get isConfigured => baseUrl.isNotEmpty;

  /// Versioned API prefix used by the security + chat endpoints.
  static const String securityApiBaseUrl = '$baseUrl/api/v1';

  /// SDK licensing endpoints (challenge, activate, heartbeat).
  static const String sdkApiBaseUrl = '$baseUrl/api/v1/sdk';
}
