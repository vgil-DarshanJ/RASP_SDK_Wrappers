import 'package:shared_preferences/shared_preferences.dart';

import 'backend_config.dart';

/// Runtime-settable backend origin, overriding the compile-time default.
///
/// Why this exists
/// ---------------
/// [BackendConfig.baseUrl] is a `String.fromEnvironment` constant, so the
/// backend host is baked into the APK at build time. Any change of origin
/// therefore silently bricks an already-installed build — the SDK treats an
/// unreachable host as "offline" — and the only remedy would be a full rebuild
/// and reinstall on every device.
///
/// That happens more often than a "permanent deployment" implies: the demo
/// server's address can change, a tester needs to point at a LAN box, a
/// customer moves from a staging endpoint to production. (It was originally
/// written for Cloudflare quick tunnels, whose hostname rotated on every
/// `cloudflared` restart — the demo no longer needs a tunnel, but the
/// underlying problem is not tunnel-specific.)
///
/// With an override stored on the device, changing backend is a 10-second
/// settings edit instead of a rebuild.
///
/// Precedence: saved override → compile-time `RASP_BACKEND_URL` default.
///
/// The value is read once at startup ([load]) and cached, because
/// `SdkConfig.configure` and `AgentConfig.baseUrl` are consumed synchronously
/// long after `main()` returns.
class BackendOverride {
  BackendOverride._();

  static const _key = 'rasp_backend_url_override';

  static String? _cached;

  /// The origin the app should talk to, with no trailing slash.
  static String get baseUrl {
    final override = _cached;
    if (override != null && override.isNotEmpty) return override;
    return BackendConfig.baseUrl;
  }

  /// Whether a device-local override is currently in force.
  static bool get isOverridden => (_cached ?? '').isNotEmpty;

  /// The compile-time default, shown in settings so the user can see what
  /// clearing the override would fall back to.
  static String get compiledDefault => BackendConfig.baseUrl;

  /// Load any saved override. Call once, before the SDK is configured.
  ///
  /// Failures are swallowed: a missing or corrupt preference store must fall
  /// back to the compiled default rather than stop the app from starting.
  static Future<void> load() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _cached = _normalize(prefs.getString(_key) ?? '');
    } catch (_) {
      _cached = null;
    }
  }

  /// Persist a new origin. Pass an empty string to clear the override.
  ///
  /// Returns the normalised value now in effect, or `null` when the input was
  /// not a usable http(s) origin.
  static Future<String?> save(String raw) async {
    final normalized = _normalize(raw);
    if (raw.trim().isNotEmpty && normalized == null) return null;

    _cached = normalized;
    try {
      final prefs = await SharedPreferences.getInstance();
      if (normalized == null) {
        await prefs.remove(_key);
      } else {
        await prefs.setString(_key, normalized);
      }
    } catch (_) {
      // Keep the in-memory value even if persistence fails, so the current
      // session still works.
    }
    return normalized ?? BackendConfig.baseUrl;
  }

  /// Trim, strip a trailing slash, and require an absolute http(s) origin.
  ///
  /// Returns `null` for anything unusable, including the empty string — the
  /// caller distinguishes "clear it" from "invalid" by checking the raw input.
  static String? _normalize(String raw) {
    var value = raw.trim();
    if (value.isEmpty) return null;
    while (value.endsWith('/')) {
      value = value.substring(0, value.length - 1);
    }
    final uri = Uri.tryParse(value);
    if (uri == null ||
        !uri.hasScheme ||
        (uri.scheme != 'http' && uri.scheme != 'https') ||
        uri.host.isEmpty) {
      return null;
    }
    return value;
  }
}
