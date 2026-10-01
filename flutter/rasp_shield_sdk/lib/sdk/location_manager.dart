import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// One capture of where a device is and what state it is in, assembled for the
/// heartbeat that already runs (see [ActivationManager.heartbeat]).
///
/// Every field is nullable on purpose. A device indoors has no GPS fix; a
/// device on wifi has no carrier; a device offline cannot reverse-geocode. The
/// capture still ships so the battery/network context is not lost — the
/// backend stores exactly what was readable and NULLs the rest.
class DeviceLocation {
  final double? latitude;
  final double? longitude;
  final double? accuracy;
  final double? speed;
  final double? bearing;
  final int? battery;
  final bool? charging;
  final String? network;
  final String? networkOperator;
  final String? city;
  final String? state;
  final String? country;
  final String capturedAt;

  const DeviceLocation({
    this.latitude,
    this.longitude,
    this.accuracy,
    this.speed,
    this.bearing,
    this.battery,
    this.charging,
    this.network,
    this.networkOperator,
    this.city,
    this.state,
    this.country,
    required this.capturedAt,
  });

  /// Heartbeat request fields. Merged into the existing heartbeat body rather
  /// than posted anywhere new — `location_reported` is the flag the backend
  /// keys on to decide whether to append a `device_locations` row.
  Map<String, dynamic> toHeartbeatFields() => {
        'location_reported': true,
        if (latitude != null) 'latitude': latitude,
        if (longitude != null) 'longitude': longitude,
        if (accuracy != null) 'accuracy': accuracy,
        if (speed != null) 'speed': speed,
        if (bearing != null) 'bearing': bearing,
        if (battery != null) 'battery': battery,
        if (charging != null) 'charging': charging,
        if (network != null) 'network': network,
        if (networkOperator != null) 'network_operator': networkOperator,
        if (city != null) 'city': city,
        if (state != null) 'state': state,
        if (country != null) 'country': country,
        'captured_at': capturedAt,
      };
}

/// Host-supplied source of GPS position, battery, and reverse-geocoded place.
///
/// **Phase 2 dependency cleanup**: this SDK core no longer depends on
/// `geolocator`/`battery_plus`/`geocoding`/`permission_handler` — those are
/// app-facing packages that request runtime permissions and drag battery
/// APIs into every integrator's build, whether or not they want device
/// location telemetry. A host app that wants [DeviceLocation.latitude] etc.
/// populated implements this interface against whatever location package it
/// chooses (or reuses `rasp_app`'s own `GeolocatorLocationProvider` as a
/// worked example — see `rasp_app/lib/services/geolocator_location_provider.dart`)
/// and sets [LocationManager.provider] once, before [RaspShield.initialize].
///
/// With no provider set, [LocationManager.capture] still returns network
/// class and carrier (see [LocationManager._readNetwork] /
/// [LocationManager._readNetworkOperator]) — neither needs a runtime
/// permission or a location package, so that much stays available with zero
/// integration effort. GPS, battery, and city/state/country stay `null`
/// until a provider is registered — an honest omission, never a fabricated
/// reading.
abstract class LocationProvider {
  /// Best-effort read of GPS position, battery state, and reverse-geocoded
  /// place. Implementations should never throw — [LocationManager.capture]
  /// treats a thrown exception the same as a `null` return (nothing from
  /// this provider this cycle), but a well-behaved provider degrades its own
  /// sub-readings instead of failing the whole capture, exactly as
  /// `GeolocatorLocationProvider` does.
  ///
  /// [network] / [networkOperator] / [capturedAt] on the returned
  /// [DeviceLocation] are ignored — [LocationManager] fills those itself.
  Future<DeviceLocation?> capture();
}

/// Collects the device-context payload that rides each heartbeat.
///
/// Nothing here decides *when* to send — [RaspSdk]'s existing heartbeat timer
/// does. This only answers "what is true right now", and answers it
/// best-effort: any sub-reading that throws or times out degrades to `null`
/// rather than failing the capture, and a capture that fails entirely returns
/// `null` so the heartbeat proceeds exactly as it did before this milestone.
class LocationManager {
  /// Host-supplied source of GPS/battery/place readings — `null` by default.
  /// See [LocationProvider]'s own doc for why this SDK does not ship one.
  static LocationProvider? provider;

  /// The app's existing native security channel (see MainActivity.kt) — reused
  /// for the one reading Dart plugins cannot supply, rather than standing up a
  /// second channel.
  static const MethodChannel _securityChannel =
      MethodChannel('com.shieldsdk.security/security');

  static const Duration _subReadingTimeout = Duration(seconds: 5);

  /// Assemble the current device context, or `null` when nothing could be read.
  ///
  /// Returns a capture even without a GPS fix — battery and network state are
  /// still worth recording, and the backend stores the row with NULL
  /// coordinates. Returns `null` only when the platform is unusable (web, or
  /// every reading — provider included — produced nothing), so the caller can
  /// skip the location fields entirely.
  static Future<DeviceLocation?> capture() async {
    if (kIsWeb) return null;

    DeviceLocation? fromProvider;
    final activeProvider = provider;
    if (activeProvider != null) {
      try {
        fromProvider = await activeProvider.capture();
      } catch (_) {
        // A misbehaving provider degrades this capture to network-only,
        // never crashes the heartbeat it rides on.
        fromProvider = null;
      }
    }

    final network = await _readNetwork();
    final operator = await _readNetworkOperator();

    // Nothing at all was readable — let the heartbeat go out unchanged.
    if (fromProvider == null && network == null) return null;

    return DeviceLocation(
      latitude: fromProvider?.latitude,
      longitude: fromProvider?.longitude,
      accuracy: fromProvider?.accuracy,
      speed: fromProvider?.speed,
      bearing: fromProvider?.bearing,
      battery: fromProvider?.battery,
      charging: fromProvider?.charging,
      network: network,
      networkOperator: operator,
      city: fromProvider?.city,
      state: fromProvider?.state,
      country: fromProvider?.country,
      capturedAt: DateTime.now().toUtc().toIso8601String(),
    );
  }

  /// Connectivity class, in the vocabulary the backend column documents:
  /// 'wifi' | 'mobile' | 'none' | 'other'. Needs no runtime permission —
  /// available with zero integration effort, provider or not.
  static Future<String?> _readNetwork() async {
    try {
      final results =
          await Connectivity().checkConnectivity().timeout(_subReadingTimeout);
      if (results.isEmpty) return null;
      if (results.contains(ConnectivityResult.wifi)) return 'wifi';
      if (results.contains(ConnectivityResult.mobile)) return 'mobile';
      if (results.contains(ConnectivityResult.none)) return 'none';
      return 'other';
    } catch (_) {
      return null;
    }
  }

  /// Carrier name of the active SIM, via the security MethodChannel the app
  /// already uses for its native detectors — no second channel, no extra
  /// plugin, no runtime permission.
  ///
  /// Null on wifi-only hardware, with no SIM, or on any non-Android platform.
  static Future<String?> _readNetworkOperator() async {
    if (defaultTargetPlatform != TargetPlatform.android) return null;
    try {
      final name = await _securityChannel
          .invokeMethod<String>('getNetworkOperator')
          .timeout(_subReadingTimeout);
      final trimmed = name?.trim();
      return (trimmed == null || trimmed.isEmpty) ? null : trimmed;
    } catch (_) {
      // Channel missing (older host build) or the read threw — report nothing
      // rather than a placeholder.
      return null;
    }
  }
}
