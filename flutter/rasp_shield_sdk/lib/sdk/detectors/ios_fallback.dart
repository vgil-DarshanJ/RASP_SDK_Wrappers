/// Host-supplied jailbreak/simulator signal for iOS, used only until a real
/// native iOS detector module exists — see the P0-1/P0-2 iOS parity notes.
///
/// ## Why this is host-supplied, not a default in this SDK core
///
/// The previous default implementation used `package:safe_device`. That
/// package's own Android manifest declares `ACCESS_FINE_LOCATION` /
/// `ACCESS_COARSE_LOCATION` unconditionally — merged into every consuming
/// app's build regardless of whether its Android code path is ever
/// exercised. It never is here: Android already has a real native root/
/// emulator detector (see `RaspNativeChannel`), so `safe_device` was
/// carried purely for iOS while silently taxing every Android customer
/// with two location permissions they get no benefit from.
///
/// A host app that targets iOS and wants this weaker, single-signal
/// fallback registers an implementation (see `rasp_app`'s
/// `SafeDeviceIosFallback` for the reference one, still backed by
/// `safe_device`) via [IosFallback.provider]. With no provider registered,
/// [isJailbroken]/[isSimulator] both report `null` (unavailable) — the same
/// honest "could not check" every other gap in this SDK reports, never a
/// false "secure".
abstract class IosFallbackDetector {
  /// `true`/`false` from a real jailbreak check, or `null` when unavailable.
  Future<bool?> isJailbroken();

  /// `true`/`false` from a real simulator check, or `null` when unavailable.
  Future<bool?> isSimulator();
}

/// Holds the host-supplied [IosFallbackDetector] — `null` by default.
class IosFallback {
  IosFallback._();

  static IosFallbackDetector? provider;
}
