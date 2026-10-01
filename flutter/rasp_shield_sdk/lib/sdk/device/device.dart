/// Cryptographic per-device licence binding.
///
/// A licence is bound to TENANT + APPLICATION + SIGNING IDENTITY + DEVICE
/// CRYPTOGRAPHIC IDENTITY. The first three were already enforced; this
/// library adds the fourth, so copying a valid token to another handset no
/// longer authorises it.
///
/// Read `docs/LICENSE_DEVICE_BINDING.md` before changing anything here.
library;

export 'canonical_field.dart';
export 'device_binding_state.dart';
export 'device_key.dart';
export 'device_key_manager.dart';
export 'device_proof.dart';
export 'license_binding_validator.dart';
