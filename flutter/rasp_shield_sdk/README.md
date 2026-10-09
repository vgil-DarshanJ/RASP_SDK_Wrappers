# rasp_shield_sdk

RASP Shield for Flutter apps on **Android**: 42 on-device security checks
(root, emulator, hooking, tampering, network interception, screen and
fraud signals) through the Kotlin engine, with signed delivery of the
results to a RASP Shield dashboard. iOS is not supported.

- Integration: [docs/LEAN_SECURITY_INTEGRATION_GUIDE.md](docs/LEAN_SECURITY_INTEGRATION_GUIDE.md)
- Facts (detector list, states, versions, minimum Android): `docs/PRODUCT_FACTS.md`
  in the engine repository

## Supported API

Use `package:rasp_shield/sdk/lean_session.dart` (`RaspLeanSession`,
`RaspLeanConfig`), `sdk/security_controls.dart`,
`sdk/events/security_event_shipper.dart`, `sdk/fraud_risk.dart` and
`sdk/core/core.dart`. The other libraries under `lib/` (licensing,
activation, vault, remote commands — the older "full path") are not part of
the supported API and are not maintained for production use.

