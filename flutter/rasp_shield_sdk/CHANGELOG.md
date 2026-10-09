## 1.1.0

* Signed evidence envelopes are the default (`useEvidenceEnvelope: true`).
* Device registration proves possession of the device key (server challenge)
  and sends a hashed device id, so a reinstall is the same phone.
* `malwareReputationAutoUpdate`: the signed list from the backend.
* `configureTlsPinning` keeps normal certificate validation and adds the pin
  check before any request data is sent; no compiled-in demo backend.
* Descriptor severities follow the backend table.
* Kotlin unit tests updated to the engine's current detector rules.

## 1.0.0

* First lean-session release: Kotlin engine detectors, five result states,
  event shipping to the dashboard.
