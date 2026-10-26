# rasp-shield-react-native

React Native plugin for RASP Shield. It holds no detection logic: it binds the shared `android-core` engine (the one behind the Flutter plugin and the Android Native SDK), so the 43 on-device detectors, the 5-state result contract and the signed event shipping are identical across all three SDKs.

**Platforms:** Android (API 24+, New and Old Architecture). iOS is not implemented yet; there every detector reports `UNAVAILABLE`, never `SECURE`.

## Install

```sh
npm install rasp-shield-react-native      # from a registry
npm install --install-links ../path/to/rasp_shield_react_native   # from the unzipped SDK folder
```

Use `--install-links` for a folder: it copies the plugin into `node_modules`. A plain link points outside your app, where Metro and TypeScript cannot find `react` / `react-native`. Autolinked either way, no manual Gradle edit.

The engine comes from JitPack (added automatically). Pin another engine with `raspEngineVersion=1.1.0` in `gradle.properties`; `1.1.0-local` resolves from `mavenLocal`.

Add to `AndroidManifest.xml` what the detectors you use need: `READ_PHONE_STATE` (`sim_change`, `vishing_call`), `DETECT_SCREEN_CAPTURE` (`screenshot_event`), `DETECT_SCREEN_RECORDING` (`screen_recording`), `ACCESS_WIFI_STATE` / `ACCESS_NETWORK_STATE` (`unsafe_wifi`). Plain-HTTP backends need a `network_security_config`.

## Use

```tsx
import { configFromDetectors, useRaspSession, RaspEventShipper } from 'rasp-shield-react-native';

await RaspEventShipper.configure(credentialJson, { persist: true }); // from the dashboard

const config = configFromDetectors(['root_jailbreak', 'frida', 'hook_detection', 'vpn'], {
  expectedSigningCertSha256: '…', // lets `tamper` give a verdict
});

function Screen() {
  const { state, error, refresh } = useRaspSession(config);
  return <Text>{state.extendedDetectors.root_jailbreak?.status ?? 'WAITING'}</Text>;
}
```

Without React: `const s = await RaspLeanSession.start(config); s.onState(console.log); await s.stop();`

| API | Purpose |
|---|---|
| `RaspLeanSession` / `useRaspSession` | Scans on an interval, ships changes to the dashboard. One native session at a time. |
| `RaspShieldCore` | One-shot `scanAll`, `check`, `selfTest`, `setScreenshotProtection`, `clearClipboard`, `getSdkInfo`. |
| `RaspEventShipper` | `configure`, `restore`, `clear`, `isConfigured` for `credential.json`. |
| `session.reportSession / reportTransaction / signTransaction` | Session risk and signed transaction binding (`sessionRiskScoring: true`; needs `account_hash_salt`). |
| `session.setLocation / setServerTime / refreshRemoteConfigNow` | Host-supplied inputs and signed remote config. |

## Rules

- A check that could not run is `UNAVAILABLE`, `UNKNOWN` or `ERROR`; only a real finding is `DETECTED` and only a real pass is `SECURE`. Treat the first three as "no verdict".
- The API secret never returns to JavaScript. Location is supplied by your app; the SDK never requests it.
- Run `RaspShieldCore.selfTest()` on your release build in CI to catch R8 stripping.

## Develop

`npm test` and `npm run typecheck` need the dev dependencies (`npm install` here). The trial app (`trial_app/rasp_trial_rn`) also runs this package's tests with `npm test`.
