# Android Native SDK Reference — `RaspShieldCore`

The authoritative reference for the pure Kotlin/Java native Android SDK
(`android_core` + `rasp_shield_native`, see
`sdk_rasp/android_native/README.md` for integration steps). Covers every
public method, the result contract, required permissions/manifest entries,
R8/ProGuard requirements, and how to wire `selfTest()` into a release
pipeline.

This document did not exist before the Android Native/Flutter Feature
Parity effort — several comments elsewhere in this codebase *cited* a doc
like this without one actually existing on disk. This is now the real one.

## Contents
1. [The result contract](#the-result-contract)
2. [Calling convention: blocking + async](#calling-convention-blocking--async)
3. [Full detector reference, by category](#full-detector-reference-by-category)
4. [Whole-catalog orchestration](#whole-catalog-orchestration)
5. [Play Integrity attestation](#play-integrity-attestation)
6. [Screenshot/video protection — `RaspScreenGuard`](#screenshotvideo-protection--raspscreenguard)
7. [Configuration surface](#configuration-surface)
8. [Manifest & permissions](#manifest--permissions)
9. [R8/ProGuard keep rules](#r8proguard-keep-rules)
10. [Exception-handling contract](#exception-handling-contract)
11. [Production checklist](#production-checklist)
12. [Known platform-version gates](#known-platform-version-gates)
13. [Explicitly out of scope](#explicitly-out-of-scope)

---

## The result contract

Every detector returns a `RaspCheckResult`:

```kotlin
data class RaspCheckResult(
    val detectorId: String,
    val status: RaspCheckStatus,
    val evidence: List<RaspEvidence> = emptyList(),
    val reason: String? = null,       // set only for UNAVAILABLE/UNKNOWN/ERROR
    val observedAtMillis: Long = System.currentTimeMillis(),
)

enum class RaspCheckStatus { SECURE, DETECTED, UNAVAILABLE, UNKNOWN, ERROR }
```

**The single rule that governs this whole SDK**: a check that could not run
is never reported as `SECURE`. Five states, not two:

| Status | Meaning | Treat as a threat? |
|---|---|---|
| `SECURE` | Ran, found nothing. | No — the only "safe" status. |
| `DETECTED` | Ran, found a threat. | Yes. |
| `UNAVAILABLE` | Never ran — wrong platform/API level, nothing configured, or a signed policy disabled it. Expected. | No, but don't treat as safe either — it means "no answer." |
| `UNKNOWN` | Ran, but couldn't reach a conclusion (e.g. a system path this app can't list). | No — but again, not safe. |
| `ERROR` | Ran, threw/timed out/malformed reply. A fault. | No — investigate. |

`RaspEvidence(key, value, note?)` — supporting detail. Never the full raw
signal a caller didn't ask for (e.g. clipboard evidence carries a change
*count*, never clipboard *content*).

No confidence/severity score is included — this native SDK reports raw
per-detector results only. Combine results with your own policy weighting,
or use the full licensed Flutter `RaspShield` pipeline if you want a single
risk-score engine built in.

## Calling convention: blocking + async

Every check ships as a matched pair:

```kotlin
fun checkXBlocking(context: Context): RaspCheckResult          // synchronous
fun checkXAsync(context: Context, callback: (RaspCheckResult) -> Unit)  // background thread, callback on main
```

`checkXBlocking` does real I/O (Keystore, `Runtime.exec`, filesystem,
network) — **call it off the main thread**, or use `checkXAsync`, which
runs on an internal single-thread executor and delivers the result via
`Handler(Looper.getMainLooper())`. No `kotlinx-coroutines` dependency
either way. Callable from Java as `checkXAsync(context, result -> { ... })`.

## Full detector reference, by category

### Device integrity

| Method | detectorId | Notes |
|---|---|---|
| `checkRootBlocking/Async` | `root_jailbreak` | Evidence: `root_signal` × N, `signal_count`. |
| `checkEmulatorBlocking/Async` | `emulator` | Evidence: `emulator_signal` × N, `signal_count`. |
| `checkDeviceBindingBlocking/Async` | `device_binding` | Hardware Keystore key. `UNAVAILABLE` below API 23. |
| `checkDeviceFingerprintBlocking/Async` | `device_fingerprint` | Screen lock, ADB, SELinux, install source. |
| `checkCloneBlocking/Async` | `clone` | Parallel-space/dual-app detection, 2-signal. |
| `checkDeveloperModeBlocking/Async` | `developer_mode` | `Settings.Global` read. |
| `checkAdbEnabledBlocking/Async` | `adb_enabled` | `Settings.Global` read. |
| `checkUsbConnectionBlocking/Async` | `usb_connection` | Physical cable/dock state. |
| `checkDeviceLockMissingBlocking/Async` | `device_lock_missing` | No PIN/pattern/password/biometric. |
| `checkSecureHardwareUnavailableBlocking/Async` | `secure_hardware_unavailable` | No TEE/StrongBox. |

Batch: `RaspShieldCore.scanDeviceIntegrityBlocking(context): List<RaspCheckResult>` (10 results).

### Runtime protection

| Method | detectorId | Notes |
|---|---|---|
| `checkFridaBlocking/Async` | `frida` | Evidence: `frida_signal` × N. |
| `checkDebuggerBlocking/Async` | `debugger` | `DETECTED` on debuggable build OR live attach. Evidence: `build_mode` and/or `debugger_signal`. |
| `checkReverseEngineeringToolsBlocking/Async` | `re_tools` | 9 curated packages — see [Manifest](#manifest--permissions). |
| `checkHookingBlocking/Async` | `hook_detection` | Reflection-based — see [R8 keep rules](#r8proguard-keep-rules). |

Batch: `scanRuntimeProtectionBlocking(context)` (4 results).

### App integrity

| Method | detectorId | Notes |
|---|---|---|
| `checkTamperBlocking/Async` | `tamper` | Meaningful even with no fingerprint configured (checks install-dir integrity too). |
| `checkRepackagingBlocking/Async` | `repackage` | **`UNAVAILABLE` until you call `configureExpectedSigningCertificate()`.** Never silently passes. |
| `checkUntrustedInstallSourceBlocking/Async` | `untrusted_install_source` | Trusted installers: Play Store, Amazon, Huawei, Samsung Galaxy Store. |

Batch: `scanAppIntegrityBlocking(context)` (3 results).

### Network security

| Method | detectorId | Notes |
|---|---|---|
| `checkVpnBlocking/Async` | `vpn` | `NetworkCapabilities` + `tun`/`ppp`/`tap` interface fallback. |
| `checkMitmBlocking/Async` | `mitm` | Native proxy check first; TLS-pin corroboration if `configureCertificatePin()` was called. **Real network I/O when the pin path runs.** |
| `checkHighRiskIpBlocking/Async` | `high_risk_ip` | **Real network I/O, 5s timeout.** `UNAVAILABLE` on a failed lookup — never blocks a legitimate user on a flaky network. |

Batch: `scanNetworkSecurityBlocking(context)` (3 results) — **heavier than other batches** (network I/O). Always call off the main thread.

### Privacy & screen

| Method | detectorId | Notes |
|---|---|---|
| `checkOverlayBlocking/Async(context, screenGuard?)` | `overlay` | Pass your attached `RaspScreenGuard` for the touch-obscured corroboration signal. Without one, only the static permission-holder signal runs — see its own disclosed API 30+ limitation below. |
| `checkAccessibilityBlocking/Async` | `accessibility` | Excludes first-party/TalkBack services. |
| `checkExternalDisplayBlocking/Async` | `external_display` | Presence only — not proof your content is shown there. |

Batch: `scanPrivacyScreenBlocking(context, screenGuard?)` (3 results). Screenshot/video protection is **not** in this batch — see [§6](#screenshotvideo-protection--raspscreenguard).

**Disclosed limitation — `overlay`'s static signal**: the permission-holder scan requires enumerating installed packages, which Android 11+ restricts to `<queries>`-visible packages unless the app holds `QUERY_ALL_PACKAGES` (a sensitive Play-reviewed permission this SDK does not request on your behalf). On a real device without that permission, this signal is **structurally blind** to most third-party apps. The `touch_obscured` runtime signal (via `RaspScreenGuard`) is unaffected by this and is the more reliable corroborating signal in practice.

### Risky app / app intelligence

| Method | detectorId | Notes |
|---|---|---|
| `checkRiskyAppBlocking/Async` | `risky_app` | 7 curated remote-access/instrumentation packages + suspicious accessibility services. |
| `checkAppIntelligenceBlocking/Async` | `app_intelligence` | Signing-identity + install-source classification for the same 7 packages, if installed. |

Batch: `scanRiskyAppBlocking(context)` (2 results). **Not a malware scanner** — see the class docs on `RaspRiskyAppProbes`/`RaspAppIntelligenceProbes` for the `<queries>`-visibility constraint.

## Whole-catalog orchestration

```kotlin
RaspShieldCore.scanAllBlocking(context): List<RaspCheckResult>   // 25 results
RaspShieldCore.scanAllAsync(context) { results -> ... }
```

Covers every Context-only detector above. **Not included**: screenshot/video
protection (needs a live `Activity` — see §6) and offline-compliance (needs
the licensed backend pipeline this native SDK deliberately excludes — there
is no native equivalent to call at all).

### `selfTest()` — run this in your release-build CI, not just once

```kotlin
val report = RaspShieldCore.selfTest(context)
report.results                    // same as scanAllBlocking — 25 results
report.criticalReflectionIntact   // false = R8 keep rules missing/broken
report.erroredDetectorIds         // any ERROR is worth investigating
report.unavailableDetectorIds     // inspect each `reason` — some are expected
```

`criticalReflectionIntact` is the one concrete, self-diagnosable symptom of
a missing R8 keep rule: `hook_detection`'s reflection-based integrity check
(`RaspHookProbes`) resolves six methods by hardcoded class+method name. Run
`selfTest()` against your actual **release, R8-minified** build — an
unminified debug build can never catch this, by construction.

## Play Integrity attestation

Not shaped like a `RaspCheckResult` — it returns an attestation **token**
(opaque, server-verified), not a local verdict.

```kotlin
RaspShieldCore.isPlayIntegrityAvailable(context): Boolean   // heuristic reachability only
RaspShieldCore.requestPlayIntegrityToken(context, nonce, onResult)
// onResult: (Result<String>) -> Unit — success carries the raw token,
// failure carries an IntegrityRequestException with a stable .code
```

The `nonce` must be a **server-issued** challenge — this method never
mints or trusts a locally-generated one. Requires the
`com.google.android.play:integrity` dependency (already declared in
`android_core/build.gradle.kts`) and Google Play Services on-device.

## Screenshot/video protection — `RaspScreenGuard`

Needs a live `Activity`, not just a `Context` — a one-shot `Context`-based
call cannot express the touch-tracking/screenshot-event lifecycle this
needs. Construct one per `Activity` (or reuse across transitions):

```kotlin
class TransferActivity : AppCompatActivity() {
    private val screenGuard = RaspScreenGuard()

    override fun onCreate(savedInstanceState: Bundle?) {
        screenGuard.attach(this)   // apply BEFORE super.onCreate()
        super.onCreate(savedInstanceState)
    }

    override fun onDestroy() {
        screenGuard.detach()
        super.onDestroy()
    }
}
```

| Method | Returns | Notes |
|---|---|---|
| `attach(activity)` | — | Applies `FLAG_SECURE`, installs touch-obscured tracking, registers screenshot-event callback (API 34+). |
| `detach()` | — | Idempotent. |
| `isScreenshotProtectionActive()` | `Boolean?` | `null` = not attached / could not determine. |
| `enableScreenshotProtection()` / `disableScreenshotProtection()` | `Boolean` | For a screen the user is meant to screenshot (e.g. a QR code). |
| `currentTouchObscuredState()` | `Boolean?` | `null` until a touch has been observed this attach. Feed to `checkOverlayBlocking`. |
| `drainScreenshotEventEvidence()` | `RaspScreenshotEventEvidence` | Read-and-clear. API 34+ only — `supported=false` below that. |
| `screenCaptureCapabilities()` | `RaspScreenCaptureCapabilities` | What this build/OS can actually do. |

**`FLAG_SECURE` blocks BOTH still screenshots and screen recording/casting**
— one call, no separate video toggle. It cannot stop a second physical
camera filming the screen, or an HDMI-out capture rig on heavily modified
hardware — no app-side control anywhere can.

**Disclosed OnePlus timing risk**: `attach()` applies `FLAG_SECURE`
immediately — calling it before `super.onCreate()` (as shown above) gives
the earliest-possible timing, empirically proven necessary on a physical
OnePlus device (Android 16/API 36) to avoid an OEM compositor black-screen
regression. Test on your real device matrix (Samsung, Xiaomi/Oppo/Vivo,
OnePlus), not just an emulator.

## Configuration surface

No license, no activation, no backend call — every configuration point
below is a plain, explicit method call your app makes, never magic
reflection into your own `BuildConfig` and never a value fetched from a
server.

```kotlin
RaspShieldCore.configureExpectedSigningCertificate(fingerprint: String?)
// Required before checkRepackagingBlocking() reports anything but UNAVAILABLE.
// Accepts ':'/space/dash-separated or plain hex; normalized internally.

RaspShieldCore.configureCertificatePin(host: String?, pinnedSha256Hex: String?)
// Optional — enables the TLS-pin corroboration half of checkMitmBlocking().
// Pass null/null to clear.

RaspShieldCore.logger = object : RaspShieldLogger {
    override fun onDetectorError(detectorId: String, throwable: Throwable) {
        // wire into your own crash reporting
    }
}
// Default is a silent no-op. Never allowed to crash a detector itself —
// an exception from your logger implementation is caught and dropped.
```

## Manifest & permissions

Everything below merges automatically from `android_core`'s own
`AndroidManifest.xml` into any app that depends on it — no manual edit
needed on your side.

- **`INTERNET`** — required by `high_risk_ip`, the TLS-pin half of `mitm`,
  and Play Integrity's own client library. Every other detector needs no
  permission at all.
- **`<queries>`** — 15 packages total: 7 for risky-app/app-intelligence
  (TeamViewer ×2, AnyDesk, Mobizen, RemotePC, Xposed framework, Substrate)
  and 9 (with one overlap) for reverse-engineering-tools detection (Xposed
  Installer, Magisk, su apps, Lucky Patcher, GameGuardian-class tools,
  AdAway). **These 7/9 lists are intentionally small and curated** — this
  SDK does not request `QUERY_ALL_PACKAGES` and never will on your behalf.

## R8/ProGuard keep rules

Already declared in `android_core/consumer-rules.pro` and applied
automatically to any consuming app's release build:

```proguard
-keep class com.google.android.play.core.integrity.** { *; }

-keep class com.shieldsdk.rasp.RaspDeviceProbes {
    boolean isFridaDetected();
    boolean isDebuggerAttached();
}
-keep class com.shieldsdk.rasp.RaspHookProbes {
    boolean isHookingDetected();
}
-keep class com.shieldsdk.rasp.RaspSignalAnalysis {
    boolean fridaVerdict(java.util.List);
    boolean debuggerVerdict(java.util.List);
}
-keep class com.shieldsdk.rasp.RaspHookAnalysis {
    boolean hookVerdict(java.util.List);
}
```

**Why this matters**: `RaspHookProbes` (the `hook_detection` check)
resolves six specific methods reflectively, by hardcoded class+method name
string, as its own integrity check (a Java-level hooking framework
replaces a method's entry point, after which ART reports it as `native` —
that's the actual signal being checked for). **Without these keep rules**,
R8 minification on your release build silently renames these methods, the
reflection permanently resolves to "unavailable" for all six, and
`hook_native_method` can never fire again — not a crash, a detector
quietly going dark. This is a **real, pre-existing gap** this SDK's
extraction found (the rule did not exist before this effort) — it's fixed
now, but `selfTest().criticalReflectionIntact` exists specifically so a CI
pipeline catches it again if these `consumer-rules.pro` entries are ever
accidentally dropped or overridden by a conflicting rule elsewhere in your
build.

## Exception-handling contract

1. **Never throws across the public API boundary.** Every `checkXBlocking`
   is wrapped internally — an uncaught exception becomes `ERROR` with a
   `reason`, reported to `RaspShieldCore.logger` if one is set.
2. **`null`/`UNAVAILABLE`/`UNKNOWN` are never "safe."** Always branch on
   the real status, never assume anything but `SECURE` means clean.
3. **Every blocking I/O call is time-bounded.** `Runtime.exec` calls
   (`RaspProcessUtils`) have a hard timeout with a watcher-thread fallback
   below API 26; the Frida port probe has a 500ms join deadline; network
   calls (`high_risk_ip`, TLS-pin) have a 5s timeout.
4. **One detector's failure never blocks another's.** `scanAllBlocking`
   sequences already-guarded calls — no additional exception risk from the
   orchestration layer itself.
5. **No host-app-specific reflection.** Unlike the Flutter plugin path's
   historical `readHostSigningBuildConfig()`, this native SDK never
   reflects into your app's generated `BuildConfig` — see
   [Configuration surface](#configuration-surface).

## Production checklist

- [ ] Run `RaspShieldCore.selfTest()` against your actual **release**
      (R8-minified) build in CI, before every production release
- [ ] Confirm `report.criticalReflectionIntact == true` on that build
- [ ] Call `configureExpectedSigningCertificate()` before relying on
      `repackage` reporting anything but `UNAVAILABLE`
- [ ] Every `Boolean?`/status branch in your app handles all outcomes —
      code-reviewed, not just tested
- [ ] `RaspScreenGuard.attach()`/`.detach()` wired to your Activity
      lifecycle, tested on a real OEM device matrix (not just emulator)
- [ ] `RaspShieldCore.logger` wired to your crash-reporting pipeline
- [ ] Decided and documented your policy response for each `DETECTED`
      result — this SDK detects, it does not decide your banking policy
- [ ] Your own audit-logging wired at every call site you act on (this
      SDK reports nothing to any backend on its own — see
      `LEAN_SECURITY_INTEGRATION_GUIDE.md` Part D for the pattern)

## Known platform-version gates

| Feature | Minimum API | Below that |
|---|---|---|
| Screenshot-event detection (`drainScreenshotEventEvidence`) | 34 (`UPSIDE_DOWN_CAKE`) | `supported=false`, honestly — never approximated |
| StrongBox keystore check | 28 (`P`) | TEE-only check |
| `KeyInfo.securityLevel`-based secure-hardware check | 31 | Falls back to `isInsideSecureHardware` |
| `getInstallSourceInfo` (install source) | 30 (`R`) | Falls back to deprecated `getInstallerPackageName` |
| Everything else (root, emulator, Frida, hooking, tamper, VPN, overlay, accessibility, clipboard, USB) | 23 (`minSdk`) | N/A |

Screen recording/casting has **no detection API at any level** — `FLAG_SECURE`
is the platform's actual defense there, with no complementary detector to pair it with.

## Explicitly out of scope

- **Offline-compliance** — requires the licensed `LicenseManager`/
  `RemoteConfigManager` backend pipeline. No native equivalent exists;
  not planned for this SDK.
- **Confidence/severity scoring** — this SDK reports raw detector results
  only. Use the full licensed Flutter `RaspShield` pipeline if you want a
  single weighted risk score computed for you.
- **iOS** — not covered by this document at all; a separate effort.
