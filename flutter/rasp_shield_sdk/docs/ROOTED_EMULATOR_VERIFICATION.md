# P0-1 permanent regression gate — rooted-device root detection

This is the reproducible procedure that closed the P0-1 acceptance gap:
proving the customer SDK ZIP's packaged native `root_jailbreak` detector
returns `DETECTED`, with real evidence, on a genuinely rooted Android
runtime — not a mocked `MethodChannel`, not source-repository files.

Not yet wired into CI (needs an emulator + writable-system relaunch, not a
plain `flutter test`/`pytest` run) — this doc is the procedure until it is.

## Prerequisites

- Android SDK with the `emulator` and `platform-tools` components.
- An AVD on a `userdebug`/`eng` system image (`ro.build.type` — check with
  `adb shell getprop ro.build.type`). A `google_apis` (not `google_apis_playstore`)
  image is verified to work; a locked "Google Play" image will refuse
  `-writable-system`.
- The backend running locally (never the office server) so a real customer
  ZIP can be generated through `POST /api/v1/sdk-center/packages/{id}/generate`.

## Procedure

1. **Generate a real customer ZIP** through the actual endpoint (a portal
   session that passed lifecycle approval — see
   `Ai/backend/tests/test_sdk_distribution.py`'s `_seed`/`_approved_portal_headers`/
   `_generate` helpers for the exact call shape). Extract it into a **brand
   new temp directory outside the repo** — never reuse a previous extraction.

2. **Build it standalone**, from the extracted `example/`:
   ```
   flutter pub get
   flutter analyze
   flutter build apk --debug
   ```
   This must be the only build step — no file is ever copied in from the
   source checkout.

3. **Boot the AVD with `-writable-system`**:
   ```
   emulator -avd <name> -writable-system -no-snapshot -no-boot-anim
   ```

4. **Create a genuine root condition** (not a mock, not injected app state):
   ```
   adb root
   adb reboot                     # required once, for a disabled dm-verity to take effect
   adb root
   adb remount                    # remounts /system (and /vendor, /product) read-write
   adb shell cp /system/bin/toybox /system/bin/su
   adb shell chmod 06755 /system/bin/su
   adb unroot                     # test as an ordinary unprivileged app would see it
   ```
   **Path matters**: `/system/xbin` is `drwxr-x---` (no `other` permission at
   all) on this AVD's image — a file placed there is invisible to an
   unprivileged app's process, which is a real, documented Android hardening
   behavior, not a detector bug. `/system/bin` is `drwxr-x--x` (`other` has
   execute/traverse), so a file placed there resolves by exact path from any
   app's own sandbox. Confirm with:
   ```
   adb shell run-as <package> ls -la /system/bin/su
   ```

5. **Install the clean-built APK and launch it**:
   ```
   adb install -r example/build/app/outputs/flutter-apk/app-debug.apk
   adb shell am start -n <package>/com.shieldsdk.rasp_shield_example.MainActivity
   ```
   The packaged example runs the SDK's real detector registry
   (`ScanRunner(registry: defaultRegistry(...)).scanAll()`) once at startup
   and prints every result to logcat as `[RASP-SCAN] <id> status=... threat=...
   evidence=[...]`. Read with:
   ```
   adb logcat | grep RASP-SCAN
   ```

6. **Verify**:
   - `root_jailbreak status=detected threat=true evidence=[root_signal=su_binary,...]`
   - `native_layer=NATIVE_SECURITY_LAYER_AVAILABLE` (proves the native plugin
     answered at all — a missing plugin would instead read
     `NATIVE_SECURITY_LAYER_UNAVAILABLE` and `root_jailbreak status=unavailable`,
     never a false `secure`).
   - Repeat on a clean (non-writable, no `su`) boot of the same AVD and
     confirm `root_jailbreak status=secure threat=false evidence=[]` —
     the same packaged APK must produce different real outcomes.
   - Every other detector must be `status=secure`, `status=detected`, or an
     explained `status=unavailable`/`error` (e.g. `high_risk_ip` needs
     network, `repackage` needs a pinned cert) — **never** silently absent.

## Known limitation surfaced by this procedure (not fixed here — out of scope)

`RaspDeviceIntegrityProbes.readMounts()` reads `/proc/mounts` via
`java.io.File(...).readText()`. `/proc/mounts` reports `stat` size `0` (a
standard procfs virtual-file property), and on this runtime `readText()`
silently returns `""` for it — confirmed directly:
`run-as <package> stat -c '%s' /proc/self/mounts` → `0`, and the string
`magisk`/`KSU`/`/data/adb` is absent from what the app reads even when a
real overlay-mounted, genuinely `rw` `/system` is present. This makes the
`system_writable` and `mount_namespace` root signals permanently
non-firing — a **pre-existing defect** (the logic is a verbatim, unmodified
move from the original `MainActivity.rootSignals()`), not something this
verification introduced. `root_jailbreak` still correctly reaches `DETECTED`
via `su_binary`/`su_on_path`, since the verdict is "any signal convicts" —
but two of eleven signals are dead weight. Worth a follow-up ticket to read
`/proc/mounts` via a streaming reader (e.g. `BufferedReader` without a
length-presized buffer) instead of `File.readText()`.
