# RASP Shield — Flutter Integration Guide

This walks through integrating the real, current SDK — `RaspLeanSession`,
all 26 detectors, automatic event shipping to your RASP Shield dashboard —
into a Flutter app, step by step, showing exactly where each piece of code
goes relative to what's already in a fresh Flutter project.

If you're on Android Native (no Flutter) instead, skip to
[the Android Native guide](../../android_native/README.md) — the concepts
are identical, only the language differs.

---

## Before you start: two things you need from the dashboard

1. **Register your app.** On the RASP Shield dashboard → **Applications** →
   **Register application** → pick **Flutter**. This issues a credential —
   click **Download credential.json** and keep the file; it's shown once
   and can't be re-displayed (only rotated).
2. **Download the SDK.** Same card → **Download SDK**. Unzip it somewhere —
   you'll reference the `flutter/rasp_shield_sdk` folder inside it in Step
   2 below.

---

## Step 1 — Add the JitPack repository

The SDK's detection engine (`android_core`) is published via
[JitPack](https://jitpack.io), not bundled inside the SDK download —
Gradle fetches it automatically the first time you build, the same way it
already fetches every other dependency your app uses. This is a real,
required step: skipping it produces a clear "could not resolve
com.github.Vedant0Nisar:RaShield-SDK" error at build time, not a silent
failure.

Open **`android/build.gradle.kts`** in your Flutter app (not the SDK's own
files — your app's own file, at the Android project root). A fresh Flutter
project already has this exact block — you're adding **one line** inside
the existing `repositories { }`:

```kotlin
// android/build.gradle.kts — your app, BEFORE
allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
```

```kotlin
// android/build.gradle.kts — your app, AFTER (the new line is the maven{} one)
allprojects {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }   // ← add this line
    }
}
```

If your project instead declares repositories inside
`android/settings.gradle.kts` under a `dependencyResolutionManagement`
block (some newer Flutter/Android Studio templates do this), add the same
`maven { url = uri("https://jitpack.io") }` line inside that block instead
— same one line, different file, depending on which template your project
started from. If you're not sure which one your project has, search your
`android/` folder for `repositories {` — wherever `google()` and
`mavenCentral()` already appear together is the right spot.

---

## Step 2 — Add the SDK as a dependency

Open **`pubspec.yaml`** at your Flutter app's root. Find the existing
`dependencies:` block — every fresh Flutter project has one, listing at
least `flutter: sdk: flutter`. Add `rasp_shield` as a sibling entry:

```yaml
# pubspec.yaml — BEFORE
dependencies:
  flutter:
    sdk: flutter
  cupertino_icons: ^1.0.8
```

```yaml
# pubspec.yaml — AFTER (rasp_shield is the new block)
dependencies:
  flutter:
    sdk: flutter
  cupertino_icons: ^1.0.8
  rasp_shield:
    path: ../rasp_shield_flutter_sdk/flutter/rasp_shield_sdk   # ← add this
```

Adjust the `path:` to wherever you actually unzipped the SDK download —
it must point at the folder that directly contains `rasp_shield_sdk`'s own
`pubspec.yaml` (the one with `name: rasp_shield` in it), not the zip's top
folder and not a `.iml`/IDE project file.

Then, in the SAME `pubspec.yaml`, find the `flutter:` block near the
bottom (every fresh project has one, usually just `uses-material-design:
true`) and add an `assets:` entry — this is where your downloaded
credential file will live:

```yaml
# pubspec.yaml — BEFORE
flutter:
  uses-material-design: true
```

```yaml
# pubspec.yaml — AFTER
flutter:
  uses-material-design: true
  assets:
    - assets/rasp_credential.json   # ← add this
```

Now create the actual folder and file: make a new folder named `assets`
at your project root (same level as `pubspec.yaml`, next to `lib/`), and
put the `credential.json` you downloaded from the dashboard inside it,
renamed to exactly `rasp_credential.json`.

Run:
```bash
flutter pub get
```

---

## Step 3 — Wire it into your app's startup

This is the only code you write. Open **`lib/main.dart`**. A fresh Flutter
project's `main.dart` has a `_MyHomePageState` class (or whatever your
main screen's State class is called) with an `initState()` method already
in it. Here's exactly what changes, shown against the actual Flutter
starter template so you can see precisely what's new versus what was
already there:

```dart
// lib/main.dart — BEFORE (stock Flutter starter template)
import 'package:flutter/material.dart';

void main() {
  runApp(const MyApp());
}

// ...MyApp class unchanged...

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;

  @override
  void initState() {
    super.initState();
  }

  void _incrementCounter() {
    setState(() { _counter++; });
  }

  @override
  Widget build(BuildContext context) { /* ... */ }
}
```

```dart
// lib/main.dart — AFTER (added lines marked)
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;                 // ← add
import 'package:rasp_shield/sdk/events/security_event_shipper.dart';    // ← add
import 'package:rasp_shield/sdk/lean_session.dart';                     // ← add

void main() {
  runApp(const MyApp());
}

// ...MyApp class unchanged...

class _MyHomePageState extends State<MyHomePage> {
  int _counter = 0;
  RaspLeanSession? _raspSession;                                        // ← add

  @override
  void initState() {
    super.initState();
    _bootstrapRasp();                                                   // ← add
  }

  // ← add this whole method
  Future<void> _bootstrapRasp() async {
    // First launch ever: load the credential you downloaded and bundled
    // as an asset in Step 2. Every launch after that, `restore()` reads
    // it back from encrypted storage — you don't reload the asset again.
    final restored = await RaspSecurityEventShipper.restore();
    if (!restored) {
      final credentialJson = await rootBundle.loadString('assets/rasp_credential.json');
      await RaspSecurityEventShipper.configureAndPersist(credentialJson);
    }

    // Starts the background poll/ship loop. This is the ONLY place you
    // choose which of the 26 detectors are active — see the table below
    // for what each one does and what you're exposed to if you skip it.
    _raspSession = await RaspLeanSession.start(const RaspLeanConfig(
      screenshotProtection: true,
      usbDetection: true,
      adbDetection: true,
      clipboardProtection: true,
      rootDetection: true,
      fridaDetection: true,
      hookDetection: true,
      tamperDetection: true,
      untrustedInstallSourceDetection: true,
      mitmDetection: true,
      overlayDetection: true,
      accessibilityDetection: true,
      developerModeDetection: true,
      deviceLockCheck: true,
    ));

    // This is where YOUR app reacts to a detection — the SDK already
    // ships every event to your dashboard automatically regardless of
    // what you do here; this listener is purely for in-app behavior.
    _raspSession!.stateStream.listen((state) {
      final root = state.extendedDetectors['root_jailbreak'];
      final frida = state.extendedDetectors['frida'];
      final criticalThreat = (root?.status.isThreat ?? false) ||
          (frida?.status.isThreat ?? false);

      if (criticalThreat && mounted) {
        // Replace with your own policy: force logout, block a payment
        // screen, show a blocking dialog — whatever your bank decides.
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Security threat detected on this device')),
        );
      }
    });
  }

  // ← add this whole method
  @override
  void dispose() {
    _raspSession?.dispose();
    super.dispose();
  }

  void _incrementCounter() {
    setState(() { _counter++; });
  }

  @override
  Widget build(BuildContext context) { /* unchanged */ }
}
```

That's the entire integration. Run `flutter run` (or `flutter build apk`)
and check the **Live Threats**/**Devices** page on your dashboard — events
should appear within a few seconds of the app launching.

---

## What each `RaspLeanConfig` flag actually turns on

Every flag defaults to `false` — you only pay for (and are protected by)
what you explicitly enable. The full table of all 26, with the exact
config field name and what you're exposed to if you leave one off, is on
your dashboard's **Integration Guide** page (`/guide`) — it's generated
directly from this same SDK's source, so it never drifts out of sync the
way a hand-maintained doc table eventually does. This document won't
duplicate that table for the same reason.

---

## Exception-handling contract — read this once, it explains "will it crash"

1. **Three states, never two.** Every detector reports
   `SECURE` / `DETECTED` / `UNAVAILABLE` / `UNKNOWN` / `ERROR` — never a
   plain boolean. `UNAVAILABLE`/`UNKNOWN`/`ERROR` mean *"could not
   determine,"* never *"safe."* If you write your own logic against
   `state.extendedDetectors[...]`, always check `.status.isThreat`
   (`true` only for a genuine `DETECTED`) rather than assuming a missing
   or non-`DETECTED` result means secure.
2. **Every detector is crash-isolated.** A detector throwing internally is
   caught and reported as `ERROR`, never an uncaught exception that could
   crash your app — this is enforced by a single wrapper
   (`runGuarded` in `RaspShieldCore.kt`) every one of the 26 detectors
   goes through.
3. **Shipping never blocks or crashes your app.** `RaspSecurityEventShipper`
   sends each event fire-and-forget on its own background execution path.
   A network failure, a malformed response, a misconfigured credential —
   all resolve to a logged no-op, never a thrown exception back into your
   app and never a delay to your UI.
4. **The one detector that makes a real network call** is `high_risk_ip`
   (a 5-second-timeout lookup). It runs on the SDK's own background poll
   thread — it cannot freeze your UI or cause an ANR — but a slow network
   can delay that specific poll tick's other results by up to 5 seconds
   internally. That's invisible to your users, not a performance problem.
5. **Two flags change real app behavior, not just detection:**
   - `clipboardProtection` with auto-clear wipes the clipboard the instant
     *any* copy happens while your app is foregrounded — if your app has
     its own copy-paste flow (an account number, a pasted OTP), this will
     interfere with it. Test this specifically before enabling it.
   - `screenshotProtection` blocks screenshots/screen recording via
     `FLAG_SECURE` on whichever screen is active — genuinely useful for a
     transfer/balance screen, genuinely breaks a "share a screenshot"
     feature if you have one anywhere.

---

## Pre-production checklist

- [ ] Credential JSON is bundled as a Flutter asset and loads successfully
      on a fresh install (test `configureAndPersist` actually runs once,
      `restore()` on every launch after)
- [ ] JitPack repository line is in your **release** build config too, not
      just debug (it's the same `android/build.gradle.kts` either way, so
      this is usually automatic — just confirm a `flutter build apk
      --release` succeeds)
- [ ] Screenshot block tested on real devices from at least 2–3 different
      OEMs (Samsung, Xiaomi/Oppo/Vivo, OnePlus) — OEM compositor
      differences are real and device-specific
- [ ] Decided your policy response for each enabled detector (root → force
      logout? Frida → block transactions? log only?) — the SDK detects,
      it does not decide your bank's policy
- [ ] Confirmed events actually appear on the dashboard's Live Threats /
      Devices pages from a real test device, not just that the build
      compiles
- [ ] Reviewed the full 26-detector matrix on your dashboard's `/guide`
      page and made a deliberate choice for every flag you left `false`
