package com.shieldsdk.rasp

/**
 * Release Obfuscation + Self-Integrity Verification milestone — the native
 * (Kotlin/R8) counterpart to `lib/sdk/trust/obfuscation_state.dart`'s Dart
 * marker.
 *
 * Not referenced by any `-keep` rule in `proguard-rules.pro`, not a
 * component declared in `AndroidManifest.xml`, and not reached via
 * reflection anywhere in this codebase — exactly the shape of class R8
 * renames by default when minification is enabled
 * (`isMinifyEnabled = true` in `build.gradle.kts`). Its only job is to let
 * [MainActivity.obfuscationMarker] ask the runtime what this class is
 * actually called right now.
 */
internal class RaspObfuscationMarker
