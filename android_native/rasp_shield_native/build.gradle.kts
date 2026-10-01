// Thin, zero-Flutter-dependency facade over android_core — the single
// source of truth for every detection class (see
// ../../android_core/build.gradle.kts). This module holds NO duplicated
// detector logic of its own; it depends on android_core exactly like the
// Flutter plugin (flutter/rasp_shield_sdk) does, so a bug fix lands once
// and reaches both consumption paths identically. See ../README.md for how
// to wire this into a pure Kotlin/Java Android app.

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

val raspEngineVersion = providers.gradleProperty("raspEngineVersion").orElse("1.1.0-local").get()

repositories {
    google()
    mavenCentral()
    mavenLocal()
    // Published home of android_core — see the dependencies block below.
    // Covers THIS module's own build only — see that block's doc for why
    // a consuming app must add this same line to its own root build file.
}

android {
    namespace = "com.shieldsdk.rasp.nativeshield"
    compileSdk = 35

    defaultConfig {
        minSdk = 23
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // The one and only place ScreenshotGuard/RaspUsbAnalysis/
    // RaspClipboardGuard/AdbGuard and every other detector is implemented.
    // `api` so a consuming native app can call com.shieldsdk.rasp.* classes
    // directly without an extra dependency declaration of its own.
    //
    // Resolved via JitPack (com.github.Vedant0Nisar:RaShield-SDK) rather
    // than `project(":android_core")` — see the Flutter plugin's own
    // build.gradle.kts for the full reasoning; identical here. A consuming
    // native Android app needs this one dependency line PLUS the JitPack
    // repository added to its own root build file (see this file's
    // repositories block) — no android_core source to download or wire
    // in as a sibling Gradle module anymore, which is the actual
    // improvement over the old project(":android_core") approach.
    api("com.shieldsdk.rasp:android-core:$raspEngineVersion")
}
