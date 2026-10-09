group = "com.shieldsdk.rasp"
version = "1.1.0-local"

val raspEngineVersion = providers.gradleProperty("raspEngineVersion").orElse("1.1.0-local").get()

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

repositories {
    google()
    mavenCentral()
    mavenLocal()
    // Published home of android_core (see the dependencies block below) —
    // https://github.com/Vedant0Nisar/RaShield-SDK. Declared here so THIS
    // module's own build (its unit/instrumented tests, standalone
    // compile-verification, etc.) resolves it. This does NOT, by itself,
    // cover a consuming app's build: Gradle resolves a project
    // dependency's transitive external artifacts using the CONSUMING
    // project's own repositories, not the library's — verified directly
    // (a consumer missing this repo gets a real "could not find" 404,
    // never a silent success). Every consuming app must add this same
    // `maven { url = uri("https://jitpack.io") }` line to its OWN root
    // build.gradle.kts (or the dependencyResolutionManagement block in
    // settings.gradle.kts) — see LEAN_SECURITY_INTEGRATION_GUIDE.md.
}

android {
    // AGP requires a unique `namespace` (R/BuildConfig package) per module
    // in the whole app graph — distinct from android_core's "com.shieldsdk.rasp"
    // even though every actual Kotlin file in this module still declares
    // `package com.shieldsdk.rasp` (namespace only governs generated
    // R.java/BuildConfig, not where your own classes live — no source file
    // changes needed for this). pubspec.yaml's `pluginClass:
    // RaspShieldPlugin` resolves via the real Kotlin package, unaffected by
    // this value.
    namespace = "com.shieldsdk.rasp.plugin"

    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    // No explicit sourceSets block: `src/main/kotlin`, `src/test/kotlin`
    // and `src/androidTest/kotlin` are already recognized by convention
    // once the Kotlin Android plugin is applied (same as rasp_app's own
    // :app module, which declares no sourceSets block either). An earlier
    // version of this file configured them explicitly via the now-deprecated
    // `java.srcDirs(...)` vararg API, which newer Kotlin/AGP toolchains
    // (as used by the packaged customer example/) treat as a hard script
    // compilation error, not just a warning — removed rather than migrated,
    // since it was redundant with the convention-based default all along.

    defaultConfig {
        minSdk = flutter.minSdkVersion
        // Play Integrity's response models are deserialized reflectively by
        // Google's own client library — same rule the demo app previously
        // carried in its own proguard-rules.pro, moved here so it travels
        // with the code that now owns it (see RaspPlayIntegrityBridge.kt).
        consumerProguardFiles("consumer-rules.pro")
        // Required for `connectedAndroidTest`/`connectedDebugAndroidTest` to
        // discover and run the instrumentation tests under
        // src/androidTest/kotlin/ at all — without this, Gradle compiles and
        // packages them but "Starting 0 tests" at run time.
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        buildConfig = true
    }

    testOptions {
        unitTests.isReturnDefaultValues = false
    }
}

kotlin {
    // Modern compilerOptions DSL, not the deprecated `android.kotlinOptions`
    // — stable across the Kotlin Gradle Plugin versions this module is
    // actually built with (2.2.20 via rasp_app, 2.3.20 via the packaged
    // customer example/).
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // android_core — the single source of truth for ScreenshotGuard,
    // RaspUsbAnalysis, RaspClipboardGuard, AdbGuard and every other
    // detector class. `api`, not `implementation`: this plugin module's
    // own classes (RaspSecurityChannelHandler etc.) reference android_core's
    // types directly, and a consuming Flutter app's build must see them
    // too.
    //
    // Resolved as a real published artifact via JitPack
    // (com.github.Vedant0Nisar:RaShield-SDK — source lives at
    // rashield-sdk-publish/, the only copy now) rather than
    // `project(":android_core")` — a
    // source-folder reference that required every consuming app to clone
    // this SDK's source and manually wire it into their own
    // settings.gradle.kts as a sibling Gradle module. That was never how
    // any other RASP vendor's SDK integrates, and it's not how this one
    // does anymore: a consuming app now needs nothing beyond this
    // dependency, exactly like any other third-party Android library.
    api("com.shieldsdk.rasp:android-core:$raspEngineVersion")

    // The only external native dependency the moved detectors need — see
    // RaspPlayIntegrityBridge.kt.
    implementation("com.google.android.play:integrity:1.4.0")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test:rules:1.5.0")
}
