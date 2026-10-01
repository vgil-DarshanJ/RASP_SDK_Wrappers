package com.shieldsdk.rasp.nativeshield

import android.app.Activity
import android.os.Bundle
import com.shieldsdk.rasp.RaspCheckStatus
import com.shieldsdk.rasp.RaspScreenGuard
import com.shieldsdk.rasp.RaspShieldCore

/**
 * A minimal reference `Activity` proving the native path works completely
 * independent of Flutter, and the canonical copy-paste starting point in
 * `docs/ANDROID_NATIVE_SDK_REFERENCE.md`.
 *
 * Compiles into this module like any other class here, but this module
 * declares no manifest `<application>`/launcher entry for it — it is
 * inert (adds one small class, nothing more) in a consuming app unless
 * that app explicitly launches it or copies its contents into its own
 * Activity. A real app would replace `logResult` with its own policy:
 * step-up auth, blocking a transaction, routing to a lock screen, shipping
 * the result to its own audit backend, etc. — see that doc's "Exception
 * handling & production checklist" section.
 */
class SampleSecureActivity : Activity() {

    private val screenGuard = RaspScreenGuard()

    override fun onCreate(savedInstanceState: Bundle?) {
        // Apply BEFORE super.onCreate() — see RaspScreenGuard's class doc
        // for why this ordering matters on some OEM compositors.
        screenGuard.attach(this)
        super.onCreate(savedInstanceState)

        // Explicit configuration — no reflection into any host BuildConfig,
        // no backend call. Replace with your own build's real fingerprint
        // and backend host/pin.
        RaspShieldCore.configureExpectedSigningCertificate(null)
        RaspShieldCore.configureCertificatePin(host = null, pinnedSpkiPin = null)

        // Release-build CI check — call this in your pipeline, not just
        // here. Shown here so the shape is visible in one place.
        RaspShieldCore.selfTest(this).let { report ->
            if (!report.criticalReflectionIntact) {
                android.util.Log.e(
                    "RaspShieldSample",
                    "Hook-detection reflection did not resolve — check R8 keep rules"
                )
            }
        }

        // Full scan, off the main thread via the async API — no manual
        // threading, no coroutines dependency.
        RaspShieldCore.scanAllAsync(this) { results ->
            results.forEach { logResult(it) }
        }
    }

    override fun onDestroy() {
        screenGuard.detach()
        super.onDestroy()
    }

    private fun logResult(result: com.shieldsdk.rasp.RaspCheckResult) {
        when (result.status) {
            RaspCheckStatus.DETECTED -> android.util.Log.w(
                "RaspShieldSample", "THREAT: ${result.detectorId} evidence=${result.evidence}"
            )
            RaspCheckStatus.ERROR -> android.util.Log.e(
                "RaspShieldSample", "ERROR: ${result.detectorId} reason=${result.reason}"
            )
            else -> android.util.Log.d(
                "RaspShieldSample", "${result.status}: ${result.detectorId}"
            )
        }
    }
}
