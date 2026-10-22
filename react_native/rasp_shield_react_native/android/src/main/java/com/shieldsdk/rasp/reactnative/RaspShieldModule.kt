package com.shieldsdk.rasp.reactnative

import android.app.Activity
import android.os.Build
import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.LifecycleEventListener
import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.UiThreadUtil
import com.facebook.react.bridge.WritableMap
import com.shieldsdk.rasp.RaspCheckResult
import com.shieldsdk.rasp.RaspClipboardGuard
import com.shieldsdk.rasp.RaspEventShipper
import com.shieldsdk.rasp.RaspLeanSession
import com.shieldsdk.rasp.RaspScreenGuard
import com.shieldsdk.rasp.RaspSessionEvent
import com.shieldsdk.rasp.RaspShieldCore
import com.shieldsdk.rasp.RaspShieldLogger
import com.shieldsdk.rasp.ScreenshotGuard
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.RejectedExecutionException

/**
 * React Native binding of the shared android-core engine. It holds no
 * detection logic: it owns ONE [RaspLeanSession], forwards its state to
 * JavaScript, and adapts the engine's calls to promises. The Activity
 * lifecycle work that the Flutter plugin does in `RaspShieldPlugin`
 * (screen guard attach/detach) is done here through [LifecycleEventListener].
 *
 * Threading: anything that touches a window (FLAG_SECURE, session start)
 * runs on the UI thread; anything blocking (scans, signing) runs on [worker].
 */
class RaspShieldModule(private val reactContext: ReactApplicationContext) :
    NativeRaspShieldSpec(reactContext), LifecycleEventListener {

    private val appContext get() = reactContext.applicationContext
    private val screenGuard = RaspScreenGuard()
    private val worker: ExecutorService =
        Executors.newSingleThreadExecutor { Thread(it, "RaspShieldRN").apply { isDaemon = true } }

    @Volatile private var session: RaspLeanSession? = null
    private var attachedActivity: Activity? = null

    init {
        reactContext.addLifecycleEventListener(this)
        // Detector faults reach JS as RaspShield.error instead of vanishing.
        RaspShieldCore.logger = object : RaspShieldLogger {
            override fun onDetectorError(detectorId: String, throwable: Throwable) {
                emitError(detectorId, throwable.message ?: throwable.javaClass.simpleName)
            }
        }
    }

    override fun getName(): String = NAME

    // ── Lifecycle ────────────────────────────────────────────────────────

    override fun onHostResume() = ensureGuardAttached()
    override fun onHostPause() = Unit
    override fun onHostDestroy() {
        screenGuard.detach()
        attachedActivity = null
    }

    /** Attaches the guard once per Activity instance: attach() re-applies FLAG_SECURE. */
    private fun ensureGuardAttached() {
        val activity = reactContext.currentActivity ?: return
        if (attachedActivity === activity) return
        attachedActivity = activity
        screenGuard.attach(activity)
    }

    override fun invalidate() {
        reactContext.removeLifecycleEventListener(this)
        session?.dispose()
        session = null
        screenGuard.detach()
        worker.shutdownNow()
        super.invalidate()
    }

    // ── Lean session ─────────────────────────────────────────────────────

    override fun startSession(config: ReadableMap, promise: Promise) {
        UiThreadUtil.runOnUiThread {
            try {
                val parsed = RaspShieldSerialization.config(config)
                session?.dispose()
                ensureGuardAttached()
                val next = RaspLeanSession.start(appContext, parsed, { reactContext.currentActivity }, screenGuard)
                next.setListener { state -> emit(STATE_EVENT, RaspShieldSerialization.state(state)) }
                session = next
                emit(STATE_EVENT, RaspShieldSerialization.state(next.current))
                promise.resolve(null)
            } catch (t: Throwable) {
                promise.reject("E_RASP_START", t.message ?: "Could not start the RASP session", t)
            }
        }
    }

    override fun stopSession(promise: Promise) {
        UiThreadUtil.runOnUiThread {
            session?.dispose()
            session = null
            promise.resolve(null)
        }
    }

    override fun refreshNow() {
        session?.refreshNow()
    }

    override fun refreshRemoteConfigNow() {
        session?.refreshRemoteConfigNow()
    }

    override fun getState(promise: Promise) {
        val current = session?.current
        promise.resolve(current?.let { RaspShieldSerialization.state(it) })
    }

    override fun setLocation(location: ReadableMap?) {
        session?.currentLocation = RaspShieldSerialization.location(location)
    }

    override fun setServerTime(serverTimeMillis: Double) {
        session?.setServerTime(serverTimeMillis.toLong())
    }

    // ── Credential ───────────────────────────────────────────────────────

    override fun configureCredential(credentialJson: String, persist: Boolean, promise: Promise) {
        onWorker(promise, "E_RASP_CREDENTIAL") {
            if (persist) RaspEventShipper.configureAndPersist(appContext, credentialJson)
            else RaspEventShipper.configure(credentialJson)
        }
    }

    override fun restoreCredential(promise: Promise) =
        onWorker(promise, "E_RASP_CREDENTIAL") { RaspEventShipper.restore(appContext) }

    override fun clearCredential(promise: Promise) =
        onWorker(promise, "E_RASP_CREDENTIAL") { RaspEventShipper.clearPersisted(appContext) }

    override fun isCredentialConfigured(promise: Promise) = promise.resolve(RaspEventShipper.isConfigured())

    // ── One-shot scans ───────────────────────────────────────────────────

    override fun runCheck(detectorId: String, promise: Promise) {
        onWorker(promise, "E_RASP_SCAN") {
            val found = RaspShieldCore.scanAllBlocking(appContext).firstOrNull { it.detectorId == detectorId }
                ?: RaspCheckResult.unavailable(
                    detectorId,
                    "Not part of the one-shot scan; enable it in a session (startSession) to read it",
                )
            RaspShieldSerialization.result(found)
        }
    }

    override fun scanAll(promise: Promise) =
        onWorker(promise, "E_RASP_SCAN") { RaspShieldSerialization.results(RaspShieldCore.scanAllBlocking(appContext)) }

    override fun selfTest(promise: Promise) =
        onWorker(promise, "E_RASP_SCAN") { RaspShieldSerialization.selfTest(RaspShieldCore.selfTest(appContext)) }

    // ── Fraud / risk ─────────────────────────────────────────────────────

    override fun setHighRiskTransactionMode(enabled: Boolean) {
        session?.setHighRiskTransactionMode(enabled)
    }

    override fun reportSession(accountId: String, sessionId: String, event: String, promise: Promise) {
        onWorker(promise, "E_RASP_FRAUD") {
            val parsed = RaspSessionEvent.fromWire(event) ?: throw IllegalArgumentException("Unknown session event: $event")
            RaspShieldSerialization.sessionReport(requireSession().reportSession(accountId, sessionId, parsed))
        }
    }

    override fun reportTransaction(
        amount: String, currency: String, beneficiaryId: String, channel: String, promise: Promise,
    ) = onWorker(promise, "E_RASP_FRAUD") {
        RaspShieldSerialization.transactionReport(requireSession().reportTransaction(amount, currency, beneficiaryId, channel))
    }

    override fun signTransaction(amount: String, currency: String, beneficiaryId: String, promise: Promise) =
        onWorker(promise, "E_RASP_FRAUD") {
            RaspShieldSerialization.signedTransaction(requireSession().signTransaction(amount, currency, beneficiaryId))
        }

    private fun requireSession(): RaspLeanSession =
        session ?: throw IllegalStateException("No RASP session is running; call startSession first")

    // ── Direct controls / info ───────────────────────────────────────────

    override fun setScreenshotProtection(enabled: Boolean, promise: Promise) {
        UiThreadUtil.runOnUiThread {
            try {
                val activity = reactContext.currentActivity
                if (enabled) ScreenshotGuard.enable(activity) else ScreenshotGuard.disable(activity)
                promise.resolve(ScreenshotGuard.isActive(activity))
            } catch (t: Throwable) {
                promise.reject("E_RASP_SCREEN", t.message, t)
            }
        }
    }

    override fun clearClipboard(promise: Promise) =
        onWorker(promise, "E_RASP_CLIPBOARD") { RaspClipboardGuard(appContext).clear() }

    override fun getSdkInfo(promise: Promise) {
        promise.resolve(Arguments.createMap().apply {
            putString("sdkVersion", BuildConfig.RASP_RN_VERSION)
            putString("engineVersion", BuildConfig.RASP_ENGINE_VERSION)
            putString("platform", "android")
            putBoolean("nativeAvailable", true)
            putString("osVersion", Build.VERSION.RELEASE)
            putInt("apiLevel", Build.VERSION.SDK_INT)
        })
    }

    // ── Required by NativeEventEmitter ───────────────────────────────────

    override fun addListener(eventName: String) = Unit
    override fun removeListeners(count: Double) = Unit

    // ── Helpers ──────────────────────────────────────────────────────────

    private fun <T> onWorker(promise: Promise, code: String, block: () -> T) {
        try {
            worker.execute {
                try {

                    promise.resolve(block().takeUnless { it is Unit })
                } catch (t: Throwable) {
                    promise.reject(code, t.message ?: t.javaClass.simpleName, t)
                }
            }
        } catch (e: RejectedExecutionException) {
            promise.reject(code, "The RASP module was shut down", e)
        }
    }

    private fun emit(event: String, payload: WritableMap) {
        if (reactContext.hasActiveReactInstance()) reactContext.emitDeviceEvent(event, payload)
    }

    private fun emitError(source: String, message: String) {
        emit(ERROR_EVENT, Arguments.createMap().apply {
            putString("source", source)
            putString("message", message)
        })
    }

    companion object {
        const val NAME = "RaspShield"
        const val STATE_EVENT = "RaspShield.stateChanged"
        const val ERROR_EVENT = "RaspShield.error"
    }
}
