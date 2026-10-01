package com.shieldsdk.rasp

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.WindowManager
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.NetworkInterface
import java.util.Collections
import java.security.KeyStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.interfaces.RSAPrivateKey
import android.util.Base64

/**
 * The real native RASP Shield security engine.
 *
 * Extracted verbatim (P0-1 native-plugin extraction) from what used to be
 * `com.example.rasp_app.MainActivity`'s `configureFlutterEngine` handler —
 * the demo app is no longer the owner of this code, this plugin is. Every
 * branch, every helper, every detector below is unchanged logic; only the
 * container (a `FlutterPlugin`-registered class instead of a
 * `FlutterActivity` subclass) and the source of `Context`/`Activity` moved.
 *
 * Registered on channel `com.shieldsdk.security/security` by
 * [RaspShieldPlugin] — the same channel name `RaspNativeChannel` (Dart side)
 * has always called, so no Dart change was needed for this migration.
 *
 * [applicationContext] backs every check that only needs a `Context`
 * (packageManager, contentResolver, keystore, connectivity, telephony —
 * the large majority). [activityProvider] backs the handful that need the
 * live `Activity`/`Window` (screenshot blocking, overlay/touch evidence) —
 * it returns null when no activity is currently attached, and those
 * branches report the same honest ERROR/UNAVAILABLE the original code
 * reported on any other failure, never a false SECURE.
 */
internal class RaspSecurityChannelHandler(
    private val applicationContext: Context,
    private val activityProvider: () -> Activity?,
) : MethodChannel.MethodCallHandler, EventChannel.StreamHandler {

    companion object {
        private const val KEY_ALIAS = "RASP_DEVICE_BINDING_KEY"

        /**
         * The per-device licence binding key. See the original doc on this
         * constant in git history (`MainActivity.kt`, pre-P0-1) for why this
         * is a second alias rather than a reuse of [KEY_ALIAS] — unchanged
         * reasoning, just relocated.
         */
        private const val IDENTITY_KEY_ALIAS = "RASP_DEVICE_IDENTITY_KEY"

        /**
         * Suppression window (see [onScreenshotEventDetected]) for
         * platform-generated `ScreenCaptureCallback` noise around Activity
         * start/registration — chiefly Android's task-snapshot capture for
         * Recents. 2s comfortably covers a `mainExecutor`-queued delayed
         * fire on real hardware without meaningfully widening the gap in
         * which a genuine startup-time screenshot goes undetected (a user
         * cannot physically trigger a hardware-button screenshot in under
         * ~2s of the app becoming visible).
         */
        private const val SCREEN_CAPTURE_STARTUP_SUPPRESSION_MILLIS = 2000L
    }

    private var isScreenshotBlocked = false
    private val leanScreenGuard = RaspScreenGuard()
    private val mainHandler = Handler(Looper.getMainLooper())
    @Volatile private var leanStateSink: EventChannel.EventSink? = null
    private var leanSession: RaspLeanSession? = null

    fun onActivityAttached(activity: Activity) = leanScreenGuard.attach(activity)
    fun onActivityDetached() = leanScreenGuard.detach()

    override fun onListen(arguments: Any?, events: EventChannel.EventSink) {
        leanStateSink = events
    }

    override fun onCancel(arguments: Any?) {
        leanStateSink = null
    }

    /// Fingerprint this build *should* carry, supplied by the host app at
    /// startup via `setExpectedSigningCert`. Null means on-device
    /// repackaging comparison is skipped and the server-side pinning check
    /// in /activate is the only enforcement point.
    private var expectedSigningCert: String? = null

    /// Overlay corroboration signal. `null` = no touch event observed yet
    /// (UNKNOWN, not a clean result). Set by [onTouchObscuredChanged], which
    /// [RaspShieldPlugin] calls from its Window.Callback wrapper — the
    /// plugin-side replacement for `Activity.dispatchTouchEvent`, since this
    /// class is not itself an Activity and cannot override that method.
    @Volatile
    private var lastTouchObscured: Boolean? = null

    fun onTouchObscuredChanged(obscured: Boolean) {
        lastTouchObscured = obscured
    }

    // The evidence-reading half of these detectors takes a Context instead
    // of an Activity so instrumentation tests can call the real production
    // implementation directly — no Activity, no Flutter engine, nothing
    // mocked. Unchanged from the pre-extraction design.
    private val probes by lazy { RaspDeviceProbes(applicationContext) }
    private val hookProbes by lazy { RaspHookProbes(applicationContext) }
    private val integrityProbes by lazy { RaspDeviceIntegrityProbes(applicationContext) }
    private val playIntegrityBridge by lazy { RaspPlayIntegrityBridge(applicationContext) }
    private val usbAnalysis by lazy { RaspUsbAnalysis(applicationContext) }
    private val clipboardGuard by lazy { RaspClipboardGuard(applicationContext) }

    /**
     * Called by [RaspShieldPlugin.onDetachedFromEngine] so a clipboard
     * listener registered by this handler never outlives the Flutter engine
     * that owns it — the same reason [RaspShieldPlugin] detaches its window
     * callback on Activity detach.
     */
    fun shutdown() {
        leanSession?.dispose()
        leanSession = null
        leanScreenGuard.detach()
        clipboardGuard.disable()
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "configureLeanEventShipping" -> {
                result.success(RaspEventShipper.configure(call.arguments as? String ?: ""))
            }
            "clearLeanEventShipping" -> {
                RaspEventShipper.clearPersisted(applicationContext)
                result.success(true)
            }
            "startLeanSession" -> {
                val config = leanConfig(call.arguments as? Map<*, *> ?: emptyMap<Any, Any>())
                leanSession?.dispose()
                leanSession = RaspLeanSession.start(
                    applicationContext, config, activityProvider, leanScreenGuard,
                ).also { session ->
                    session.setListener { state -> emitLeanState(state) }
                }
                RaspEventShipper.setUseEvidenceEnvelope(config.useEvidenceEnvelope)
                result.success(true)
            }
            "refreshLeanSession" -> {
                leanSession?.refreshNow()
                result.success(leanSession != null)
            }
            "disposeLeanSession" -> {
                leanSession?.dispose()
                leanSession = null
                result.success(true)
            }
            "setLeanSessionLocation" -> {
                val args = call.arguments as? Map<*, *> ?: emptyMap<Any, Any>()
                val latitude = (args["latitude"] as? Number)?.toDouble()
                val longitude = (args["longitude"] as? Number)?.toDouble()
                if (latitude == null || longitude == null) {
                    result.success(false)
                } else {
                    leanSession?.currentLocation = RaspLocationSnapshot(
                        latitude = latitude,
                        longitude = longitude,
                        accuracyMeters = (args["accuracyMeters"] as? Number)?.toDouble(),
                        capturedAtMillis = (args["capturedAtMillis"] as? Number)?.toLong()
                            ?: System.currentTimeMillis(),
                    )
                    result.success(leanSession != null)
                }
            }
            "enableScreenshotRestriction" -> {
                if (isSecureWindowActive() == false) {
                    enableScreenshotBlocking()
                }
                result.success(isSecureWindowActive())
            }

            "disableScreenshotRestriction" -> {
                disableScreenshotBlocking()
                result.success(isSecureWindowActive())
            }

            "isScreenshotBlockingActive" -> {
                result.success(isSecureWindowActive())
            }

            "getScreenCaptureCapabilities" -> {
                result.success(screenCaptureCapabilities())
            }

            "getScreenshotEventEvidence" -> {
                result.success(drainScreenshotEventEvidence())
            }

            // Read-only counterpart — see the clipboard guard's own
            // peek/drain split for why this exists: RaspLeanSession's poll
            // tick uses the destructive drain above; anything else (a host
            // app's own live UI) should use this one instead, so it never
            // resets a count the lean session hasn't seen yet.
            "peekScreenshotEventEvidence" -> {
                result.success(peekScreenshotEventEvidence())
            }

            "getExternalDisplayState" -> {
                result.success(externalDisplayState())
            }

            "isVpnActive" -> {
                result.success(isVpnActive())
            }

            "isMitmDetected" -> {
                result.success(isMitmDetected())
            }

            "isOverlayAttackDetected" -> {
                result.success(isOverlayAttackDetected())
            }

            "getOverlayEvidence" -> {
                result.success(overlayEvidence())
            }

            "isAccessibilityAbused" -> {
                result.success(isAccessibilityAbused())
            }

            "checkReverseEngineeringTools" -> {
                result.success(hasReverseEngineeringTools())
            }

            "getRiskyAppEvidence" -> {
                result.success(riskyAppEvidence())
            }

            // Malware & Risky-App Intelligence milestone — additive, same
            // seven `<queries>`-declared packages as getRiskyAppEvidence.
            "getAppIntelligence" -> {
                result.success(appIntelligence())
            }

            "detectFrida" -> {
                result.success(isFridaDetected())
            }

            "getFridaSignals" -> {
                result.success(fridaSignals())
            }

            "isDebuggerAttached" -> {
                result.success(isDebuggerAttached())
            }

            "getDebuggerSignals" -> {
                result.success(debuggerSignals())
            }

            "isHookingDetected" -> {
                result.success(hookProbes.isHookingDetected())
            }

            "getHookSignals" -> {
                result.success(hookProbes.hookSignals())
            }

            "getHookDetectionResult" -> {
                result.success(hookProbes.hookDetectionResult())
            }

            "isDeviceRooted" -> {
                result.success(isDeviceRooted())
            }

            "getRootSignals" -> {
                result.success(rootSignals())
            }

            // Anti-Bypass Resilience milestone — additive. `isDeviceRooted`/
            // `getRootSignals` above are UNCHANGED; this exists so a caller
            // that needs to tell "checked, clean" apart from "could not
            // check" can, without every existing caller having to adopt a
            // new response shape. See `RaspRootAnalysis.RootVerdict`'s doc.
            "getRootAssessment" -> {
                val (signals, verdict) = integrityProbes.rootAssessment()
                result.success(mapOf(
                    "signals" to signals,
                    "verdict" to verdict.name,
                ))
            }

            "isEmulator" -> {
                result.success(isEmulator())
            }

            "getEmulatorSignals" -> {
                result.success(emulatorSignals())
            }

            "isUntrustedInstallSource" -> {
                result.success(isUntrustedInstallSource())
            }

            "isDeveloperModeEnabled" -> {
                result.success(isDeveloperModeEnabled())
            }

            "isAdbEnabled" -> {
                result.success(isAdbEnabled())
            }

            "isDeviceLockMissing" -> {
                result.success(isDeviceLockMissing())
            }

            "isSecureHardwareUnavailable" -> {
                result.success(isSecureHardwareUnavailable())
            }

            "verifySignature" -> {
                result.success(verifySignature())
            }

            "getSigningCertSha256" -> {
                result.success(signingCertSha256())
            }

            "getSigningIdentity" -> {
                result.success(signingIdentity())
            }

            "getObfuscationMarker" -> {
                result.success(obfuscationMarker())
            }

            "setExpectedSigningCert" -> {
                expectedSigningCert = call.arguments as? String
                result.success(true)
            }

            "isAppTampered" -> {
                result.success(isAppTampered())
            }

            "isCloneDetected" -> {
                result.success(isCloneDetected())
            }

            "getCloneEvidence" -> {
                result.success(cloneEvidence())
            }

            "verifyDeviceBinding" -> {
                result.success(verifyDeviceBinding())
            }

            "getDeviceKeyInfo" -> {
                result.success(deviceKeyResponse(create = false))
            }

            "ensureDeviceKey" -> {
                result.success(deviceKeyResponse(create = true))
            }

            "signWithDeviceKey" -> {
                val message = (call.arguments as? Map<*, *>)?.get("message") as? String
                if (message.isNullOrEmpty()) {
                    result.error(
                        "INVALID_ARGUMENT", "signWithDeviceKey requires a message", null
                    )
                } else {
                    result.success(signWithDeviceKey(message))
                }
            }

            "clearDeviceKey" -> {
                result.success(clearDeviceKey())
            }

            "playIntegrityIsAvailable" -> {
                result.success(playIntegrityBridge.isAvailable())
            }

            "requestPlayIntegrityToken" -> {
                val nonce = (call.arguments as? Map<*, *>)?.get("nonce") as? String
                if (nonce.isNullOrEmpty()) {
                    result.error(
                        "INVALID_ARGUMENT", "requestPlayIntegrityToken requires a nonce", null
                    )
                } else {
                    playIntegrityBridge.requestToken(nonce) { outcome ->
                        outcome.fold(
                            onSuccess = { token -> result.success(token) },
                            onFailure = { error ->
                                val code = (error as? IntegrityRequestException)?.code
                                    ?: "INTEGRITY_UNKNOWN_ERROR"
                                result.error(code, error.message, null)
                            },
                        )
                    }
                }
            }

            "getDeviceFingerprint" -> {
                result.success(getDeviceFingerprint())
            }

            "getDeviceInfo" -> {
                result.success(getDeviceInfo())
            }

            "getNetworkOperator" -> {
                result.success(getNetworkOperator())
            }

            // ── USB physical connection (new — see RaspUsbAnalysis) ────────
            "isUsbConnected" -> {
                result.success(usbAnalysis.isUsbConnected())
            }

            "getUsbConnectionEvidence" -> {
                result.success(usbAnalysis.usbConnectionEvidence())
            }

            // ── Clipboard protection (new — see RaspClipboardGuard) ────────
            "enableClipboardProtection" -> {
                val autoClear = (call.arguments as? Map<*, *>)
                    ?.get("autoClearOnCopy") as? Boolean ?: true
                result.success(clipboardGuard.enable(autoClearOnCopy = autoClear))
            }

            "disableClipboardProtection" -> {
                clipboardGuard.disable()
                result.success(true)
            }

            "isClipboardProtectionActive" -> {
                result.success(clipboardGuard.isActive())
            }

            "clearClipboard" -> {
                result.success(clipboardGuard.clear())
            }

            "getClipboardEvidence" -> {
                result.success(clipboardGuard.drainEvidence())
            }

            // Read-only counterpart to getClipboardEvidence — see
            // RaspClipboardGuard.peekEvidence's doc. This is the one to call
            // from a host app's own live UI display; getClipboardEvidence
            // above is what RaspLeanSession's own poll tick uses internally.
            "peekClipboardEvidence" -> {
                result.success(clipboardGuard.peekEvidence())
            }

            "applyBackgroundBlur" -> {
                if (isSecureWindowActive() == false) {
                    enableScreenshotBlocking()
                }
                result.success(isSecureWindowActive())
            }

            "removeBackgroundBlur" -> {
                result.success(isSecureWindowActive())
            }

            // A device identifier that survives this app's own uninstall/
            // reinstall — unlike a value generated and persisted purely in
            // Dart-side storage (SharedPreferences/EncryptedSharedPreferences
            // are both wiped on uninstall, causing one physical device to
            // re-register as a "new" device every reinstall). ANDROID_ID is
            // scoped per device + app signing key + user profile since
            // Android 8 (O): stable across reinstalls of this exact signed
            // app, changes only on factory reset or a different signing
            // key — no permission required, nothing hardware-identifying
            // across other apps. Can legitimately return null/empty on a
            // small minority of devices; the Dart side falls back to its
            // own random id in that case rather than crashing.
            "getAndroidId" -> {
                val androidId = try {
                    Settings.Secure.getString(
                        applicationContext.contentResolver,
                        Settings.Secure.ANDROID_ID,
                    )
                } catch (e: Exception) {
                    null
                }
                result.success(androidId)
            }

            else -> result.notImplemented()
        }
    }

    // ── Screen capture (needs the live Activity/Window) ────────────────────

    /**
     * The single source of truth for "is screen capture actually blocked?".
     * Reads the live window attributes rather than any bookkeeping boolean.
     * Returns `null` (never a guessed boolean) when no Activity is currently
     * attached or the attribute cannot be read — the Dart side maps that to
     * UNAVAILABLE, never to a clean result.
     */
    private fun isSecureWindowActive(): Boolean? {
        val window = activityProvider()?.window ?: return null
        return try {
            (window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
        } catch (e: Exception) {
            null
        }
    }

    private fun enableScreenshotBlocking() {
        val window = activityProvider()?.window ?: return
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        isScreenshotBlocked = true
    }

    private fun disableScreenshotBlocking() {
        val window = activityProvider()?.window ?: return
        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
        isScreenshotBlocked = false
    }

    // ── Screen-capture event detection (real Android APIs, honestly scoped) ─
    //
    // Android provides exactly one reliable, first-party signal that an
    // arbitrary app (this one included) can use to learn a screenshot was
    // just taken: `Activity.registerScreenCaptureCallback`, added in API 34
    // (Android 14). Below that level there is no supported callback — the
    // old approach (a ContentObserver on MediaStore.Images, guessing from a
    // new file landing in the Pictures/Screenshots folder) is a heuristic
    // that requires storage permissions this SDK does not request and is
    // trivially wrong (any new image file matching the heuristic counts),
    // so it is deliberately NOT implemented here. Below API 34 this is
    // UNAVAILABLE, honestly, not approximated.
    //
    // There is, separately, NO Android API — at any level — for a passive
    // app to learn that another app is actively **recording** or **casting**
    // its screen via MediaProjection. MediaProjection is initiated and held
    // by the capturing app; the target app is never notified. FLAG_SECURE is
    // this platform's actual defense here (it blanks the surface in both a
    // screenshot AND a screen recording/cast) — there is no complementary
    // *detection* capability to pair with it, and this class does not
    // pretend one exists.

    /** Incremented by [RaspShieldPlugin]'s `ScreenCaptureCallback` on every
     * fired callback. Volatile: written from the callback's own thread,
     * read from whatever thread the Dart method channel dispatches on. */
    @Volatile
    private var screenshotEventCount = 0

    @Volatile
    private var lastScreenshotEventAtMillis: Long? = null

    /**
     * Timestamp of the most recent `registerScreenCaptureCallback` call.
     * A callback fire inside [SCREEN_CAPTURE_STARTUP_SUPPRESSION_MILLIS] of
     * this timestamp is treated as platform-generated noise, not a real user
     * screenshot — see [onScreenshotEventDetected] for why a one-shot flush
     * (the earlier fix) is not enough on its own.
     */
    @Volatile
    private var screenCaptureRegisteredAtMillis: Long = 0L

    /**
     * Called by [RaspShieldPlugin] when the real OS callback fires.
     *
     * A callback landing within [SCREEN_CAPTURE_STARTUP_SUPPRESSION_MILLIS]
     * of registration is dropped rather than counted. This is a *window*,
     * not the earlier one-shot "flush right after register" fix, because
     * `registerScreenCaptureCallback` dispatches through `target.
     * mainExecutor` — a posted `Handler` message, not a synchronous call —
     * so a spurious fire tied to registration can still arrive on the main
     * looper *after* the flush already ran, defeating a single reset. A
     * time window survives that delay. The leading real-world source of
     * this noise is Android's own task-snapshot capture for the Recents UI
     * (see https://source.android.com/docs/core/perf/task-snapshots),
     * which happens automatically around Activity start on every launch —
     * independent of anything this SDK does. [attachActivity]'s
     * `setRecentsScreenshotEnabled(false)` call (API 33+) is the other,
     * complementary half of this fix: it asks the platform to skip that
     * capture entirely, so this window is a safety net for OS versions or
     * OEM skins where that request is not honored, not the sole defense.
     */
    fun onScreenshotEventDetected() {
        val now = System.currentTimeMillis()
        if (now - screenCaptureRegisteredAtMillis < SCREEN_CAPTURE_STARTUP_SUPPRESSION_MILLIS) {
            return
        }
        screenshotEventCount += 1
        lastScreenshotEventAtMillis = now
    }

    /**
     * Called by [RaspShieldPlugin] immediately after
     * `registerScreenCaptureCallback` returns successfully. Discards
     * anything already counted at that exact moment (same as the old
     * flush) AND arms the [SCREEN_CAPTURE_STARTUP_SUPPRESSION_MILLIS]
     * suppression window in [onScreenshotEventDetected] going forward, so a
     * delayed/queued spurious fire arriving after this call still gets
     * caught. A genuine screenshot taken after the window elapses still
     * increments normally.
     */
    fun flushScreenshotEventCountOnRegister() {
        screenshotEventCount = 0
        lastScreenshotEventAtMillis = null
        screenCaptureRegisteredAtMillis = System.currentTimeMillis()
    }

    /**
     * Read-and-clear: the Dart-side detector polls this once per scan cycle
     * (same poll convention as [onTouchObscuredChanged]/[lastTouchObscured]).
     * Draining rather than only reading means two screenshots between scans
     * are not silently collapsed into "one event happened" — the count
     * reported is exactly how many fired since the last read, then resets to
     * zero so the next scan does not re-report the same capture.
     */
    private fun drainScreenshotEventEvidence(): Map<String, Any?> {
        val count = screenshotEventCount
        val lastAt = lastScreenshotEventAtMillis
        screenshotEventCount = 0
        return mapOf(
            "supported" to (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE),
            "detected" to (count > 0),
            "count" to count,
            "last_at_millis" to lastAt,
        )
    }

    /** Same shape as [drainScreenshotEventEvidence], read-only. */
    private fun peekScreenshotEventEvidence(): Map<String, Any?> {
        return mapOf(
            "supported" to (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE),
            "detected" to (screenshotEventCount > 0),
            "count" to screenshotEventCount,
            "last_at_millis" to lastScreenshotEventAtMillis,
        )
    }

    /**
     * What this build/OS combination can actually do — read by the Dart
     * detector once, so it can report UNAVAILABLE honestly on API < 34
     * instead of silently reporting zero events forever (which would look
     * identical to "ran, found nothing").
     */
    private fun screenCaptureCapabilities(): Map<String, Any?> {
        return mapOf(
            "screenshot_prevention_supported" to true, // FLAG_SECURE — every API level this SDK targets
            "screenshot_detection_supported" to
                (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE),
            "screenshot_detection_min_sdk_int" to Build.VERSION_CODES.UPSIDE_DOWN_CAKE,
            // No Android API exists, at any level, for a passive app to learn
            // it is being screen-recorded or cast by another app/service —
            // see the class doc above. Reported honestly as false, not
            // omitted (an absent key would look like "we forgot to check"
            // rather than "this genuinely cannot be done").
            "screen_recording_detection_supported" to false,
            "screen_share_detection_supported" to false,
            "external_display_detection_supported" to true,
        )
    }

    /**
     * Real `DisplayManager` query: is there currently a display other than
     * the device's own built-in one — the honest, checkable proxy for
     * "content may be mirrored/cast/presented elsewhere". This reports
     * PRESENCE of an external/wireless display, not proof that THIS app's
     * content is actually being shown there (Android does not expose that
     * distinction to an app that has not itself created a `Presentation`).
     */
    private fun externalDisplayState(): Map<String, Any?> {
        return try {
            val displayManager = applicationContext.getSystemService(Context.DISPLAY_SERVICE)
                as? android.hardware.display.DisplayManager
                ?: return mapOf("supported" to false)
            val displays = displayManager.displays
            val nonDefault = displays.filter { it.displayId != android.view.Display.DEFAULT_DISPLAY }
            mapOf(
                "supported" to true,
                "external_display_count" to nonDefault.size,
                "external_display_detected" to nonDefault.isNotEmpty(),
                "display_names" to nonDefault.map { it.name },
            )
        } catch (e: Exception) {
            mapOf("supported" to false)
        }
    }

    // ── Network / device posture ────────────────────────────────────────────

    private fun getNetworkOperator(): String? {
        return try {
            val tm = applicationContext.getSystemService(Context.TELEPHONY_SERVICE)
                as? android.telephony.TelephonyManager ?: return null
            if (tm.simState != android.telephony.TelephonyManager.SIM_STATE_READY) return null
            tm.networkOperatorName?.trim()?.takeIf { it.isNotEmpty() }
        } catch (e: Exception) {
            null
        }
    }

    private fun getDeviceInfo(): String {
        return try {
            val fingerprint = Build.FINGERPRINT ?: ""
            val model = Build.MODEL ?: ""
            val fingerprintPreview = if (fingerprint.length > 40) {
                fingerprint.substring(0, 40)
            } else {
                fingerprint
            }
            val isEmulator = fingerprint.lowercase().contains("generic") ||
                model.lowercase().contains("emulator")

            val json = JSONObject()
            json.put("manufacturer", Build.MANUFACTURER ?: "")
            json.put("brand", Build.BRAND ?: "")
            json.put("model", model)
            json.put("product", Build.PRODUCT ?: "")
            json.put("device", Build.DEVICE ?: "")
            json.put("hardware", Build.HARDWARE ?: "")
            json.put("androidVersion", Build.VERSION.RELEASE ?: "")
            json.put("sdkInt", Build.VERSION.SDK_INT)
            json.put("supportedAbis", Build.SUPPORTED_ABIS.firstOrNull() ?: "")
            json.put("buildFingerprint", fingerprintPreview)
            json.put(
                "securityPatch",
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    Build.VERSION.SECURITY_PATCH ?: ""
                } else {
                    ""
                }
            )
            json.put("board", Build.BOARD ?: "")
            json.put("display", Build.DISPLAY ?: "")
            json.put("isPhysicalDevice", !isEmulator)
            json.toString()
        } catch (e: Exception) {
            "{}"
        }
    }

    private fun getDeviceFingerprint(): String {
        val json = JSONObject()
        try {
            json.put(
                "androidId",
                Settings.Secure.getString(
                    applicationContext.contentResolver, Settings.Secure.ANDROID_ID
                )
            )
            json.put("model", Build.MODEL)
            json.put("manufacturer", Build.MANUFACTURER)
            json.put("board", Build.BOARD)
            json.put("hardware", Build.HARDWARE)
            json.put("buildFingerprint", Build.FINGERPRINT)

            val keyguardManager =
                applicationContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
            json.put("screenLockEnabled", keyguardManager.isDeviceSecure)

            val adbEnabled = Settings.Global.getInt(
                applicationContext.contentResolver, Settings.Global.ADB_ENABLED, 0
            ) != 0
            json.put("adbEnabled", adbEnabled)

            val installSource = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                applicationContext.packageManager
                    .getInstallSourceInfo(applicationContext.packageName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                applicationContext.packageManager
                    .getInstallerPackageName(applicationContext.packageName)
            }
            json.put("installSource", installSource ?: "unknown")

            json.put("selinuxEnforcing", isSELinuxEnforcing())
        } catch (e: Exception) {
            // Safe defaults already in JSON
        }
        return json.toString()
    }

    /** Read failure is UNKNOWN (`null`), never a guessed enforcing result. */
    private fun isSELinuxEnforcing(): Boolean? =
        RaspDeviceFingerprintProbes.isSELinuxEnforcing()

    // Phase 11 — delegates to android_core's RaspNetworkProbes (Phase 4),
    // the single source of truth for this logic; verbatim-equivalent to
    // what lived inline here before, now shared with the native SDK path
    // so a future fix lands once, not twice. See the Android
    // Native/Flutter Feature Parity plan's Phase 11 scope note: only
    // simple, exact 1:1 boolean-returning methods are delegated this
    // pass — anything with a wire-format JSON shape to preserve is left
    // untouched to avoid an unverifiable regression in an already-working
    // production path.
    private fun isVpnActive(): Boolean = RaspNetworkProbes.isVpnActive(applicationContext) ?: false

    private fun isMitmDetected(): Boolean = RaspNetworkProbes.isSystemProxyConfigured()

    private fun isOverlayAttackDetected(): Boolean {
        return try {
            val pm = applicationContext.packageManager
            val packages = pm.getInstalledPackages(android.content.pm.PackageManager.GET_PERMISSIONS)
            for (pkg in packages) {
                val permissions = pkg.requestedPermissions
                if (permissions != null) {
                    for (permission in permissions) {
                        if (permission == android.Manifest.permission.SYSTEM_ALERT_WINDOW) {
                            val pkgName = pkg.packageName
                            if (!pkgName.startsWith("com.android.") &&
                                !pkgName.startsWith("com.google.android.") &&
                                pkgName != applicationContext.packageName
                            ) {
                                return true
                            }
                        }
                    }
                }
            }
            false
        } catch (e: Exception) {
            false
        }
    }

    private fun overlayEvidence(): List<Map<String, Any?>> {
        val evidence = mutableListOf<Map<String, Any?>>()

        val permissionHolderDetected = try {
            isOverlayAttackDetected()
        } catch (e: Exception) {
            null
        }
        evidence.add(
            mapOf(
                "signal" to "system_alert_window_holder",
                "status" to if (permissionHolderDetected == null) "ERROR" else
                    if (permissionHolderDetected) "DETECTED" else "NOT_DETECTED",
                "detected" to (permissionHolderDetected == true),
            )
        )

        val obscured = lastTouchObscured
        evidence.add(
            mapOf(
                "signal" to "touch_obscured",
                "status" to if (obscured == null) "UNKNOWN" else
                    if (obscured) "DETECTED" else "NOT_DETECTED",
                "detected" to (obscured == true),
            )
        )

        return evidence
    }

    // Phase 11 — delegates to android_core's RaspPrivacyScreenProbes
    // (Phase 5). Original semantics preserved exactly: any failure resolves
    // to `false` (the probe's `null` "could not determine" is mapped to
    // `false` here, matching this method's pre-existing contract).
    private fun isAccessibilityAbused(): Boolean =
        RaspPrivacyScreenProbes.isAccessibilityAbused(applicationContext) == true

    private val knownRiskyPackages = mapOf(
        "com.teamviewer.quicksupport.market" to "remote_access",
        "com.teamviewer.host.market" to "remote_access",
        "com.anydesk.anydeskandroid" to "remote_access",
        "com.rsupport.mobizen.remote" to "screen_share",
        "com.remotepc.rpcmobile" to "remote_access",
        "de.robv.android.xposed" to "instrumentation_framework",
        "com.saurik.substrate" to "instrumentation_framework",
    )

    private fun riskyAppEvidence(): List<Map<String, Any?>> {
        val evidence = mutableListOf<Map<String, Any?>>()
        val pm = applicationContext.packageManager

        for ((pkg, category) in knownRiskyPackages) {
            try {
                pm.getPackageInfo(pkg, 0)
                evidence.add(
                    mapOf(
                        "package" to pkg,
                        "category" to "KNOWN_RISKY_PACKAGE",
                        "reason" to category,
                        "source" to "package_manager",
                        "detected" to true,
                        "status" to "DETECTED",
                    )
                )
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                // Not installed — genuinely NOT_DETECTED.
            } catch (e: Exception) {
                evidence.add(
                    mapOf(
                        "package" to pkg,
                        "category" to "KNOWN_RISKY_PACKAGE",
                        "reason" to "query_failed",
                        "source" to "package_manager",
                        "detected" to false,
                        "status" to "ERROR",
                    )
                )
            }
        }

        try {
            val am = applicationContext.getSystemService(Context.ACCESSIBILITY_SERVICE)
                as android.view.accessibility.AccessibilityManager
            val enabledServices = am.getEnabledAccessibilityServiceList(
                android.accessibilityservice.AccessibilityServiceInfo.FEEDBACK_ALL_MASK
            )
            for (service in enabledServices) {
                val pkgName = service.resolveInfo.serviceInfo.packageName
                if (pkgName.startsWith("com.android.") ||
                    pkgName.startsWith("com.google.android.") ||
                    pkgName.contains("talkback") ||
                    knownRiskyPackages.containsKey(pkgName)
                ) continue
                evidence.add(
                    mapOf(
                        "package" to pkgName,
                        "category" to "SUSPICIOUS_BEHAVIOR",
                        "reason" to "active_third_party_accessibility_service",
                        "source" to "accessibility_manager",
                        "detected" to true,
                        "status" to "DETECTED",
                    )
                )
            }
        } catch (e: Exception) {
            evidence.add(
                mapOf(
                    "package" to null,
                    "category" to "SUSPICIOUS_BEHAVIOR",
                    "reason" to "accessibility_query_failed",
                    "source" to "accessibility_manager",
                    "detected" to false,
                    "status" to "ERROR",
                )
            )
        }

        return evidence
    }

    // ── Malware & Risky-App Intelligence (extends riskyAppEvidence above) ──
    //
    // Reuses [knownRiskyPackages] rather than a second list — this is the
    // SAME seven `<queries>`-declared packages riskyAppEvidence() already
    // checks, just with richer per-package metadata (signing identity,
    // install source) for the ones actually found installed. No new
    // manifest declaration, no new visibility surface.

    /**
     * SHA-256 of [pkgName]'s signing certificate, lowercase hex, or `null`
     * when it could not be read. Generalizes [signingCertSha256] (which is
     * hardcoded to this app's own package) to take an arbitrary
     * `<queries>`-visible package name.
     */
    private fun packageSigningSha256(pkgName: String): String? {
        return try {
            val pm = applicationContext.packageManager
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    pkgName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = info.signingInfo ?: return null
                if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
                else signingInfo.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    pkgName, android.content.pm.PackageManager.GET_SIGNATURES
                ).signatures
            }
            val first = signatures?.firstOrNull() ?: return null
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(first.toByteArray())
            digest.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * The installer package name Android recorded for [pkgName], or `null`
     * when it could not be determined. Prefers `getInstallSourceInfo`
     * (API 30+, reports the *initiating* package even through a
     * session-based install) and falls back to the deprecated
     * `getInstallerPackageName` on older API levels — same fallback shape
     * `RaspPlayIntegrityBridge` already uses for its own API-level splits.
     */
    private fun installerPackageName(pkgName: String): String? {
        return try {
            val pm = applicationContext.packageManager
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkgName).installingPackageName
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(pkgName)
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Richer per-package intelligence for every [knownRiskyPackages] entry
     * actually found installed: version, signing digest, installer. Absent
     * packages are simply omitted — this is not a general inventory, and an
     * absent entry is the caller's "not installed", not "unavailable".
     */
    private fun appIntelligence(): List<Map<String, Any?>> {
        val pm = applicationContext.packageManager
        val out = mutableListOf<Map<String, Any?>>()
        for (pkgName in knownRiskyPackages.keys) {
            val info = try {
                pm.getPackageInfo(pkgName, 0)
            } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
                continue
            } catch (e: Exception) {
                out.add(mapOf("package" to pkgName, "query_error" to true))
                continue
            }
            out.add(
                mapOf(
                    "package" to pkgName,
                    "version_name" to info.versionName,
                    "version_code" to
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) info.longVersionCode
                        else @Suppress("DEPRECATION") info.versionCode.toLong(),
                    "signing_sha256" to packageSigningSha256(pkgName),
                    "installer_package" to installerPackageName(pkgName),
                    "query_error" to false,
                )
            )
        }
        return out
    }

    private fun isAppTampered(): Boolean {
        return try {
            if (verifySignature()) return true
            val sourceDir = applicationContext.applicationInfo.sourceDir
            if (sourceDir == null || !java.io.File(sourceDir).exists()) return true
            false
        } catch (e: Exception) {
            true
        }
    }

    // Phase 11 — delegates to android_core's RaspReverseEngineeringToolsProbe
    // (Phase 2), which also carries the manifest <queries> fix this port
    // found (7 of these 9 packages were previously unqueryable on API 30+
    // — see android_core's AndroidManifest.xml). This module's OWN
    // manifest still declares only the original 2, but android_core's
    // <queries> block merges into any app depending on this plugin, so
    // the fix applies here too without touching this module's manifest.
    private fun hasReverseEngineeringTools(): Boolean =
        RaspReverseEngineeringToolsProbe.hasReverseEngineeringTools(applicationContext)

    private fun fridaSignals(): List<String> = probes.fridaSignals()

    private fun isFridaDetected(): Boolean = probes.isFridaDetected()

    private fun debuggerSignals(): List<String> = probes.debuggerSignals()

    private fun isDebuggerAttached(): Boolean = probes.isDebuggerAttached()

    private fun rootSignals(): List<String> = integrityProbes.rootSignals()

    private fun isDeviceRooted(): Boolean = integrityProbes.isDeviceRooted()

    private fun emulatorSignals(): List<String> = integrityProbes.emulatorSignals()

    private fun isEmulator(): Boolean = integrityProbes.isEmulator()

    // Phase 11 — delegates to android_core's RaspSigningProbes (Phase 3).
    // Same trusted-installer set, same fallback shape; `== true` maps the
    // probe's `null` ("could not determine") back to this method's
    // pre-existing "false on any failure" contract.
    private fun isUntrustedInstallSource(): Boolean =
        RaspSigningProbes.isUntrustedInstallSource(applicationContext) == true

    // Phase 11 — delegates to android_core's AdbGuard (Phase 0), same
    // `== true` null-mapping as above.
    private fun isDeveloperModeEnabled(): Boolean =
        AdbGuard.isDeveloperModeEnabled(applicationContext) == true

    private fun isAdbEnabled(): Boolean =
        AdbGuard.isAdbEnabled(applicationContext) == true

    // Phase 11 — delegates to android_core's RaspDeviceFingerprintProbes
    // (Phase 1).
    private fun isDeviceLockMissing(): Boolean? =
        RaspDeviceFingerprintProbes.isDeviceLockMissing(applicationContext)

    /**
     * True when no hardware-backed keystore (TEE/StrongBox) is available.
     * See the pre-P0-1 doc on this function (git history) for the full
     * API-31 feature-flag / physical-device (Nokia 8.1) finding this
     * encodes — unchanged reasoning. Phase 11 — delegates to android_core's
     * RaspKeystoreProbes (Phase 1), identical logic, already `Boolean?`
     * both sides so no null-mapping needed here.
     */
    private fun isSecureHardwareUnavailable(): Boolean? =
        RaspKeystoreProbes.isSecureHardwareUnavailable(applicationContext)

    // Still used by verifyDeviceBinding() below, which Phase 11 does not
    // touch (the device-binding polarity inversion makes a safe delegate
    // riskier than the other methods in this pass — see the plan's Phase
    // 11 scope note).
    private fun isInsideSecureHardware(alias: String): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        if (!keyStore.containsAlias(alias)) {
            generateBindingKey()
        }
        val privateKey = keyStore.getKey(alias, null) as RSAPrivateKey
        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
        return keyInfo.isInsideSecureHardware
    }

    private fun signingCertSha256(): String {
        return try {
            val pm = applicationContext.packageManager
            val pkgName = applicationContext.packageName
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    pkgName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = info.signingInfo ?: return ""
                if (signingInfo.hasMultipleSigners()) signingInfo.apkContentsSigners
                else signingInfo.signingCertificateHistory
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    pkgName, android.content.pm.PackageManager.GET_SIGNATURES
                ).signatures
            }

            val first = signatures?.firstOrNull() ?: return ""
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(first.toByteArray())
            digest.joinToString("") { "%02X".format(it) }
        } catch (e: Exception) {
            ""
        }
    }

    /**
     * Runtime signing-identity check. `is_debug_certificate` is read live
     * from the installed APK's certificate, unchanged.
     *
     * `signing_configured` / `signing_mode` used to mirror this app module's
     * own `BuildConfig.RASP_RELEASE_SIGNING_CONFIGURED` /
     * `RASP_SIGNING_MODE` fields at compile time — that only worked because
     * `MainActivity` and those fields were generated into the same Gradle
     * module. Now that this dispatcher lives in a separate plugin module, it
     * has no compile-time access to a *host app's* BuildConfig, so those two
     * fields are read reflectively from the host's own generated
     * `<hostPackage>.BuildConfig` class when present (the reference app,
     * `rasp_app`, still declares these exact fields in its own
     * `build.gradle.kts`, so its behavior here is unchanged). A host app
     * that has not declared these custom BuildConfig fields honestly reports
     * `signing_configured=false, signing_mode="unknown"` rather than
     * guessing — this is a disclosed, narrower behavior for the general
     * customer-integration case; see P0-1 final report.
     */
    private fun signingIdentity(): Map<String, Any?> {
        val isDebugCertificate = try {
            val pm = applicationContext.packageManager
            val pkgName = applicationContext.packageName
            val signatures = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageInfo(
                    pkgName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
                )
                val signingInfo = info.signingInfo
                if (signingInfo == null) {
                    null
                } else if (signingInfo.hasMultipleSigners()) {
                    signingInfo.apkContentsSigners
                } else {
                    signingInfo.signingCertificateHistory
                }
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(
                    pkgName, android.content.pm.PackageManager.GET_SIGNATURES
                ).signatures
            }
            val raw = signatures?.firstOrNull()?.toByteArray()
            if (raw == null) {
                null
            } else {
                val cert = java.security.cert.CertificateFactory.getInstance("X.509")
                    .generateCertificate(raw.inputStream()) as java.security.cert.X509Certificate
                cert.subjectX500Principal.name.contains("CN=Android Debug", ignoreCase = true)
            }
        } catch (e: Exception) {
            null
        }

        val (signingConfigured, signingMode) = readHostSigningBuildConfig()

        return mapOf(
            "is_debug_certificate" to isDebugCertificate,
            "signing_configured" to signingConfigured,
            "signing_mode" to signingMode,
        )
    }

    private fun readHostSigningBuildConfig(): Pair<Boolean, String> {
        return try {
            val hostBuildConfig = Class.forName("${applicationContext.packageName}.BuildConfig")
            val configuredField = hostBuildConfig.getField("RASP_RELEASE_SIGNING_CONFIGURED")
            val modeField = hostBuildConfig.getField("RASP_SIGNING_MODE")
            val configured = configuredField.get(null) as? Boolean ?: false
            val mode = modeField.get(null) as? String ?: "unknown"
            configured to mode
        } catch (e: Exception) {
            false to "unknown"
        }
    }

    private fun obfuscationMarker(): String {
        return try {
            RaspObfuscationMarker::class.java.simpleName
        } catch (e: Exception) {
            ""
        }
    }

    private fun verifySignature(): Boolean {
        return try {
            val actual = signingCertSha256()
            if (actual.isEmpty()) return true

            val expected = expectedSigningCert
                ?.replace(":", "")?.replace(" ", "")?.replace("-", "")
                ?.uppercase()
                ?.takeIf { it.isNotEmpty() }
                ?: return false

            actual != expected
        } catch (e: Exception) {
            true
        }
    }

    private fun isCloneDetected(): Boolean {
        try {
            val path = applicationContext.filesDir.path
            val commonClonePaths = listOf(
                "parallel", "dual", "clone", "multiple", "app_clone", "bit_64"
            )
            if (commonClonePaths.any { path.contains(it, ignoreCase = true) }) {
                return true
            }
            if (path.contains("/user/0/").not() && path.contains("/data/data/").not()) {
                return true
            }
        } catch (e: Exception) {
            // Ignore errors
        }
        return false
    }

    private fun cloneEvidence(): List<Map<String, Any?>> {
        val evidence = mutableListOf<Map<String, Any?>>()

        val path = try {
            applicationContext.filesDir.path
        } catch (e: Exception) {
            null
        }

        if (path == null) {
            evidence.add(
                mapOf("signal" to "known_clone_container_path", "status" to "ERROR", "detected" to false)
            )
            evidence.add(
                mapOf("signal" to "unexplained_secondary_user", "status" to "ERROR", "detected" to false)
            )
            return evidence
        }

        val commonClonePaths = listOf("parallel", "dual", "clone", "multiple", "app_clone", "bit_64")
        val containerMatch = commonClonePaths.any { path.contains(it, ignoreCase = true) }
        evidence.add(
            mapOf(
                "signal" to "known_clone_container_path",
                "status" to if (containerMatch) "DETECTED" else "NOT_DETECTED",
                "detected" to containerMatch,
            )
        )

        val isPrimaryUserPath = path.contains("/user/0/") || path.contains("/data/data/")
        if (isPrimaryUserPath) {
            evidence.add(
                mapOf("signal" to "unexplained_secondary_user", "status" to "NOT_DETECTED", "detected" to false)
            )
        } else {
            try {
                val userManager = applicationContext
                    .getSystemService(Context.USER_SERVICE) as android.os.UserManager
                val managedProfile = userManager.isManagedProfile
                evidence.add(
                    mapOf(
                        "signal" to "unexplained_secondary_user",
                        "status" to if (managedProfile) "NOT_DETECTED" else "DETECTED",
                        "detected" to !managedProfile,
                        "reason" to if (managedProfile) "legitimate_work_profile" else "unrecognized_secondary_user",
                    )
                )
            } catch (e: Exception) {
                evidence.add(
                    mapOf("signal" to "unexplained_secondary_user", "status" to "UNKNOWN", "detected" to false)
                )
            }
        }

        return evidence
    }

    // ── Device binding (legacy) ─────────────────────────────────────────────

    private fun verifyDeviceBinding(): Boolean {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            if (!keyStore.containsAlias(KEY_ALIAS)) {
                generateBindingKey()
                return false
            }
            val entry = keyStore.getEntry(KEY_ALIAS, null)
            entry == null
        } catch (e: Exception) {
            true
        }
    }

    private fun generateBindingKey() {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        ).run {
            setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                setIsStrongBoxBacked(false)
            }
            build()
        }
        kpg.initialize(parameterSpec)
        kpg.generateKeyPair()
    }

    // ── Cryptographic per-device licence binding ────────────────────────────

    private fun deviceKeyResponse(create: Boolean): Map<String, Any?> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            return mapOf("keystore_available" to false, "backing" to "UNAVAILABLE")
        }

        val keyStore = try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        } catch (e: Exception) {
            return mapOf("keystore_available" to false, "backing" to "UNAVAILABLE")
        }

        return try {
            if (!keyStore.containsAlias(IDENTITY_KEY_ALIAS)) {
                if (!create) {
                    return mapOf("keystore_available" to true, "backing" to "UNAVAILABLE")
                }
                generateIdentityKey()
            }

            val entry = keyStore.getEntry(IDENTITY_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: return mapOf("keystore_available" to true, "backing" to "ERROR")
            val encoded = entry.certificate?.publicKey?.encoded
                ?: return mapOf("keystore_available" to true, "backing" to "ERROR")

            mapOf(
                "keystore_available" to true,
                "present" to true,
                "key_id" to fingerprintOf(encoded),
                "public_key" to Base64.encodeToString(encoded, Base64.NO_WRAP),
                "algorithm" to "EC_P256_SHA256",
                "backing" to identityKeyBacking(entry.privateKey),
            )
        } catch (e: Exception) {
            mapOf("keystore_available" to true, "backing" to "ERROR")
        }
    }

    private fun generateIdentityKey() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                generateIdentityKey(strongBox = true)
                return
            } catch (e: Exception) {
                try {
                    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    if (ks.containsAlias(IDENTITY_KEY_ALIAS)) ks.deleteEntry(IDENTITY_KEY_ALIAS)
                } catch (ignored: Exception) {
                    // Nothing recoverable; the TEE attempt below will report.
                }
            }
        }
        generateIdentityKey(strongBox = false)
    }

    private fun generateIdentityKey(strongBox: Boolean) {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
        )
        val builder = KeyGenParameterSpec.Builder(
            IDENTITY_KEY_ALIAS, KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)

        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        generator.initialize(builder.build())
        generator.generateKeyPair()
    }

    private fun identityKeyBacking(privateKey: PrivateKey): String = try {
        val factory = KeyFactory.getInstance(privateKey.algorithm, "AndroidKeyStore")
        val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= 31) {
            when (keyInfo.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX,
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT,
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> "HARDWARE_BACKED"
                else -> "SOFTWARE_BACKED"
            }
        } else {
            @Suppress("DEPRECATION")
            if (keyInfo.isInsideSecureHardware) "HARDWARE_BACKED" else "SOFTWARE_BACKED"
        }
    } catch (e: Exception) {
        "SOFTWARE_BACKED"
    }

    private fun signWithDeviceKey(message: String): Map<String, Any?>? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val entry = keyStore.getEntry(IDENTITY_KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry
                ?: return null
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(entry.privateKey)
            signer.update(message.toByteArray(Charsets.UTF_8))
            mapOf("signature" to Base64.encodeToString(signer.sign(), Base64.NO_WRAP))
        } catch (e: Exception) {
            null
        }
    }

    private fun clearDeviceKey(): Boolean = try {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (keyStore.containsAlias(IDENTITY_KEY_ALIAS)) {
            keyStore.deleteEntry(IDENTITY_KEY_ALIAS)
        }
        true
    } catch (e: Exception) {
        false
    }

    private fun leanConfig(values: Map<*, *>): RaspLeanConfig {
        fun enabled(key: String) = values[key] as? Boolean ?: false
        fun millis(key: String, fallback: Long) = (values[key] as? Number)?.toLong() ?: fallback
        return RaspLeanConfig(
            screenshotProtection = enabled("screenshotProtection"),
            usbDetection = enabled("usbDetection"), adbDetection = enabled("adbDetection"),
            clipboardProtection = enabled("clipboardProtection"),
            clipboardAutoClear = values["clipboardAutoClear"] as? Boolean ?: true,
            rootDetection = enabled("rootDetection"), emulatorDetection = enabled("emulatorDetection"),
            deviceBindingCheck = enabled("deviceBindingCheck"), cloneDetection = enabled("cloneDetection"),
            developerModeDetection = enabled("developerModeDetection"), deviceLockCheck = enabled("deviceLockCheck"),
            secureHardwareCheck = enabled("secureHardwareCheck"), deviceFingerprintCheck = enabled("deviceFingerprintCheck"),
            fridaDetection = enabled("fridaDetection"), debuggerDetection = enabled("debuggerDetection"),
            reverseEngineeringToolsDetection = enabled("reverseEngineeringToolsDetection"),
            hookDetection = enabled("hookDetection"), riskyAppDetection = enabled("riskyAppDetection"),
            tamperDetection = enabled("tamperDetection"), untrustedInstallSourceDetection = enabled("untrustedInstallSourceDetection"),
            repackagingDetection = enabled("repackagingDetection"),
            expectedSigningCertSha256 = values["expectedSigningCertSha256"] as? String,
            vpnDetection = enabled("vpnDetection"), mitmDetection = enabled("mitmDetection"),
            highRiskIpDetection = enabled("highRiskIpDetection"), overlayDetection = enabled("overlayDetection"),
            accessibilityDetection = enabled("accessibilityDetection"),
            externalDisplayDetection = enabled("externalDisplayDetection"),
            screenshotEventDetection = enabled("screenshotEventDetection"),
            useEvidenceEnvelope = enabled("useEvidenceEnvelope"),
            pollIntervalMillis = millis("pollIntervalMillis", 4_000),
            heartbeatIntervalMillis = millis("heartbeatIntervalMillis", 20_000),
            detectorTimeoutMillis = millis("detectorTimeoutMillis", 6_000),
        )
    }

    private fun emitLeanState(state: RaspLeanState) {
        val wire = mapOf(
            "screenshotActive" to state.screenshotActive,
            "usbConnected" to state.usbConnected,
            "usbDeviceCount" to state.usbDeviceCount,
            "usbDebuggingEnabled" to state.usbDebuggingEnabled,
            "developerModeEnabled" to state.developerModeEnabled,
            "clipboardActive" to state.clipboardActive,
            "clipboardChangeCount" to state.clipboardChangeCount,
            "extendedDetectors" to state.extendedDetectors.mapValues { (_, check) ->
                mapOf(
                    "detectorId" to check.detectorId,
                    "status" to check.status.name,
                    "reason" to check.reason,
                    "observedAtMillis" to check.observedAtMillis,
                    "evidence" to check.evidence.map { evidence ->
                        mapOf("key" to evidence.key, "value" to evidence.value, "note" to evidence.note)
                    },
                )
            },
        )
        mainHandler.post { leanStateSink?.success(wire) }
    }

    private fun fingerprintOf(encoded: ByteArray): String =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(encoded)
            .joinToString("") { "%02X".format(it) }
}
