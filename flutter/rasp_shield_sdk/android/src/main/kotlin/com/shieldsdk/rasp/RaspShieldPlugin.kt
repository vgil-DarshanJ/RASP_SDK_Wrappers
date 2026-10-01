package com.shieldsdk.rasp

import android.app.Activity
import android.os.Build
import android.view.MotionEvent
import android.view.Window
import android.view.WindowManager
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.activity.ActivityAware
import io.flutter.embedding.engine.plugins.activity.ActivityPluginBinding
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel

/**
 * The self-registering entry point of the real RASP Shield native security
 * engine (P0-1 native-plugin extraction).
 *
 * Flutter's own plugin loader (`dev.flutter.flutter-plugin-loader`, already
 * applied by every consuming app's `settings.gradle.kts` in this project)
 * discovers this class from `pubspec.yaml`'s `flutter: plugin:` declaration
 * and instantiates it automatically — a host app gets working native
 * detectors from a normal `pubspec.yaml` dependency, with **no MainActivity
 * edit, no manual MethodChannel registration, no manual Gradle wiring**
 * beyond the standard `flutter pub get`.
 *
 * The channel name (`com.shieldsdk.security/security`) is unchanged from
 * the pre-extraction implementation, so `RaspNativeChannel` (Dart side)
 * required no changes at all.
 *
 * ## FLAG_SECURE timing — a disclosed, NOT fully resolved, compatibility risk
 *
 * The pre-extraction `MainActivity.onCreate()` applied `FLAG_SECURE`
 * **before** calling `super.onCreate()`, a placement empirically proven on a
 * physical OnePlus device (Android 16 / API 36) to avoid a black-screen
 * regression the OEM's security-mask compositor otherwise causes when the
 * flag is applied to an already-rendering FlutterView surface (see
 * `docs/ONEPLUS_FLAG_SECURE_PRODUCTION_FIX.md` in the reference app).
 *
 * A Flutter plugin has no hook that runs before `Activity.onCreate()` — the
 * earliest this class can ever touch the Activity is [onAttachedToActivity],
 * which necessarily fires *after* `super.onCreate()` has already run. This
 * plugin applies `FLAG_SECURE` at that earliest available point, which is
 * the closest a plugin-only architecture can get — but it is NOT proven
 * equivalent to the original guaranteed-safe timing until re-verified on a
 * real device/emulator. See the P0-1 final report's FLAG_SECURE section for
 * the actual verification result. This is called out explicitly rather than
 * silently assumed safe.
 */
class RaspShieldPlugin : FlutterPlugin, ActivityAware {

    private lateinit var channel: MethodChannel
    private lateinit var leanStateChannel: EventChannel
    private lateinit var handler: RaspSecurityChannelHandler

    private var activity: Activity? = null
    private var originalWindowCallback: Window.Callback? = null

    // Real screenshot-event callback, API 34+ only — `Activity.
    // ScreenCaptureCallback` has no pre-34 equivalent (see
    // RaspSecurityChannelHandler's screen-capture section doc for why
    // nothing is approximated below that level). This module's compileSdk
    // (`flutter.compileSdkVersion`) is >= 34, so the type itself is always
    // resolvable at compile time; only the runtime SDK_INT check below
    // decides whether it is ever registered.
    private var screenCaptureCallback: Activity.ScreenCaptureCallback? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        handler = RaspSecurityChannelHandler(
            applicationContext = binding.applicationContext,
            activityProvider = { activity },
        )
        channel = MethodChannel(binding.binaryMessenger, "com.shieldsdk.security/security")
        channel.setMethodCallHandler(handler)
        leanStateChannel = EventChannel(binding.binaryMessenger, "com.shieldsdk.security/lean_state")
        leanStateChannel.setStreamHandler(handler)
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
        leanStateChannel.setStreamHandler(null)
        handler.shutdown()
    }

    override fun onAttachedToActivity(binding: ActivityPluginBinding) {
        attachActivity(binding.activity)
    }

    override fun onReattachedToActivityForConfigChanges(binding: ActivityPluginBinding) {
        attachActivity(binding.activity)
    }

    override fun onDetachedFromActivityForConfigChanges() {
        detachActivity()
    }

    override fun onDetachedFromActivity() {
        detachActivity()
    }

    private fun attachActivity(newActivity: Activity) {
        activity = newActivity
        handler.onActivityAttached(newActivity)

        // Earliest available point to apply FLAG_SECURE — see the class doc
        // above for why this is not claimed equivalent to the pre-extraction
        // pre-super.onCreate() placement without device re-verification.
        try {
            newActivity.window.setFlags(
                WindowManager.LayoutParams.FLAG_SECURE,
                WindowManager.LayoutParams.FLAG_SECURE
            )
        } catch (e: Exception) {
            // Never block attachment on this. isSecureWindowActive() reads
            // the real window attribute, so a failure here surfaces honestly
            // as ERROR at scan time rather than being silently assumed
            // applied.
        }

        // Tell the platform to never generate a task-snapshot screenshot of
        // this Activity for the Recents UI (API 33+; default is `true` on
        // every Activity). Android takes this snapshot automatically around
        // Activity start on every single launch — completely independent of
        // any user action — and on-device testing shows that capture can be
        // observed by `ScreenCaptureCallback` (registered just below) as a
        // spurious "screenshot taken" event the instant the app opens, with
        // no real screenshot ever having been taken. This is the primary
        // fix for that false positive; the startup suppression window in
        // RaspSecurityChannelHandler.onScreenshotEventDetected is the
        // fallback for OS versions/OEM skins where this request isn't
        // honored. See https://source.android.com/docs/core/perf/task-snapshots.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            try {
                newActivity.setRecentsScreenshotEnabled(false)
            } catch (e: Exception) {
                // Never block attachment on this — purely a false-positive
                // mitigation, not a security control.
            }
        }

        installTouchObscuredTracking(newActivity)
        registerScreenCaptureCallback(newActivity)
    }

    private fun detachActivity() {
        handler.onActivityDetached()
        unregisterScreenCaptureCallback()
        restoreWindowCallback()
        activity = null
    }

    /**
     * Real screenshot-event detection (API 34+ only — see
     * [RaspSecurityChannelHandler]'s doc comment on this section for exactly
     * why nothing is approximated on older OS versions). Registered on
     * every attach, including [onReattachedToActivityForConfigChanges] — an
     * activity recreation (rotation, config change) would otherwise leave
     * this device silently unmonitored until the next cold start.
     */
    private fun registerScreenCaptureCallback(target: Activity) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.UPSIDE_DOWN_CAKE) return
        try {
            val callback = Activity.ScreenCaptureCallback { handler.onScreenshotEventDetected() }
            target.registerScreenCaptureCallback(target.mainExecutor, callback)
            screenCaptureCallback = callback
            // See flushScreenshotEventCountOnRegister's own doc — discards
            // anything counted at/before this exact registration, so a
            // spurious fire tied to registration (or the FLAG_SECURE
            // application immediately above) can never be misreported as a
            // real screenshot the user just took.
            handler.flushScreenshotEventCountOnRegister()
        } catch (e: Exception) {
            // Never block attachment on this — getScreenCaptureCapabilities()
            // reports the real, current state; a registration failure here
            // simply means no further screenshot events are observed this
            // session, honestly reflected as `detected: false` rather than a
            // crash.
            screenCaptureCallback = null
        }
    }

    private fun unregisterScreenCaptureCallback() {
        val current = activity
        val callback = screenCaptureCallback ?: return
        if (current != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            try {
                current.unregisterScreenCaptureCallback(callback)
            } catch (e: Exception) {
                // Activity may already be torn down; nothing to unregister.
            }
        }
        screenCaptureCallback = null
    }

    /**
     * Overlay/tapjacking corroboration signal, without subclassing the
     * host's Activity (impossible from a plugin — this is the standard
     * Android technique for observing touch dispatch non-invasively).
     * Wraps whatever `Window.Callback` is currently installed (Flutter's
     * own, or the platform default), forwards every call unchanged, and
     * only peeks at `MotionEvent` flags on `dispatchTouchEvent` — the exact
     * same signal the pre-extraction `Activity.dispatchTouchEvent` override
     * read, just observed from outside the Activity instead of by
     * overriding it.
     */
    private fun installTouchObscuredTracking(activity: Activity) {
        val window = activity.window
        val current = window.callback ?: return
        originalWindowCallback = current
        window.callback = TouchObscuredWindowCallback(current) { obscured ->
            handler.onTouchObscuredChanged(obscured)
        }
    }

    private fun restoreWindowCallback() {
        val activity = activity ?: return
        val original = originalWindowCallback ?: return
        try {
            if (activity.window.callback is TouchObscuredWindowCallback) {
                activity.window.callback = original
            }
        } catch (e: Exception) {
            // Activity/window may already be torn down; nothing to restore.
        }
        originalWindowCallback = null
    }

    private class TouchObscuredWindowCallback(
        private val delegate: Window.Callback,
        private val onTouch: (Boolean) -> Unit,
    ) : Window.Callback by delegate {
        override fun dispatchTouchEvent(event: MotionEvent): Boolean {
            onTouch(
                (event.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED) != 0 ||
                    (event.flags and MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
            )
            return delegate.dispatchTouchEvent(event)
        }
    }
}
