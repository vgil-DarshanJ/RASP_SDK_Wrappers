package com.shieldsdk.rasp.reactnative

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.ReadableMap
import com.facebook.react.bridge.ReadableType
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap
import com.shieldsdk.rasp.RaspCheckResult
import com.shieldsdk.rasp.RaspShieldCore
import com.shieldsdk.rasp.nativeshield.RaspLeanConfig
import com.shieldsdk.rasp.nativeshield.RaspLeanState
import com.shieldsdk.rasp.nativeshield.RaspLocationSnapshot

/**
 * Native ⇄ JS conversion. Shapes match `src/types.ts` exactly; the JS
 * side re-validates everything in `normalizeResult`/`normalizeState`, so a
 * field added here without a matching type change degrades to a safe
 * default rather than crashing.
 */
internal object RaspShieldSerialization {

    const val MIN_INTERVAL_MILLIS = 1_000L

    fun result(result: RaspCheckResult): WritableMap = Arguments.createMap().apply {
        putString("detectorId", result.detectorId)
        putString("status", result.status.name)
        putArray("evidence", Arguments.createArray().also { array ->
            result.evidence.forEach { e ->
                array.pushMap(Arguments.createMap().apply {
                    putString("key", e.key)
                    putValue(this, "value", e.value)
                    if (e.note != null) putString("note", e.note) else putNull("note")
                })
            }
        })
        if (result.reason != null) putString("reason", result.reason) else putNull("reason")
        putDouble("observedAtMillis", result.observedAtMillis.toDouble())
    }

    fun results(results: List<RaspCheckResult>): WritableArray =
        Arguments.createArray().also { array -> results.forEach { array.pushMap(result(it)) } }

    fun state(state: RaspLeanState): WritableMap = Arguments.createMap().apply {
        putNullableBoolean(this, "screenshotActive", state.screenshotActive)
        putNullableBoolean(this, "usbConnected", state.usbConnected)
        putInt("usbDeviceCount", state.usbDeviceCount)
        putNullableBoolean(this, "usbDebuggingEnabled", state.usbDebuggingEnabled)
        putNullableBoolean(this, "developerModeEnabled", state.developerModeEnabled)
        putNullableBoolean(this, "clipboardActive", state.clipboardActive)
        putInt("clipboardChangeCount", state.clipboardChangeCount)
        putMap("extendedDetectors", Arguments.createMap().also { map ->
            state.extendedDetectors.forEach { (id, r) -> map.putMap(id, result(r)) }
        })
        putDouble("observedAtMillis", System.currentTimeMillis().toDouble())
    }

    fun selfTest(report: RaspShieldCore.RaspSelfTestReport): WritableMap = Arguments.createMap().apply {
        putArray("results", results(report.results))
        putBoolean("criticalReflectionIntact", report.criticalReflectionIntact)
        putArray("erroredDetectorIds", Arguments.createArray().also { a ->
            report.erroredDetectorIds.forEach { a.pushString(it) }
        })
        putArray("unavailableDetectorIds", Arguments.createArray().also { a ->
            report.unavailableDetectorIds.forEach { a.pushString(it) }
        })
    }

    /**
     * Reads every flag by the SAME name as the Kotlin/Dart configs. An
     * absent key keeps the Kotlin default (every detector off,
     * clipboardAutoClear on, 4s poll, 20s heartbeat). Intervals are
     * clamped to ≥1s so a typo like `pollIntervalMillis: 4` cannot turn the
     * session into a busy loop hammering the ingestion API.
     */
    fun config(map: ReadableMap): RaspLeanConfig {
        val d = RaspLeanConfig()
        fun b(key: String, default: Boolean) =
            if (map.hasKey(key) && map.getType(key) == ReadableType.Boolean) map.getBoolean(key) else default
        fun ms(key: String, default: Long) =
            if (map.hasKey(key) && map.getType(key) == ReadableType.Number) {
                map.getDouble(key).toLong().coerceAtLeast(MIN_INTERVAL_MILLIS)
            } else default
        val cert = if (map.hasKey("expectedSigningCertSha256") &&
            map.getType("expectedSigningCertSha256") == ReadableType.String
        ) map.getString("expectedSigningCertSha256")?.takeIf { it.isNotBlank() } else null

        return RaspLeanConfig(
            screenshotProtection = b("screenshotProtection", d.screenshotProtection),
            usbDetection = b("usbDetection", d.usbDetection),
            adbDetection = b("adbDetection", d.adbDetection),
            clipboardProtection = b("clipboardProtection", d.clipboardProtection),
            clipboardAutoClear = b("clipboardAutoClear", d.clipboardAutoClear),
            rootDetection = b("rootDetection", d.rootDetection),
            emulatorDetection = b("emulatorDetection", d.emulatorDetection),
            deviceBindingCheck = b("deviceBindingCheck", d.deviceBindingCheck),
            cloneDetection = b("cloneDetection", d.cloneDetection),
            developerModeDetection = b("developerModeDetection", d.developerModeDetection),
            deviceLockCheck = b("deviceLockCheck", d.deviceLockCheck),
            secureHardwareCheck = b("secureHardwareCheck", d.secureHardwareCheck),
            deviceFingerprintCheck = b("deviceFingerprintCheck", d.deviceFingerprintCheck),
            fridaDetection = b("fridaDetection", d.fridaDetection),
            debuggerDetection = b("debuggerDetection", d.debuggerDetection),
            reverseEngineeringToolsDetection = b("reverseEngineeringToolsDetection", d.reverseEngineeringToolsDetection),
            hookDetection = b("hookDetection", d.hookDetection),
            riskyAppDetection = b("riskyAppDetection", d.riskyAppDetection),
            tamperDetection = b("tamperDetection", d.tamperDetection),
            untrustedInstallSourceDetection = b("untrustedInstallSourceDetection", d.untrustedInstallSourceDetection),
            repackagingDetection = b("repackagingDetection", d.repackagingDetection),
            expectedSigningCertSha256 = cert,
            vpnDetection = b("vpnDetection", d.vpnDetection),
            mitmDetection = b("mitmDetection", d.mitmDetection),
            highRiskIpDetection = b("highRiskIpDetection", d.highRiskIpDetection),
            overlayDetection = b("overlayDetection", d.overlayDetection),
            accessibilityDetection = b("accessibilityDetection", d.accessibilityDetection),
            externalDisplayDetection = b("externalDisplayDetection", d.externalDisplayDetection),
            screenshotEventDetection = b("screenshotEventDetection", d.screenshotEventDetection),
            pollIntervalMillis = ms("pollIntervalMillis", d.pollIntervalMillis),
            heartbeatIntervalMillis = ms("heartbeatIntervalMillis", d.heartbeatIntervalMillis),
        )
    }

    /** `null` for a null map or one missing a finite latitude/longitude. */
    fun location(map: ReadableMap?): RaspLocationSnapshot? {
        if (map == null) return null
        fun num(key: String): Double? =
            if (map.hasKey(key) && map.getType(key) == ReadableType.Number) map.getDouble(key) else null
        val lat = num("latitude")?.takeIf { it.isFinite() && it in -90.0..90.0 } ?: return null
        val lng = num("longitude")?.takeIf { it.isFinite() && it in -180.0..180.0 } ?: return null
        return RaspLocationSnapshot(
            latitude = lat,
            longitude = lng,
            accuracyMeters = num("accuracyMeters")?.takeIf { it.isFinite() && it >= 0 },
            capturedAtMillis = num("capturedAtMillis")?.toLong() ?: System.currentTimeMillis(),
        )
    }

    private fun putNullableBoolean(map: WritableMap, key: String, value: Boolean?) {
        if (value == null) map.putNull(key) else map.putBoolean(key, value)
    }

    /** Evidence values are `Any?` in android_core (counts, strings,
     *  booleans, lists of display names, maps). Everything else falls back
     *  to its string form rather than being dropped. */
    private fun putValue(map: WritableMap, key: String, value: Any?) {
        when (value) {
            null -> map.putNull(key)
            is Boolean -> map.putBoolean(key, value)
            is Int -> map.putInt(key, value)
            is Number -> map.putDouble(key, value.toDouble())
            is String -> map.putString(key, value)
            is Collection<*> -> map.putArray(key, array(value))
            is Array<*> -> map.putArray(key, array(value.toList()))
            is Map<*, *> -> map.putMap(key, nested(value))
            else -> map.putString(key, value.toString())
        }
    }

    private fun array(values: Collection<*>): WritableArray = Arguments.createArray().also { a ->
        values.forEach { v ->
            when (v) {
                null -> a.pushNull()
                is Boolean -> a.pushBoolean(v)
                is Int -> a.pushInt(v)
                is Number -> a.pushDouble(v.toDouble())
                is String -> a.pushString(v)
                is Collection<*> -> a.pushArray(array(v))
                is Map<*, *> -> a.pushMap(nested(v))
                else -> a.pushString(v.toString())
            }
        }
    }

    private fun nested(values: Map<*, *>): WritableMap = Arguments.createMap().also { m ->
        values.forEach { (k, v) -> putValue(m, k.toString(), v) }
    }
}
