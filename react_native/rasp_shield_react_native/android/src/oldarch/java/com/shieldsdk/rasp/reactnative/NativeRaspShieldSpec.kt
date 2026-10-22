package com.shieldsdk.rasp.reactnative

import com.facebook.react.bridge.Promise
import com.facebook.react.bridge.ReactApplicationContext
import com.facebook.react.bridge.ReactContextBaseJavaModule
import com.facebook.react.bridge.ReactMethod
import com.facebook.react.bridge.ReadableMap

/**
 * Old Architecture (bridge) counterpart of the codegen-generated
 * `NativeRaspShieldSpec` used under the New Architecture. Method-for-method
 * identical to `src/specs/NativeRaspShield.ts`, so [RaspShieldModule] is a
 * single implementation that compiles against either.
 */
abstract class NativeRaspShieldSpec(context: ReactApplicationContext) :
    ReactContextBaseJavaModule(context) {

    @ReactMethod abstract fun startSession(config: ReadableMap, promise: Promise)
    @ReactMethod abstract fun stopSession(promise: Promise)
    @ReactMethod abstract fun refreshNow()
    @ReactMethod abstract fun getState(promise: Promise)
    @ReactMethod abstract fun setLocation(location: ReadableMap?)
    @ReactMethod abstract fun setServerTime(serverTimeMillis: Double)
    @ReactMethod abstract fun refreshRemoteConfigNow()

    @ReactMethod abstract fun configureCredential(credentialJson: String, persist: Boolean, promise: Promise)
    @ReactMethod abstract fun restoreCredential(promise: Promise)
    @ReactMethod abstract fun clearCredential(promise: Promise)
    @ReactMethod abstract fun isCredentialConfigured(promise: Promise)

    @ReactMethod abstract fun runCheck(detectorId: String, promise: Promise)
    @ReactMethod abstract fun scanAll(promise: Promise)
    @ReactMethod abstract fun selfTest(promise: Promise)

    @ReactMethod abstract fun setHighRiskTransactionMode(enabled: Boolean)
    @ReactMethod abstract fun reportSession(accountId: String, sessionId: String, event: String, promise: Promise)
    @ReactMethod abstract fun reportTransaction(amount: String, currency: String, beneficiaryId: String, channel: String, promise: Promise)
    @ReactMethod abstract fun signTransaction(amount: String, currency: String, beneficiaryId: String, promise: Promise)

    @ReactMethod abstract fun setScreenshotProtection(enabled: Boolean, promise: Promise)
    @ReactMethod abstract fun clearClipboard(promise: Promise)
    @ReactMethod abstract fun getSdkInfo(promise: Promise)

    @ReactMethod abstract fun addListener(eventName: String)
    @ReactMethod abstract fun removeListeners(count: Double)

}
