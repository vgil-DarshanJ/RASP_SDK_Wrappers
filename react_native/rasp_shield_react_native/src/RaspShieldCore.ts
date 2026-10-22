import { Platform } from 'react-native';
import {
  SDK_VERSION,
  isNativeAvailable,
  nativeModule,
  normalizeResult,
  unavailableReason,
  unavailableResult,
} from './native';
import type { DetectionResult, DetectorId, RaspSdkInfo, RaspSelfTestReport } from './types';

const strings = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : []);

/**
 * One-shot calls: run now, return, ship nothing, start no timer. For a
 * continuously watching, dashboard-reporting setup use `RaspLeanSession`.
 * Without the native module every call returns UNAVAILABLE — never SECURE.
 */
export const RaspShieldCore = {
  /** Runs the whole one-shot catalog once (real network I/O: seconds, not ms). */
  async scanAll(): Promise<DetectionResult[]> {
    const native = nativeModule();
    if (!native) return [];
    return (await native.scanAll()).map(normalizeResult);
  },

  /** One detector's result from a full scan. Detectors that only exist inside a session report UNAVAILABLE. */
  async check(detectorId: DetectorId | string): Promise<DetectionResult> {
    const native = nativeModule();
    if (!native) return unavailableResult(detectorId);
    return normalizeResult(await native.runCheck(detectorId));
  },

  /** Run on your RELEASE build in CI: catches R8 stripping classes the hook detector inspects. */
  async selfTest(): Promise<RaspSelfTestReport> {
    const native = nativeModule();
    if (!native) {
      return { results: [], criticalReflectionIntact: false, erroredDetectorIds: [], unavailableDetectorIds: [] };
    }
    const raw = (await native.selfTest()) as Record<string, unknown>;
    return {
      results: Array.isArray(raw.results) ? raw.results.map(normalizeResult) : [],
      criticalReflectionIntact: raw.criticalReflectionIntact === true,
      erroredDetectorIds: strings(raw.erroredDetectorIds),
      unavailableDetectorIds: strings(raw.unavailableDetectorIds),
    };
  },

  /** Turns FLAG_SECURE on or off for the current screen; resolves with the real window state (`null` if unreadable). */
  async setScreenshotProtection(enabled: boolean): Promise<boolean | null> {
    return (await nativeModule()?.setScreenshotProtection(enabled)) ?? null;
  },

  /** Empties the clipboard; `false` when there was nothing to do or it failed. */
  async clearClipboard(): Promise<boolean> {
    return (await nativeModule()?.clearClipboard()) ?? false;
  },

  async getSdkInfo(): Promise<RaspSdkInfo> {
    const native = nativeModule();
    if (!native) {
      return {
        sdkVersion: SDK_VERSION,
        engineVersion: null,
        platform: Platform.OS,
        nativeAvailable: false,
        osVersion: null,
        apiLevel: null,
      };
    }
    const raw = (await native.getSdkInfo()) as Partial<RaspSdkInfo>;
    return {
      sdkVersion: String(raw.sdkVersion ?? SDK_VERSION),
      engineVersion: raw.engineVersion ?? null,
      platform: String(raw.platform ?? Platform.OS),
      nativeAvailable: raw.nativeAvailable === true,
      osVersion: raw.osVersion ?? null,
      apiLevel: typeof raw.apiLevel === 'number' ? raw.apiLevel : null,
    };
  },

  isNativeAvailable,
  unavailableReason,
};
