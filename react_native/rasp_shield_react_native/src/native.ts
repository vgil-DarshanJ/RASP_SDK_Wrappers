/**
 * The ONE place the JS layer touches the native module. Everything else
 * goes through these helpers, which:
 *   - cast codegen's untyped `Object` results to the public types, and
 *   - degrade honestly when the native module is absent (iOS today, a
 *     broken autolink, a Jest environment): nothing throws into the host
 *     app, and nothing ever pretends a check passed.
 */
import { NativeEventEmitter, Platform } from 'react-native';
import NativeRaspShield, { type Spec } from './specs/NativeRaspShield';
import type { DetectionResult, RaspShieldErrorEvent, RaspLeanState } from './types';

export const STATE_EVENT = 'RaspShield.stateChanged';
export const ERROR_EVENT = 'RaspShield.error';

/** Kept in sync with package.json by `scripts/sync-shared-session.js --check`. */
export const SDK_VERSION = '1.0.0';

let nativeOverride: Spec | null | undefined;

/** Test seam — lets unit tests inject a fake native module. */
export function __setNativeModuleForTests(module: Spec | null | undefined): void {
  nativeOverride = module;
  emitter = null;
}

export function nativeModule(): Spec | null {
  if (nativeOverride !== undefined) return nativeOverride;
  return NativeRaspShield ?? null;
}

export function isNativeAvailable(): boolean {
  return nativeModule() !== null;
}

export function unavailableReason(): string {
  if (Platform.OS !== 'android') {
    return `RASP Shield's native detection engine is Android-only today; not available on ${Platform.OS}`;
  }
  return (
    'RASP Shield native module is not linked. Rebuild the Android app after installing ' +
    'rasp-shield-react-native (autolinking), and make sure JitPack is in your Gradle repositories.'
  );
}

let emitter: NativeEventEmitter | null = null;

function eventEmitter(): NativeEventEmitter | null {
  const module = nativeModule();
  if (!module) return null;
  if (!emitter) {
    // Passing the module lets NativeEventEmitter call addListener /
    // removeListeners on it, which Android requires to avoid a warning.
    emitter = new NativeEventEmitter(module as never);
  }
  return emitter;
}

export type Unsubscribe = () => void;

export function onNativeState(listener: (state: RaspLeanState) => void): Unsubscribe {
  const e = eventEmitter();
  if (!e) return () => {};
  const sub = e.addListener(STATE_EVENT, (payload: unknown) => {
    listener(normalizeState(payload));
  });
  return () => sub.remove();
}

export function onNativeError(listener: (error: RaspShieldErrorEvent) => void): Unsubscribe {
  const e = eventEmitter();
  if (!e) return () => {};
  const sub = e.addListener(ERROR_EVENT, (payload: unknown) => {
    const p = (payload ?? {}) as Partial<RaspShieldErrorEvent>;
    listener({ source: String(p.source ?? 'unknown'), message: String(p.message ?? '') });
  });
  return () => sub.remove();
}

// ── Normalization: native maps → public types ─────────────────────────────

const STATUSES = new Set(['SECURE', 'DETECTED', 'UNAVAILABLE', 'UNKNOWN', 'ERROR']);

export function normalizeResult(raw: unknown): DetectionResult {
  const r = (raw ?? {}) as Record<string, unknown>;
  const status = String(r.status ?? 'ERROR');
  return {
    detectorId: String(r.detectorId ?? 'unknown'),
    // An unrecognized status from a future engine version is surfaced as
    // ERROR, never silently widened into SECURE.
    status: (STATUSES.has(status) ? status : 'ERROR') as DetectionResult['status'],
    evidence: Array.isArray(r.evidence)
      ? (r.evidence as Array<Record<string, unknown>>).map((e) => ({
          key: String(e?.key ?? ''),
          value: (e?.value ?? null) as DetectionResult['evidence'][number]['value'],
          note: (e?.note as string | null | undefined) ?? null,
        }))
      : [],
    reason: typeof r.reason === 'string' ? r.reason : null,
    observedAtMillis: typeof r.observedAtMillis === 'number' ? r.observedAtMillis : Date.now(),
  };
}

function boolOrNull(v: unknown): boolean | null {
  return typeof v === 'boolean' ? v : null;
}

function numOrZero(v: unknown): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

export function normalizeState(raw: unknown): RaspLeanState {
  const s = (raw ?? {}) as Record<string, unknown>;
  const extendedRaw = (s.extendedDetectors ?? {}) as Record<string, unknown>;
  const extendedDetectors: RaspLeanState['extendedDetectors'] = {};
  for (const [id, value] of Object.entries(extendedRaw)) {
    (extendedDetectors as Record<string, DetectionResult>)[id] = normalizeResult(value);
  }
  return {
    screenshotActive: boolOrNull(s.screenshotActive),
    usbConnected: boolOrNull(s.usbConnected),
    usbDeviceCount: numOrZero(s.usbDeviceCount),
    usbDebuggingEnabled: boolOrNull(s.usbDebuggingEnabled),
    developerModeEnabled: boolOrNull(s.developerModeEnabled),
    clipboardActive: boolOrNull(s.clipboardActive),
    clipboardChangeCount: numOrZero(s.clipboardChangeCount),
    extendedDetectors,
    observedAtMillis: numOrZero(s.observedAtMillis),
  };
}

export function unavailableResult(detectorId: string, reason = unavailableReason()): DetectionResult {
  return {
    detectorId,
    status: 'UNAVAILABLE',
    evidence: [],
    reason,
    observedAtMillis: Date.now(),
  };
}
