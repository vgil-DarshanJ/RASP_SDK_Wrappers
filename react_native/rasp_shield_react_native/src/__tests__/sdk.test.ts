import { EventEmitter } from 'events';
import {
  __setEmitterForTests,
  __setNativeModuleForTests,
  ERROR_EVENT,
  SDK_VERSION,
  STATE_EVENT,
  normalizeResult,
  normalizeState,
} from '../native';
import type { Spec } from '../specs/NativeRaspShield';
import { DETECTOR_FLAGS, configFromDetectors, enabledDetectorIds } from '../config';
import { DETECTORS } from '../detectors';
import { RaspLeanSession } from '../RaspLeanSession';
import { RaspShieldCore } from '../RaspShieldCore';
import { RaspEventShipper } from '../RaspEventShipper';

const bus = new EventEmitter();

function fakeNative(overrides: Partial<Record<keyof Spec, unknown>> = {}): Spec {
  const fn = (v?: unknown) => jest.fn(async () => v);
  return {
    startSession: fn(),
    stopSession: fn(),
    refreshNow: jest.fn(),
    refreshRemoteConfigNow: jest.fn(),
    getState: fn(null),
    setLocation: jest.fn(),
    setServerTime: jest.fn(),
    configureCredential: fn(true),
    restoreCredential: fn(false),
    clearCredential: fn(),
    isCredentialConfigured: fn(false),
    runCheck: fn({ detectorId: 'frida', status: 'SECURE' }),
    scanAll: fn([{ detectorId: 'frida', status: 'SECURE' }]),
    selfTest: fn({ results: [], criticalReflectionIntact: true }),
    setHighRiskTransactionMode: jest.fn(),
    reportSession: fn({ accountHash: 'a', sessionHash: 's', event: 'login', risk: { verdict: 'LOW', score: 0 } }),
    reportTransaction: fn({ transaction: { counter: 3, risk: {} }, channel: 'upi', sentToBackend: true }),
    signTransaction: fn({ canonical: 'c', counter: 1 }),
    setScreenshotProtection: fn(true),
    clearClipboard: fn(true),
    getSdkInfo: fn({ sdkVersion: '1.1.0', engineVersion: '1.1.0', platform: 'android', nativeAvailable: true }),
    addListener: jest.fn(),
    removeListeners: jest.fn(),
    ...overrides,
  } as unknown as Spec;
}

beforeEach(() => {
  bus.removeAllListeners();
  __setEmitterForTests({
    addListener: (event, listener) => {
      bus.on(event, listener);
      return { remove: () => bus.off(event, listener) };
    },
  });
});

afterEach(() => {
  __setNativeModuleForTests(undefined);
  __setEmitterForTests(null);
});

describe('catalog consistency', () => {
  it('has 43 detectors, each with one config flag', () => {
    expect(DETECTORS).toHaveLength(43);
    expect(Object.keys(DETECTOR_FLAGS)).toHaveLength(43);
    for (const d of DETECTORS) expect(DETECTOR_FLAGS[d.id]).toBeDefined();
  });

  it('configFromDetectors turns on exactly the listed detectors', () => {
    const config = configFromDetectors(['frida', 'vpn'], { pollIntervalMillis: 5000 });
    expect(enabledDetectorIds(config).sort()).toEqual(['frida', 'vpn']);
    expect(config.rootDetection).toBe(false);
    expect(config.pollIntervalMillis).toBe(5000);
  });

  it('keeps SDK_VERSION equal to package.json', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    expect(SDK_VERSION).toBe(require('../../package.json').version);
  });
});

describe('normalization never widens to safe', () => {
  it('maps an unknown status to ERROR', () => {
    expect(normalizeResult({ detectorId: 'x', status: 'FUTURE_STATE' }).status).toBe('ERROR');
    expect(normalizeResult(null).status).toBe('ERROR');
  });

  it('keeps malformed state fields at safe defaults', () => {
    const s = normalizeState({ usbConnected: 'yes', remoteConfigStatus: 'BOGUS', risk: { verdict: 'FINE' } });
    expect(s.usbConnected).toBeNull();
    expect(s.remoteConfigStatus).toBe('OFF');
    expect(s.risk?.verdict).toBe('UNKNOWN');
    expect(s.risk?.score).toBeNull();
  });
});

describe('RaspLeanSession', () => {
  it('starts the native session and delivers state changes', async () => {
    const native = fakeNative();
    __setNativeModuleForTests(native);
    const session = await RaspLeanSession.start({ rootDetection: true });
    expect(native.startSession).toHaveBeenCalledWith({ rootDetection: true });

    const seen: string[] = [];
    session.onState((s) => seen.push(s.extendedDetectors.root_jailbreak?.status ?? 'none'));
    bus.emit(STATE_EVENT, { extendedDetectors: { root_jailbreak: { detectorId: 'root_jailbreak', status: 'DETECTED' } } });
    expect(seen).toEqual(['DETECTED']);
    expect(session.state.extendedDetectors.root_jailbreak?.status).toBe('DETECTED');
  });

  it('forwards native errors and stops cleanly', async () => {
    const native = fakeNative();
    __setNativeModuleForTests(native);
    const session = await RaspLeanSession.start({ fridaDetection: true });
    const errors: string[] = [];
    session.onError((e) => errors.push(`${e.source}:${e.message}`));
    bus.emit(ERROR_EVENT, { source: 'frida', message: 'boom' });
    expect(errors).toEqual(['frida:boom']);

    await session.stop();
    await session.stop(); // idempotent
    expect(native.stopSession).toHaveBeenCalledTimes(1);
    bus.emit(STATE_EVENT, { usbConnected: true });
    expect(session.state.usbConnected).toBeNull();
    await expect(session.reportSession('a', 's', 'login')).rejects.toThrow('stopped');
  });

  it('rejects start when the native session fails to start', async () => {
    __setNativeModuleForTests(fakeNative({ startSession: jest.fn(async () => { throw new Error('nope'); }) }));
    await expect(RaspLeanSession.start({})).rejects.toThrow('nope');
  });

  it('without the native module reports every enabled detector UNAVAILABLE, never SECURE', async () => {
    __setNativeModuleForTests(null);
    const session = await RaspLeanSession.start(configFromDetectors(['frida', 'vpn', 'usb_connection']));
    const ext = session.state.extendedDetectors;
    expect(Object.keys(ext).sort()).toEqual(['frida', 'vpn']);
    expect(ext.frida?.status).toBe('UNAVAILABLE');
    expect(ext.frida?.reason).toBeTruthy();
    expect(session.state.usbConnected).toBeNull();
    await expect(session.signTransaction('1', 'INR', 'b')).rejects.toThrow();
  });

  it('normalizes risk and transaction reports', async () => {
    __setNativeModuleForTests(fakeNative());
    const session = await RaspLeanSession.start({ sessionRiskScoring: true });
    const report = await session.reportTransaction('10', 'INR', 'b', 'upi');
    expect(report.transaction.counter).toBe(3);
    expect(report.transaction.risk.verdict).toBe('UNKNOWN');
    expect(report.sentToBackend).toBe(true);
    const login = await session.reportSession('a', 's', 'login');
    expect(login.risk.verdict).toBe('LOW');
  });
});

describe('RaspShieldCore / RaspEventShipper', () => {
  it('returns UNAVAILABLE results without the native module', async () => {
    __setNativeModuleForTests(null);
    expect((await RaspShieldCore.check('frida')).status).toBe('UNAVAILABLE');
    expect(await RaspShieldCore.scanAll()).toEqual([]);
    expect((await RaspShieldCore.getSdkInfo()).nativeAvailable).toBe(false);
    expect(await RaspEventShipper.isConfigured()).toBe(false);
    await expect(RaspEventShipper.configure('{}')).rejects.toThrow();
  });

  it('passes the credential JSON through and persists by default', async () => {
    const native = fakeNative();
    __setNativeModuleForTests(native);
    const ok = await RaspEventShipper.configure({
      organization_id: 'o',
      application_id: 'a',
      api_key: 'k',
      api_secret: 's',
      ingestion_url: 'http://x/v1/events',
    });
    expect(ok).toBe(true);
    const [json, persist] = (native.configureCredential as jest.Mock).mock.calls[0];
    expect(JSON.parse(json).api_key).toBe('k');
    expect(persist).toBe(true);
  });

  it('reads sdk info and self-test from the native module', async () => {
    __setNativeModuleForTests(fakeNative());
    expect((await RaspShieldCore.getSdkInfo()).engineVersion).toBe('1.1.0');
    expect((await RaspShieldCore.selfTest()).criticalReflectionIntact).toBe(true);
  });
});
