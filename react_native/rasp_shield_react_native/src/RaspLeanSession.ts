import { BASIC_CONTROL_IDS, enabledDetectorIds } from './config';
import {
  isNativeAvailable,
  nativeModule,
  normalizeRisk,
  onNativeError,
  onNativeState,
  unavailableReason,
  unavailableResult,
  type Unsubscribe,
} from './native';
import type {
  DetectionResult,
  RaspLeanConfig,
  RaspLeanState,
  RaspLocationSnapshot,
  RaspSessionEvent,
  RaspSessionReport,
  RaspShieldErrorEvent,
  RaspSignedTransaction,
  RaspTransactionReport,
} from './types';
import { normalizeSignedTransaction } from './fraud';

export const INITIAL_STATE: RaspLeanState = Object.freeze({
  screenshotActive: null,
  usbConnected: null,
  usbDeviceCount: 0,
  usbDebuggingEnabled: null,
  developerModeEnabled: null,
  clipboardActive: null,
  clipboardChangeCount: 0,
  extendedDetectors: {},
  risk: null,
  locationHeartbeat: null,
  remoteConfigVersion: null,
  remoteConfigStatus: 'OFF',
  observedAtMillis: 0,
}) as RaspLeanState;

export type StateListener = (state: RaspLeanState) => void;
export type ErrorListener = (error: RaspShieldErrorEvent) => void;

/**
 * One running scan session: every detector you enabled is re-read on an
 * interval and every change is shipped to the dashboard by the native
 * engine (signed evidence envelopes) — JavaScript never touches the
 * credentials or the detection logic.
 *
 * Only ONE native session runs at a time. Starting a new one stops the
 * previous one; a stopped session's calls are no-ops.
 *
 * Without the native module (iOS today, a broken autolink) the session
 * still starts, but every enabled detector reads UNAVAILABLE with the
 * reason — never SECURE.
 */
export class RaspLeanSession {
  private listeners = new Set<StateListener>();
  private errorListeners = new Set<ErrorListener>();
  private unsubscribers: Unsubscribe[] = [];
  private stopped = false;
  private latest: RaspLeanState;

  private constructor(readonly config: RaspLeanConfig) {
    this.latest = RaspLeanSession.fallbackState(config);
  }

  static async start(config: RaspLeanConfig): Promise<RaspLeanSession> {
    const session = new RaspLeanSession(config);
    const native = nativeModule();
    if (!native) return session; // honest UNAVAILABLE state, see class doc
    session.unsubscribers.push(
      onNativeState((state) => session.accept(state)),
      onNativeError((error) => session.errorListeners.forEach((l) => l(error))),
    );
    try {
      await native.startSession(config as Object);
    } catch (e) {
      session.detach();
      throw e;
    }
    return session;
  }

  /** The latest state; before the first scan every enabled detector is absent. */
  get state(): RaspLeanState {
    return this.latest;
  }

  get isRunning(): boolean {
    return !this.stopped;
  }

  /** Calls `listener` on every state change; returns the unsubscribe function. */
  onState(listener: StateListener): Unsubscribe {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  onError(listener: ErrorListener): Unsubscribe {
    this.errorListeners.add(listener);
    return () => this.errorListeners.delete(listener);
  }

  /** Runs every enabled detector now instead of waiting for the interval. */
  refreshNow(): void {
    if (!this.stopped) nativeModule()?.refreshNow();
  }

  /** Asks the backend for a new signed remote config now (needs `remoteConfigEnabled`). */
  refreshRemoteConfigNow(): void {
    if (!this.stopped) nativeModule()?.refreshRemoteConfigNow();
  }

  /** Supplies (or, with `null`, withdraws) a location from your own location code. */
  setLocation(location: RaspLocationSnapshot | null): void {
    if (!this.stopped) nativeModule()?.setLocation(location as Object | null);
  }

  /** A trusted server time (e.g. an HTTP `Date` header) for `time_spoofing`. */
  setServerTime(serverTimeMillis: number): void {
    if (!this.stopped) nativeModule()?.setServerTime(serverTimeMillis);
  }

  /** Stricter profile for sensitive actions; recomputes the risk now. */
  setHighRiskTransactionMode(enabled: boolean): void {
    if (!this.stopped) nativeModule()?.setHighRiskTransactionMode(enabled);
  }

  /** Ids are hashed on the device (HMAC-SHA256 with the per-app salt) and never stored. */
  async reportSession(
    accountId: string,
    sessionId: string,
    event: RaspSessionEvent,
  ): Promise<RaspSessionReport> {
    const raw = (await this.requireNative().reportSession(accountId, sessionId, event)) as Record<string, unknown>;
    return {
      accountHash: String(raw.accountHash ?? ''),
      sessionHash: String(raw.sessionHash ?? ''),
      event: String(raw.event ?? event) as RaspSessionEvent,
      risk: normalizeRisk(raw.risk),
      sentToBackend: raw.sentToBackend === true,
    };
  }

  /** The amount stays on the device except inside the signed binding. */
  async reportTransaction(
    amount: string,
    currency: string,
    beneficiaryId: string,
    channel: string,
  ): Promise<RaspTransactionReport> {
    const raw = (await this.requireNative().reportTransaction(amount, currency, beneficiaryId, channel)) as Record<string, unknown>;
    return {
      transaction: normalizeSignedTransaction(raw.transaction),
      channel: String(raw.channel ?? channel),
      sentToBackend: raw.sentToBackend === true,
    };
  }

  /** Signs the transaction binding with the device key; nothing is sent. */
  async signTransaction(amount: string, currency: string, beneficiaryId: string): Promise<RaspSignedTransaction> {
    return normalizeSignedTransaction(await this.requireNative().signTransaction(amount, currency, beneficiaryId));
  }

  /** Stops scanning and shipping. Safe to call more than once. */
  async stop(): Promise<void> {
    if (this.stopped) return;
    this.detach();
    await nativeModule()?.stopSession();
  }

  // ── internals ──────────────────────────────────────────────────────────

  private requireNative() {
    const native = nativeModule();
    if (!native) throw new Error(unavailableReason());
    if (this.stopped) throw new Error('This RASP session was stopped');
    return native;
  }

  private detach(): void {
    this.stopped = true;
    this.unsubscribers.forEach((u) => u());
    this.unsubscribers = [];
  }

  private accept(state: RaspLeanState): void {
    if (this.stopped) return;
    this.latest = state;
    this.listeners.forEach((l) => l(state));
  }

  /** The state when no native engine exists: everything enabled is UNAVAILABLE. */
  private static fallbackState(config: RaspLeanConfig): RaspLeanState {
    if (isNativeAvailable()) return INITIAL_STATE;
    const extended: Record<string, DetectionResult> = {};
    for (const id of enabledDetectorIds(config)) {
      if (!BASIC_CONTROL_IDS.includes(id)) extended[id] = unavailableResult(id);
    }
    return { ...INITIAL_STATE, extendedDetectors: extended, observedAtMillis: Date.now() };
  }
}
