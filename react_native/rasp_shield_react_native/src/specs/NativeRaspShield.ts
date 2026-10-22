/**
 * TurboModule spec — the typed contract between the JS layer and the
 * native Android module (`RaspShieldModule.kt`). React Native's codegen
 * reads THIS file (see `codegenConfig` in package.json) and generates the
 * abstract `NativeRaspShieldSpec` Java class the Kotlin module implements,
 * so a signature mismatch between the two sides is a compile error, not a
 * runtime crash.
 *
 * Codegen only understands a restricted TypeScript subset: `Object` is a
 * free-form map (ReadableMap on Android). The strongly-typed shapes live
 * in `../types.ts`; `../native.ts` casts between the two in exactly one
 * place.
 *
 * Not exported from the package root — app code uses `RaspLeanSession`,
 * `RaspEventShipper` and `RaspShieldCore` instead.
 */
import type { TurboModule } from 'react-native';
import { TurboModuleRegistry } from 'react-native';

export interface Spec extends TurboModule {
  // ── Lean session (config-driven polling + automatic event shipping) ──
  startSession(config: Object): Promise<void>;
  stopSession(): Promise<void>;
  refreshNow(): void;
  getState(): Promise<Object | null>;
  setLocation(location: Object | null): void;
  setServerTime(serverTimeMillis: number): void;
  refreshRemoteConfigNow(): void;

  // ── Event shipping credential (credential.json from the dashboard) ──
  configureCredential(credentialJson: string, persist: boolean): Promise<boolean>;
  restoreCredential(): Promise<boolean>;
  clearCredential(): Promise<void>;
  isCredentialConfigured(): Promise<boolean>;

  // ── One-shot detector calls (no polling, no shipping) ──
  runCheck(detectorId: string): Promise<Object>;
  scanAll(): Promise<Array<Object>>;
  selfTest(): Promise<Object>;

  // ── Session risk / fraud (needs sessionRiskScoring in the config) ──
  setHighRiskTransactionMode(enabled: boolean): void;
  reportSession(accountId: string, sessionId: string, event: string): Promise<Object>;
  reportTransaction(
    amount: string,
    currency: string,
    beneficiaryId: string,
    channel: string,
  ): Promise<Object>;
  signTransaction(amount: string, currency: string, beneficiaryId: string): Promise<Object>;

  // ── Direct controls ──
  setScreenshotProtection(enabled: boolean): Promise<boolean | null>;
  clearClipboard(): Promise<boolean>;
  getSdkInfo(): Promise<Object>;

  // ── Required by NativeEventEmitter ──
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

/**
 * `get`, not `getEnforcing`: on a platform with no native implementation
 * (iOS today, or a misconfigured Android build) this returns `null`
 * instead of throwing at import time, so the JS layer can report every
 * detector as UNAVAILABLE — never crash the host app, never fake SECURE.
 */
export default TurboModuleRegistry.get<Spec>('RaspShield');
