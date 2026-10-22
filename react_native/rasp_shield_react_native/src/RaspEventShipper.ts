import { nativeModule, unavailableReason } from './native';
import type { RaspCredential } from './types';

/**
 * The `credential.json` from the dashboard (organization, application,
 * API key + secret, ingestion URL). The secret goes straight to the native
 * engine, which signs every event with it; with `persist` it is stored in
 * encrypted storage and never comes back to JavaScript.
 */
export const RaspEventShipper = {
  /** `false` when the JSON is not a valid credential. */
  async configure(credential: RaspCredential | string, options: { persist?: boolean } = {}): Promise<boolean> {
    const native = nativeModule();
    if (!native) throw new Error(unavailableReason());
    const json = typeof credential === 'string' ? credential : JSON.stringify(credential);
    return native.configureCredential(json, options.persist ?? true);
  },

  /** Loads the credential saved by `configure(..., { persist: true })`; `false` when there is none. */
  async restore(): Promise<boolean> {
    return (await nativeModule()?.restoreCredential()) ?? false;
  },

  /** Forgets the credential, in memory and in storage. */
  async clear(): Promise<void> {
    await nativeModule()?.clearCredential();
  },

  async isConfigured(): Promise<boolean> {
    return (await nativeModule()?.isCredentialConfigured()) ?? false;
  },
};
