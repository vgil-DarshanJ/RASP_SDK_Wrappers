import { normalizeRisk } from './native';
import type { RaspSignedTransaction } from './types';

export function normalizeSignedTransaction(raw: unknown): RaspSignedTransaction {
  const t = (raw ?? {}) as Record<string, unknown>;
  const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
  return {
    canonical: String(t.canonical ?? ''),
    signatureBase64: String(t.signatureBase64 ?? ''),
    counter: num(t.counter),
    nonce: String(t.nonce ?? ''),
    timestampMillis: num(t.timestampMillis),
    beneficiaryHash: String(t.beneficiaryHash ?? ''),
    bindingSha256: String(t.bindingSha256 ?? ''),
    deviceKeyId: String(t.deviceKeyId ?? ''),
    risk: normalizeRisk(t.risk),
  };
}
