import { useCallback, useEffect, useRef, useState } from 'react';
import { INITIAL_STATE, RaspLeanSession } from './RaspLeanSession';
import type { RaspLeanConfig, RaspLeanState, RaspShieldErrorEvent } from './types';

export interface UseRaspSession {
  /** The latest state; `INITIAL_STATE` until the first scan. */
  state: RaspLeanState;
  /** `true` while the session (re)starts. */
  starting: boolean;
  /** The last start failure or native error, if any. */
  error: string | null;
  session: RaspLeanSession | null;
  refresh: () => void;
}

/**
 * Runs a session for as long as the component is mounted and `config` is
 * not `null`. A config with different content restarts it (compared by
 * value, so passing a new object with the same flags does not).
 */
export function useRaspSession(config: RaspLeanConfig | null): UseRaspSession {
  const [state, setState] = useState<RaspLeanState>(INITIAL_STATE);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [session, setSession] = useState<RaspLeanSession | null>(null);
  const sessionRef = useRef<RaspLeanSession | null>(null);
  const key = config ? JSON.stringify(config) : null;

  useEffect(() => {
    if (key === null) return undefined;
    let cancelled = false;
    let started: RaspLeanSession | null = null;
    const stopPrevious = sessionRef.current?.stop().catch(() => {});
    setStarting(true);
    setError(null);
    (async () => {
      await stopPrevious;
      try {
        const next = await RaspLeanSession.start(JSON.parse(key) as RaspLeanConfig);
        if (cancelled) {
          await next.stop();
          return;
        }
        started = next;
        sessionRef.current = next;
        next.onState(setState);
        next.onError((e: RaspShieldErrorEvent) => setError(`${e.source}: ${e.message}`));
        setState(next.state);
        setSession(next);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!cancelled) setStarting(false);
      }
    })();
    return () => {
      cancelled = true;
      started?.stop().catch(() => {});
    };
  }, [key]);

  const refresh = useCallback(() => sessionRef.current?.refreshNow(), []);
  return { state, starting, error, session, refresh };
}
