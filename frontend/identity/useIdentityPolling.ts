import { useEffect, useRef, useState } from 'react';
import { identityError } from './components.js';

/** Read progress serially, with a finite wait and no continuation after navigation. */
export function useIdentityPolling({ enabled, scope, poll, intervalMs = 3000, maxIntervalMs = 10000, timeoutMs = 600000 }: {
  enabled: boolean;
  scope: string;
  poll: (isCurrent: () => boolean) => Promise<void>;
  intervalMs?: number;
  maxIntervalMs?: number;
  timeoutMs?: number;
}) {
  const latest = useRef(poll); latest.current = poll;
  const active = useRef<{ cancel: () => void } | null>(null);
  const running = useRef<Promise<void> | null>(null);
  const [generation, setGeneration] = useState(0);
  const [error, setError] = useState(''), [paused, setPaused] = useState(false);

  useEffect(() => {
    setError(''); setPaused(false);
    if (!enabled) return;
    let current = true, timer: ReturnType<typeof setTimeout> | undefined;
    let delay = intervalMs, failures = 0;
    const deadline = Date.now() + timeoutMs;
    const token = { cancel: () => { current = false; clearTimeout(timer); } };
    active.current = token;
    const isCurrent = () => current && active.current === token;
    const schedule = () => { if (isCurrent()) timer = setTimeout(tick, delay); };
    const tick = () => {
      if (!isCurrent()) return;
      if (Date.now() >= deadline) { setPaused(true); return; }
      if (running.current) { schedule(); return; }
      const request = (async () => {
        try {
          await latest.current(isCurrent);
          if (!isCurrent()) return;
          failures = 0; setError('');
          delay = Math.min(maxIntervalMs, Math.round(delay * 1.2));
        } catch (failure) {
          if (!isCurrent()) return;
          failures++;
          const code = failure && typeof failure === 'object' && 'code' in failure ? String(failure.code) : '';
          setError(identityError(failure));
          if (!['TRANSPORT', 'UNAVAILABLE', 'OFFLINE', 'RATE_LIMITED', 'CONFLICT', 'INCOMPLETE_KEYS'].includes(code) || failures >= 5) {
            setPaused(true); return;
          }
          delay = Math.min(60000, Math.max(10000, delay * 2));
        }
        schedule();
      })();
      running.current = request;
      void request.finally(() => { if (running.current === request) running.current = null; });
    };
    schedule();
    return () => { token.cancel(); if (active.current === token) active.current = null; };
  }, [enabled, scope, generation, intervalMs, maxIntervalMs, timeoutMs]);

  return {
    error, paused,
    retry: () => setGeneration(value => value + 1),
    // Call at the start of a visible action, with polling disabled while it runs.
    // Waiting prevents a prior status read overwriting a newly prepared draft.
    waitForIdle: async () => { active.current?.cancel(); await running.current; },
  };
}
