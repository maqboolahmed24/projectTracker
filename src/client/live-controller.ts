import { LIVE_FALLBACK_MS, liveCheckpoint, liveRequest, type LiveCheckpoint } from '../shared/live.js';
import { binary } from '../shared/contracts.js';
import { parseJsonStrict } from '../shared/json.js';
import { authOrigin } from './auth-controller.js';

export interface LiveSource { subscribe(onCheckpoint: (event: LiveCheckpoint) => void, onDisconnect: () => void): () => void }
/** Fetch streaming keeps CSRF and session credentials out of event URLs. */
export class HttpLiveSource implements LiveSource {
  readonly origin: string;
  constructor(origin: string, readonly workspaceId: string, readonly csrfToken: () => string | undefined,
    readonly fetcher: typeof fetch = globalThis.fetch) { this.origin = authOrigin(origin); liveRequest.parse({ workspaceId }); }
  subscribe(onCheckpoint: (event: LiveCheckpoint) => void, onDisconnect: () => void): () => void {
    const abort = new AbortController(); let closed = false, failed = false, watchdog: ReturnType<typeof setTimeout> | undefined;
    const disconnect = () => { if (!closed && !failed) { failed = true; abort.abort(); onDisconnect(); } };
    const reset = () => { if (watchdog) clearTimeout(watchdog); watchdog = setTimeout(disconnect, 20_000); };
    reset();
    void (async () => {
      try {
        const url = `${this.origin}/v1/work/live`;
        const response = await this.fetcher.call(globalThis, url, { method: 'POST', credentials: 'same-origin', mode: 'same-origin', redirect: 'error', cache: 'no-store', referrerPolicy: 'strict-origin', signal: abort.signal,
          headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream', 'X-CSRF-Token': binary(32).parse(this.csrfToken()) },
          body: JSON.stringify({ workspaceId: this.workspaceId }) });
        if (!response.ok || response.redirected || response.url !== url || !response.headers.get('content-type')?.startsWith('text/event-stream') || !response.body) throw new Error('Live unavailable');
        const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true }); let buffer = '';
        try {
          while (!closed && !failed) {
            const chunk = await reader.read(); if (chunk.done) break;
            buffer += decoder.decode(chunk.value, { stream: true });
            // Bounded protocol, never parse arbitrary business content or event code.
            if (buffer.length > 16_384) throw new Error('Live frame too large');
            let end: number;
            while ((end = buffer.indexOf('\n\n')) !== -1) {
              const frame = buffer.slice(0, end); buffer = buffer.slice(end + 2);
              const match = /^event: checkpoint\ndata: ([^\n]+)$/.exec(frame);
              if (!match) throw new Error('Live frame invalid');
              const checkpoint = liveCheckpoint.parse(parseJsonStrict(match[1]!));
              if (closed || failed) break;
              reset(); onCheckpoint(checkpoint);
            }
          }
        } finally { await reader.cancel().catch(() => {}); reader.releaseLock(); }
        disconnect();
      } catch { disconnect(); }
      finally { if (watchdog) clearTimeout(watchdog); }
    })();
    return () => { closed = true; if (watchdog) clearTimeout(watchdog); abort.abort(); };
  }
}

export type LiveInvalidationReason = 'open' | 'refocus' | 'write' | 'event' | 'midnight' | 'fallback' | 'disconnected' | 'hidden';
export interface LiveValue<T> { value: T; asOfUtc: string; nextMidnightUtc: string }
export interface LiveState<T> { status: 'unavailable' | 'last-known' | 'current'; value: T | null; asOfUtc: string | null; reason: LiveInvalidationReason }
export interface LiveClock { now(): number; setTimer(callback: () => void, delay: number): unknown; clearTimer(handle: unknown): void }
const clock: LiveClock = { now: () => performance.now(), setTimer: (callback, delay) => setTimeout(callback, delay), clearTimer: (handle) => clearTimeout(handle as ReturnType<typeof setTimeout>) };

/** Coalesces invalidations, rejects late results, and never refreshes hidden views. */
export class LiveRefreshController<T> {
  #state: LiveState<T> = { status: 'unavailable', value: null, asOfUtc: null, reason: 'open' };
  #active = false; #visible = true; #generation = 0; #disconnectEpoch = 0; #fingerprint: string | undefined;
  #unsubscribe: (() => void) | undefined; #abort: AbortController | undefined;
  #fallback: unknown; #midnight: unknown; #running = false; #dirty = false;
  readonly #clock: LiveClock;
  constructor(readonly options: {
    source: LiveSource; refresh: (signal: AbortSignal) => Promise<LiveValue<T>>;
    onChange: (state: LiveState<T>) => void; clock?: LiveClock;
  }) { this.#clock = options.clock ?? clock; }
  state(): LiveState<T> { return { ...this.#state }; }
  start(visible = true): void {
    if (this.#active) return; this.#active = true; this.#visible = visible;
    if (visible) { this.#connect(); this.#invalidate('open'); this.#scheduleFallback(); }
  }
  stop(): void {
    this.#active = false; this.#generation++; this.#dirty = false; this.#abort = undefined;
    this.#unsubscribe?.(); this.#unsubscribe = undefined; this.#fingerprint = undefined;
    this.#clearTimers(); this.#state = { status: 'unavailable', value: null, asOfUtc: null, reason: 'hidden' };
  }
  setVisible(visible: boolean): void {
    if (this.#visible === visible) return; this.#visible = visible;
    if (!this.#active) return;
    if (!visible) { this.#invalidate('hidden'); this.#clearTimers(); this.#unsubscribe?.(); this.#unsubscribe = undefined; this.#fingerprint = undefined; }
    else { this.#connect(); this.#invalidate('refocus'); this.#scheduleFallback(); }
  }
  refocus(): void { if (this.#visible) this.#invalidate('refocus'); }
  relevantWrite(): void { this.#invalidate('write'); }
  /** Browser hooks are optional so the same headless controller is testable. */
  attachLifecycle(page: Document = document, view: Window = window): () => void {
    const visibility = () => this.setVisible(page.visibilityState === 'visible'), focus = () => this.refocus();
    page.addEventListener('visibilitychange', visibility); view.addEventListener('focus', focus);
    this.start(page.visibilityState === 'visible');
    return () => { page.removeEventListener('visibilitychange', visibility); view.removeEventListener('focus', focus); this.stop(); };
  }
  #clearTimers(): void {
    if (this.#fallback !== undefined) this.#clock.clearTimer(this.#fallback);
    if (this.#midnight !== undefined) this.#clock.clearTimer(this.#midnight);
    this.#fallback = undefined; this.#midnight = undefined;
  }
  #emit(): void { this.options.onChange(this.state()); }
  #connect(): void {
    if (this.#unsubscribe || !this.#active || !this.#visible) return;
    this.#unsubscribe = this.options.source.subscribe((event) => {
      if (!this.#active || !this.#visible || event.fingerprint === this.#fingerprint) return;
      this.#fingerprint = event.fingerprint; this.#invalidate('event');
    }, () => {
      this.#unsubscribe?.(); this.#unsubscribe = undefined; this.#fingerprint = undefined;
      if (!this.#active) return;
      // Losing the live channel makes a concurrent HTTP read last-known, but
      // does not cancel that independent read or erase a queued invalidation.
      this.#disconnectEpoch++;
      if (this.#midnight !== undefined) this.#clock.clearTimer(this.#midnight); this.#midnight = undefined;
      this.#state = { ...this.#state, status: this.#state.value === null ? 'unavailable' : 'last-known', reason: 'disconnected' }; this.#emit();
    });
  }
  #invalidate(reason: LiveInvalidationReason, refresh = true): void {
    if (!this.#active) return;
    // Refresh invalidation is not an authentication cancellation. The shared
    // crypto Worker deliberately locks on abort; let an in-flight read finish
    // and discard its generation instead of locking the user's whole session.
    this.#generation++;
    if (this.#midnight !== undefined) this.#clock.clearTimer(this.#midnight); this.#midnight = undefined;
    this.#state = { ...this.#state, status: this.#state.value === null ? 'unavailable' : 'last-known', reason }; this.#emit();
    this.#dirty = refresh && this.#visible;
    if (this.#dirty) void this.#refresh();
  }
  #scheduleFallback(): void {
    if (this.#fallback !== undefined) this.#clock.clearTimer(this.#fallback);
    if (!this.#active || !this.#visible) return;
    this.#fallback = this.#clock.setTimer(() => { this.#fallback = undefined; this.#connect(); this.#invalidate('fallback'); this.#scheduleFallback(); }, LIVE_FALLBACK_MS);
  }
  async #refresh(): Promise<void> {
    if (this.#running || !this.#active || !this.#visible || !this.#dirty) return;
    this.#running = true; this.#dirty = false;
    const generation = this.#generation, disconnectEpoch = this.#disconnectEpoch, abort = new AbortController(), began = this.#clock.now(); this.#abort = abort;
    try {
      const result = await this.options.refresh(abort.signal);
      if (abort.signal.aborted || generation !== this.#generation || !this.#active || !this.#visible) return;
      // Server UTC anchors the deadline; local wall-clock skew cannot change it.
      const until = Date.parse(result.nextMidnightUtc) - Date.parse(result.asOfUtc) - Math.max(0, this.#clock.now() - began);
      if (!Number.isFinite(until) || until <= 0 || until > 49 * 60 * 60_000) throw new Error('Invalid reporting clock');
      this.#state = { status: disconnectEpoch === this.#disconnectEpoch ? 'current' : 'last-known', value: result.value, asOfUtc: result.asOfUtc, reason: this.#state.reason }; this.#emit();
      this.#midnight = this.#clock.setTimer(() => { this.#midnight = undefined; this.#invalidate('midnight'); }, until);
    } catch {
      if (generation === this.#generation && this.#active) {
        this.#state = { ...this.#state, status: this.#state.value === null ? 'unavailable' : 'last-known', reason: 'disconnected' }; this.#emit();
      }
    } finally {
      if (this.#abort === abort) this.#abort = undefined;
      this.#running = false;
      if (this.#dirty) void this.#refresh();
    }
  }
}
