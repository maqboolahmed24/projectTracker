import assert from 'node:assert/strict';
import test from 'node:test';
import { LiveRefreshController, HttpLiveSource, type LiveClock, type LiveSource, type LiveState } from '../src/client/live-controller.js';
import type { LiveCheckpoint } from '../src/shared/live.js';

const flush = () => new Promise<void>((resolve) => setImmediate(resolve));
class Clock implements LiveClock {
  time = 0; serial = 0; timers = new Map<number, { at: number; callback: () => void }>();
  now = () => this.time;
  setTimer = (callback: () => void, delay: number) => { const id = ++this.serial; this.timers.set(id, { at: this.time + delay, callback }); return id; };
  clearTimer = (handle: unknown) => { this.timers.delete(handle as number); };
  async advance(ms: number) {
    const end = this.time + ms;
    while (true) {
      const next = [...this.timers].sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!next || next[1].at > end) break;
      this.time = next[1].at; this.timers.delete(next[0]); next[1].callback(); await flush();
    }
    this.time = end; await flush();
  }
}
class Source implements LiveSource {
  connected = 0; closed = 0; event: ((e: LiveCheckpoint) => void) | undefined; failed: (() => void) | undefined;
  subscribe(onEvent: (e: LiveCheckpoint) => void, onDisconnect: () => void) {
    this.connected++; this.event = onEvent; this.failed = onDisconnect;
    return () => { this.closed++; this.event = undefined; this.failed = undefined; };
  }
  emit(fingerprint: string) { this.event?.({ version: 1, fingerprint, observedAt: '2026-09-26T00:00:00.000Z' }); }
}
const value = (n: number, time = 0, until = 3_600_000) => ({ value: n, asOfUtc: new Date(Date.parse('2026-09-26T00:00:00Z') + time).toISOString(), nextMidnightUtc: new Date(Date.parse('2026-09-26T00:00:00Z') + time + until).toISOString() });

test('CP10 live: open, local writes, refocus and changed SSE invalidate; identical heartbeats do not repeat calculations', async () => {
  const clock = new Clock(), source = new Source(), states: LiveState<number>[] = []; let calls = 0;
  const live = new LiveRefreshController({ clock, source, refresh: async () => value(++calls, clock.now()), onChange: (state) => states.push(state) });
  live.start(); await flush(); assert.equal(calls, 1); assert.equal(live.state().status, 'current');
  source.emit('a'.repeat(64)); await flush(); assert.equal(calls, 2);
  source.emit('a'.repeat(64)); await flush(); assert.equal(calls, 2);
  live.relevantWrite(); await flush(); live.refocus(); await flush(); assert.equal(calls, 4);
  assert.deepEqual(states.filter((s) => s.status === 'last-known').map((s) => s.reason), ['event', 'write', 'refocus']);
  live.stop(); assert.equal(clock.timers.size, 0); assert.equal(source.closed, 1); assert.equal(live.state().value, null);
});

test('CP10 live: visible fallback runs at sixty seconds; hidden views stop polls and refocus fetches current state', async () => {
  const clock = new Clock(), source = new Source(); let calls = 0;
  const live = new LiveRefreshController({ clock, source, refresh: async () => value(++calls, clock.now()), onChange() {} });
  live.start(); await flush(); await clock.advance(59_999); assert.equal(calls, 1);
  await clock.advance(1); assert.equal(calls, 2);
  live.setVisible(false); assert.equal(live.state().status, 'last-known'); assert.equal(clock.timers.size, 0);
  await clock.advance(180_000); live.relevantWrite(); await flush(); assert.equal(calls, 2);
  live.setVisible(true); await flush(); assert.equal(calls, 3); assert.equal(source.connected, 2);
  live.stop();
});

test('CP10 live: next midnight is scheduled from server UTC despite a skewed local wall clock', async () => {
  const clock = new Clock(), source = new Source(); clock.time = 9_000_000; let calls = 0;
  const live = new LiveRefreshController({ clock, source, refresh: async () => value(++calls, 0, 5_000), onChange() {} });
  live.start(); await flush(); await clock.advance(4_999); assert.equal(calls, 1);
  await clock.advance(1); assert.equal(calls, 2); assert.equal(live.state().reason, 'midnight'); live.stop();
});

test('CP10 live: invalidation discards the stale response without aborting the shared crypto Worker, coalescing into one new read', async () => {
  const clock = new Clock(), source = new Source(); let calls = 0, release: (() => void) | undefined, oldSignal: AbortSignal | undefined;
  const live = new LiveRefreshController({ clock, source, refresh: async (signal) => {
    calls++; if (calls === 1) { oldSignal = signal; await new Promise<void>((resolve) => { release = resolve; }); return value(1); } return value(2);
  }, onChange() {} });
  live.start(); live.relevantWrite(); live.relevantWrite(); assert.equal(calls, 1); assert.equal(oldSignal?.aborted, false);
  release!(); await flush(); assert.equal(calls, 2); assert.equal(live.state().value, 2); live.stop();
});

test('CP10 live: a disconnect keeps only last-known values, reconnects with fallback, and never installs a stopped result', async () => {
  const clock = new Clock(), source = new Source(); let calls = 0, online = true;
  const live = new LiveRefreshController({ clock, source, refresh: async () => { calls++; if (!online) throw new Error('offline'); return value(calls, clock.now()); }, onChange() {} });
  live.start(); await flush(); online = false; source.failed!(); assert.equal(live.state().status, 'last-known'); assert.equal(live.state().value, 1);
  await clock.advance(60_000); assert.equal(calls, 2); assert.equal(live.state().status, 'last-known'); assert.equal(source.connected, 2);
  online = true; await clock.advance(60_000); assert.equal(live.state().status, 'current'); assert.equal(live.state().value, 3); live.stop();
  let release: (() => void) | undefined;
  const late = new LiveRefreshController({ clock, source, refresh: async () => { await new Promise<void>((resolve) => { release = resolve; }); return value(99); }, onChange() {} });
  late.start(); late.stop(); release!(); await flush(); assert.equal(late.state().value, null); assert.equal(clock.timers.size, 0);
});

test('CP10 live: disconnect during the initial HTTP read retains its result as last-known until bounded fallback', async () => {
  const clock = new Clock(), source = new Source(); let calls = 0, release: (() => void) | undefined, signal: AbortSignal | undefined;
  const live = new LiveRefreshController({ clock, source, refresh: async (readSignal) => {
    calls++; if (calls === 1) { signal = readSignal; await new Promise<void>((resolve) => { release = resolve; }); }
    return value(calls, clock.now());
  }, onChange() {} });
  live.start(); source.failed!(); assert.equal(live.state().status, 'unavailable'); assert.equal(signal?.aborted, false);
  release!(); await flush();
  assert.equal(live.state().value, 1); assert.equal(live.state().status, 'last-known'); assert.equal(live.state().reason, 'disconnected');
  await clock.advance(59_999); assert.equal(calls, 1); assert.equal(source.connected, 1);
  await clock.advance(1); assert.equal(calls, 2); assert.equal(source.connected, 2); assert.equal(live.state().status, 'current');
  live.stop(); assert.equal(clock.timers.size, 0);
});

test('CP10 live: disconnect preserves a queued changed-event read while still rejecting the superseded result', async () => {
  const clock = new Clock(), source = new Source(), installed: number[] = []; let calls = 0, release: (() => void) | undefined;
  const live = new LiveRefreshController({ clock, source, refresh: async () => {
    calls++; if (calls === 1) { await new Promise<void>((resolve) => { release = resolve; }); return value(1); }
    return value(2);
  }, onChange(state) { if (state.value !== null) installed.push(state.value); } });
  live.start(); source.emit('c'.repeat(64)); source.failed!(); release!(); await flush();
  assert.equal(calls, 2); assert.deepEqual(installed, [2]); assert.equal(live.state().status, 'current'); live.stop();
});

test('CP10 live: disconnected in-flight reads cannot install after a view is hidden or stopped', async () => {
  for (const finish of ['hidden', 'stopped'] as const) {
    const clock = new Clock(), source = new Source(); let release: (() => void) | undefined;
    const live = new LiveRefreshController({ clock, source, refresh: async () => {
      await new Promise<void>((resolve) => { release = resolve; }); return value(1);
    }, onChange() {} });
    live.start(); source.failed!();
    if (finish === 'hidden') live.setVisible(false); else live.stop();
    release!(); await flush(); assert.equal(live.state().value, null); assert.equal(clock.timers.size, 0); live.stop();
  }
});

test('CP10 live HTTP: strict metadata-only SSE uses cookie credentials and CSRF in a header; EOF reports disconnection', async () => {
  const workspaceId = '00000000-0000-4000-8000-000000000001', csrf = Buffer.alloc(32, 1).toString('base64url'), frames: LiveCheckpoint[] = [];
  let request: RequestInit | undefined, requested: string | undefined, disconnected = 0;
  const frame = { version: 1, fingerprint: 'b'.repeat(64), observedAt: '2026-09-26T00:00:00.000Z' };
  const fetcher: typeof fetch = async function(this: unknown, url, options) {
    assert.equal(this, globalThis);
    request = options; requested = String(url);
    const response = new Response(`event: checkpoint\ndata: ${JSON.stringify(frame)}\n\n`, { headers: { 'content-type': 'text/event-stream' } });
    Object.defineProperty(response, 'url', { value: requested }); return response;
  };
  const stop = new HttpLiveSource('https://test.example', workspaceId, () => csrf, fetcher).subscribe((event) => frames.push(event), () => { disconnected++; });
  await flush(); assert.equal(disconnected, 1); assert.deepEqual(frames, [frame]);
  assert.equal(requested, 'https://test.example/v1/work/live'); assert.equal(request?.credentials, 'same-origin'); assert.equal(request?.redirect, 'error');
  assert.deepEqual(JSON.parse(String(request?.body)), { workspaceId }); assert.equal((request?.headers as Record<string, string>)['X-CSRF-Token'], csrf); stop();
});

test('CP10 live HTTP: malformed, oversized and content-bearing events fail closed', async () => {
  for (const frame of ['event: checkpoint\ndata: {"version":1}\n\n', 'x'.repeat(16_385), `event: checkpoint\ndata: ${JSON.stringify({ version: 1, fingerprint: 'a'.repeat(64), observedAt: '2026-09-26T00:00:00.000Z', projectName: 'Private' })}\n\n`]) {
    let seen = 0, disconnected = 0;
    const fetcher: typeof fetch = async () => { const response = new Response(frame, { headers: { 'content-type': 'text/event-stream' } }); Object.defineProperty(response, 'url', { value: 'https://test.example/v1/work/live' }); return response; };
    const stop = new HttpLiveSource('https://test.example', '00000000-0000-4000-8000-000000000001', () => Buffer.alloc(32, 1).toString('base64url'), fetcher).subscribe(() => { seen++; }, () => { disconnected++; });
    await flush(); assert.equal(seen, 0); assert.equal(disconnected, 1); stop();
  }
});
