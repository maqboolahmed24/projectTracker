import { markSVG } from './mark.js';

export { markSVG };

const activeMarks = new WeakMap();

/** Animate the supplied logo paths without changing their settled geometry. */
export function animateMark(svg, { reducedMotion } = {}) {
  activeMarks.get(svg)?.cancel();
  const media = window.matchMedia('(prefers-reduced-motion: reduce)');
  const reduce = reducedMotion ?? media.matches;
  const bars = [...svg.querySelectorAll('.maqbool-segment')];
  const span = svg.viewBox.baseVal.width;
  const animations = [];
  const masks = [];
  const ns = 'http://www.w3.org/2000/svg';
  const definitions = document.createElementNS(ns, 'defs');
  const runId = `maqbool-motion-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
  const directions = { top: [-0.325, -0.50], left: [-0.50, 0.275], right: [0.50, 0.275] };
  const offsets = { top: 80, left: 340, right: 600 };
  if (!reduce) svg.prepend(definitions);

  for (const [index, bar] of bars.entries()) {
    const arm = bar.dataset.arm || 'top';
    const order = Number(bar.dataset.order || 0);
    const [x, y] = directions[arm] || directions.top;
    const delay = (offsets[arm] || 0) + order * 60;

    if (!reduce) {
      // The original arrival sequence is unchanged. Explicit endpoints let
      // each section reveal along its new triangular side; masks are temporary.
      const box = bar.getBBox();
      const start = bar.dataset.revealStart.split(' ').map(Number);
      const end = bar.dataset.revealEnd.split(' ').map(Number);
      const length = Math.hypot(end[0] - start[0], end[1] - start[1]);
      const revealWidth = Number(bar.dataset.revealWidth);
      const mask = document.createElementNS(ns, 'mask');
      mask.id = `${runId}-${index}`;
      mask.setAttribute('maskUnits', 'userSpaceOnUse');
      mask.setAttribute('x', String(box.x - revealWidth));
      mask.setAttribute('y', String(box.y - revealWidth));
      mask.setAttribute('width', String(box.width + revealWidth * 2));
      mask.setAttribute('height', String(box.height + revealWidth * 2));
      const line = document.createElementNS(ns, 'path');
      line.setAttribute('d', `M ${start.join(' ')} L ${end.join(' ')}`);
      line.setAttribute('fill', 'none');
      line.setAttribute('stroke', '#fff');
      line.setAttribute('stroke-width', String(revealWidth));
      line.setAttribute('stroke-linecap', 'round');
      line.setAttribute('stroke-dasharray', `${length} ${length + revealWidth * 2}`);
      mask.append(line);
      definitions.append(mask);
      const reference = `url(#${mask.id})`;
      masks.push({ bar, reference, previous: bar.getAttribute('mask') });
      bar.setAttribute('mask', reference);
      animations.push(line.animate(
        [{ strokeDashoffset: `${length + revealWidth}px` }, { strokeDashoffset: '0px' }],
        { duration: 1180, delay, easing: 'cubic-bezier(0.22, 0.61, 0.36, 1)', fill: 'both' },
      ));
    }

    animations.push(bar.animate(
      reduce
        ? [{ opacity: 0 }, { opacity: 1 }]
        : [
            { offset: 0, opacity: 0, transform: `translate(${x * span}px, ${y * span}px)` },
            { offset: 0.12, opacity: 1 },
            { offset: 1, opacity: 1, transform: 'translate(0px, 0px)' },
          ],
      {
        duration: reduce ? 160 : 1520,
        delay: reduce ? 0 : delay,
        easing: 'cubic-bezier(0.22, 0.8, 0.24, 1)',
        fill: 'both',
      },
    ));
  }

  // A preference changed during launch takes effect immediately.
  const onMotionChange = () => {
    if (media.matches) for (const animation of animations) animation.finish();
  };
  media.addEventListener('change', onMotionChange);
  function clear() {
    for (const animation of animations) animation.cancel();
    for (const { bar, reference, previous } of masks) {
      // A quick replay may already own the next mask by the time promises settle.
      if (bar.getAttribute('mask') !== reference) continue;
      if (previous === null) bar.removeAttribute('mask');
      else bar.setAttribute('mask', previous);
    }
    definitions.remove();
    media.removeEventListener('change', onMotionChange);
    if (activeMarks.get(svg) === handle) activeMarks.delete(svg);
  }
  const finished = Promise.all(animations.map((animation) => animation.finished.catch(() => {})))
    .then(clear);

  const handle = { finished, cancel: clear };
  activeMarks.set(svg, handle);
  return handle;
}

/**
 * Optional launch decoration. App readiness and error UI remain with the caller.
 * @param {{ready?: PromiseLike<unknown>, appRoot?: HTMLElement,
 * theme?: 'light'|'dark'|'auto', minDuration?: number, maxDuration?: number,
 * stylesheetUrl?: string|URL, logoTarget?: string}} options
 */
export function mountMaqboolLaunch(options = {}) {
  if (typeof document === 'undefined') throw new Error('Mount the launch screen in a browser.');
  if (!document.body) throw new Error('Mount the launch screen after <body> exists.');

  const {
    ready, appRoot, theme = 'light', minDuration = 2850,
    maxDuration = 10000, stylesheetUrl = new URL('./maqbool-launch.css', import.meta.url),
    logoTarget,
  } = options;
  if (!['light', 'dark', 'auto'].includes(theme)) throw new TypeError('Unknown launch theme.');
  if (!Number.isFinite(minDuration) || !Number.isFinite(maxDuration) ||
      minDuration < 0 || maxDuration <= minDuration) {
    throw new RangeError('Durations must be finite, with 0 <= minDuration < maxDuration.');
  }
  if (appRoot && (!(appRoot instanceof HTMLElement) || appRoot === document.body ||
      !document.body.contains(appRoot))) {
    throw new TypeError('appRoot must be an element inside this document body.');
  }

  const host = document.createElement('div');
  host.hidden = true;
  host.dataset.maqboolLaunch = '';
  host.dataset.theme = theme;
  host.dataset.phase = 'opening';
  const shadow = host.attachShadow({ mode: 'open' });
  const stylesheet = document.createElement('link');
  stylesheet.rel = 'stylesheet';
  stylesheet.href = String(stylesheetUrl);
  const backdrop = document.createElement('div');
  backdrop.className = 'maqbool-launch-backdrop';
  const stage = document.createElement('div');
  stage.className = 'maqbool-launch-stage';
  stage.innerHTML = markSVG;
  const svg = stage.querySelector('svg');
  svg.setAttribute('aria-hidden', 'true');
  svg.removeAttribute('role');
  const status = document.createElement('span');
  status.className = 'maqbool-launch-status';
  status.setAttribute('role', 'status');
  status.textContent = 'Opening Maqbool';
  shadow.append(stylesheet, backdrop, stage, status);

  const media = window.matchMedia('(prefers-reduced-motion: reduce)');
  const timers = new Map();
  const initiallyInert = appRoot?.inert;
  let ownsInert = false;
  let settled = false;
  let exiting = false;
  let entrance;
  let exitAnimation;
  let markExitAnimation;
  let destination;
  let previousVisibility;
  let releaseReady;
  let resolveFinished;
  const readySignal = new Promise((resolve) => { releaseReady = resolve; });
  const finished = new Promise((resolve) => { resolveFinished = resolve; });

  function pause(ms) {
    return new Promise((resolve) => {
      const id = setTimeout(() => { timers.delete(id); resolve(); }, ms);
      timers.set(id, resolve);
    });
  }

  function cleanup(reason, error) {
    if (settled) return;
    settled = true;
    host.remove();
    entrance?.cancel();
    exitAnimation?.cancel();
    markExitAnimation?.cancel();
    if (destination && destination.style.getPropertyValue('visibility') === 'hidden') {
      if (previousVisibility.value) destination.style.setProperty('visibility', previousVisibility.value, previousVisibility.priority);
      else destination.style.removeProperty('visibility');
    }
    clearTimeout(watchdog);
    for (const [id, resolve] of timers) { clearTimeout(id); resolve(); }
    timers.clear();
    releaseReady();
    releaseStyles();
    stylesheet.onload = stylesheet.onerror = null;
    media.removeEventListener('change', onMotionChange);
    window.removeEventListener('resize', onLayoutChange);
    window.removeEventListener('scroll', onLayoutChange, true);
    if (ownsInert) appRoot.inert = initiallyInert;
    resolveFinished(error ? { reason, error } : { reason });
  }

  function visibleDestination(element) {
    if (!(element instanceof HTMLElement) || !element.isConnected) return false;
    const box = element.getBoundingClientRect();
    if (box.width <= 0 || box.height <= 0 || box.left < 0 || box.top < 0 ||
        box.right > innerWidth || box.bottom > innerHeight) return false;
    for (let node = element; node instanceof HTMLElement; node = node.parentElement) {
      const style = getComputedStyle(node);
      if (style.display === 'none' || style.visibility !== 'visible' || Number(style.opacity) === 0) return false;
    }
    return true;
  }

  async function findDestination() {
    if (!logoTarget) return null;
    // Readiness can resolve just before React paints its entry screen. Give that
    // committed layout a bounded chance to appear, without extending the watchdog.
    const deadline = performance.now() + 240;
    do {
      const target = [...document.querySelectorAll(logoTarget)].find(visibleDestination);
      if (target) return target;
      await pause(16);
    } while (!settled && !media.matches && performance.now() < deadline);
    return null;
  }

  async function exit(reason, error) {
    if (settled || exiting) return;
    exiting = true;
    try {
      if (!host.hidden) {
        const target = reason === 'ready' && !media.matches ? await findDestination() : null;
        if (settled) return;
        if (target && !media.matches) {
          const from = stage.getBoundingClientRect(), to = target.getBoundingClientRect();
          // The destination image may have a square CSS box around a portrait
          // SVG. Uniform scaling and centre alignment preserve the exact mark.
          const scale = Math.min(to.width / from.width, to.height / from.height);
          const x = to.left + to.width / 2 - (from.left + from.width / 2);
          const y = to.top + to.height / 2 - (from.top + from.height / 2);
          destination = target;
          previousVisibility = { value: target.style.getPropertyValue('visibility'), priority: target.style.getPropertyPriority('visibility') };
          target.style.setProperty('visibility', 'hidden');
          host.dataset.phase = 'handoff';
          window.addEventListener('resize', onLayoutChange);
          window.addEventListener('scroll', onLayoutChange, { capture: true, passive: true });
          const duration = 720;
          markExitAnimation = stage.animate([
            { transform: 'translate3d(0, 0, 0) scale(1)' },
            { transform: `translate3d(${x}px, ${y}px, 0) scale(${scale})` },
          ], { duration, easing: 'cubic-bezier(0.22, 1, 0.36, 1)', fill: 'forwards' });
          exitAnimation = backdrop.animate([{ opacity: 1 }, { opacity: 0 }], {
            duration: 580, easing: 'cubic-bezier(0.22, 1, 0.36, 1)', fill: 'forwards',
          });
          // Keep the moving mark fully visible while the content underneath is
          // revealed. The settled corner mark takes over in the cleanup frame.
          await Promise.race([markExitAnimation.finished.catch(() => {}), pause(duration + 100)]);
          return;
        }
        host.dataset.phase = 'fading';
        const duration = media.matches ? 120 : 480;
        if (!media.matches) {
          markExitAnimation = stage.animate([{ opacity: 1 }, { opacity: 0 }], {
            duration: 280, easing: 'cubic-bezier(0.4, 0, 1, 1)', fill: 'forwards',
          });
        }
        exitAnimation = host.animate([
          { opacity: 1, offset: 0 },
          { opacity: 1, offset: media.matches ? 0 : 0.18 },
          { opacity: 0, offset: 1 },
        ], {
          duration, easing: 'cubic-bezier(0.4, 0, 0.2, 1)', fill: 'forwards',
        });
        // The timer also covers background tabs that pause animation timelines.
        await Promise.race([exitAnimation.finished.catch(() => {}), pause(duration + 100)]);
      }
    } catch (animationError) {
      reason = 'error';
      error ??= animationError;
    } finally {
      cleanup(reason, error);
    }
  }

  function onMotionChange() {
    if (media.matches) { exitAnimation?.finish(); markExitAnimation?.finish(); }
  }
  function onLayoutChange() {
    // A resized or scrolled destination no longer has the measured coordinates.
    // Settle directly into its real position rather than travel to a stale one.
    if (destination) cleanup('ready');
  }
  media.addEventListener('change', onMotionChange);

  let releaseStyles;
  const stylesReady = new Promise((resolve, reject) => {
    releaseStyles = resolve;
    stylesheet.onload = resolve;
    stylesheet.onerror = () => reject(new Error('Launch stylesheet could not load.'));
  });
  // Hard cap includes resource loading and the exit, never blocks the app forever.
  const watchdog = setTimeout(() => cleanup('timeout'), maxDuration);
  document.body.append(host);

  // Observe immediately so an early initialization failure cannot go unhandled.
  Promise.resolve(ready).then(() => releaseReady(), (error) => exit('error', error));

  (async () => {
    try {
      await stylesReady;
      if (settled || exiting) return;
      if (appRoot) { appRoot.inert = true; ownsInert = true; }
      host.hidden = false;
      entrance = animateMark(svg);
      // Reduced motion does not impose the branded waiting period.
      const minimum = media.matches ? 180 : minDuration;
      await Promise.all([entrance.finished, pause(minimum), readySignal]);
      if (!settled) await exit('ready');
    } catch (error) {
      await exit('error', error);
    }
  })();

  return {
    finished,
    finish() { releaseReady(); },
    destroy() { cleanup('destroyed'); },
  };
}
