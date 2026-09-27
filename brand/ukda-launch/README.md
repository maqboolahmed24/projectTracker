# Maqbool launch animation

An **equal-size-bar adaptation** of the supplied UK Data Service symbol. Every bar
has the same length and thickness, with a fresh shuffled palette and the
three-sided arrangement retained. No wordmark,
tagline, loading text, glow, shadow, or spinner appears in the launch screen.
The vector bars draw along their own axes as three overlapping families glide
into place. The pristine symbol holds at the centre, then shrinks and travels into
the app's visible corner logo while the background reveals the page. Without a
visible destination, it uses a short fade instead.

This directory is a standalone frontend component. It does not modify the API,
authentication, database, or headless browser client in the developing Maqbool app.

## Preview

Serve this folder with a static server and open `index.html`. Replay shows the
entrance and leaves the finished mark visible. Preview app launch also shows the
exit over the preview page. Light and dark backgrounds use the same logo colours.

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory brand/ukda-launch
```

## Integrate

Copy `ukda-launch.js`, `mark.js`, `ukda-launch.css`, and optionally
`ukda-launch.d.ts` together into your frontend's static assets. The mark is included
in `mark.js`; no external network calls, font, runtime dependency, or raster image
is required. `assets/ukds-symbol.svg` is a standalone static logo for other uses.

Add the stylesheet preload in the document head to make the launch appear promptly:

```html
<link rel="preload" href="/brand/ukda-launch/ukda-launch.css" as="style">
```

In your existing browser entry point, after the document body exists:

```js
import { mountUKDALaunch } from '/brand/ukda-launch/ukda-launch.js';

const ready = initializeApp(); // Your existing startup function.
const launch = mountUKDALaunch({
  ready,
  appRoot: document.getElementById('app'),
  theme: 'light', // 'dark' or 'auto' also supported.
  logoTarget: '.identity-brand img, .wordmark img',
});

ready.catch(showStartupError); // Your app owns its own error handling.
// If the frontend unmounts or navigates during startup:
// launch.destroy();
```

Omit `ready` for a timed intro. With a promise, the symbol holds still until the
promise resolves. `finish()` can signal readiness manually. `finished` always
resolves after removal, with `{ reason }` and an optional `error`; it is not an app
readiness signal. Errors dismiss the overlay and leave your app's error UI visible.

The default entrance takes about 2.36 seconds, followed by a short hold and a
720 ms handoff (or a 480 ms fade when no destination is available). The destination
is measured from the actual page layout; uniform scaling preserves the artwork,
and its original logo is hidden only during the handoff. A resize or scroll ends
the travel at the real logo immediately. The 10-second hard deadline includes stylesheet loading and prevents
a failed or never-settling initialization from trapping the user behind the logo.
Adjust `minDuration` / `maxDuration` in milliseconds; maximum must exceed minimum.
Reduced motion uses a 160 ms fade without drawing or travel and skips the longer
minimum hold. Reveal masks are temporary; the assembled artwork is unmodified.

Mount once per app launch, not on every route change. Avoid overlapping instances.
For a first-party static frontend, call this near the beginning of your existing
module entry so it can cover startup. The component starts hidden while its CSS
loads, so it cannot flash an unstyled logo or obscure your app if the CSS fails.

### React / Next.js client components

```jsx
'use client';
import { useEffect } from 'react';
import { mountUKDALaunch } from './brand/ukda-launch/ukda-launch.js';

export function Launch({ ready }) {
  useEffect(() => {
    const launch = mountUKDALaunch({ ready, theme: 'light' });
    return () => launch.destroy();
  }, [ready]);
  return null;
}
```

Keep the `ready` promise stable (create it once in the app's startup layer). Imports
are safe during server rendering; mounting requires a browser. If your bundler
does not copy `new URL('./ukda-launch.css', import.meta.url)`, copy the CSS to public
assets and pass `stylesheetUrl: '/brand/ukda-launch/ukda-launch.css'`.

## Accessibility and isolation

- Shadow DOM isolates the component from application styles.
- The logo is decorative during launch; an invisible status announces startup.
- `appRoot` is optional. If supplied, its prior `inert` value is restored on every
  exit, including errors, timeout and manual destruction. It must be a container
  inside body, not body itself. Without it, the caller owns interaction blocking.
- `logoTarget` is an optional selector. Only a visible, fully on-screen element
  can receive the mark. Its previous inline visibility is restored on every exit.
- No focus trap, focus movement, local storage, analytics, or cookies.
- CSS loads from your own origin; no inline style or evaluated scripts are used.
  A strict frontend policy needs to allow its own JS modules and CSS.
  Trusted Types enforcement needs an application-provided policy for the static
  SVG strings assigned via `innerHTML`.

## Artwork provenance

The three-sided arrangement follows the UK Data Service mark in the user's
supplied image. At the user's request, all 15 bars have been rebuilt
as identical rounded capsules: 26.24 units between cap centres, 2.544 units thick,
and 28.784 units overall. A fresh set of 15 vibrant colours is assigned in a
shuffled order that stays consistent on every launch.
This is an edited variant, not unchanged official artwork.
Source references and the edit are recorded in `assets/SOURCE.md`.
