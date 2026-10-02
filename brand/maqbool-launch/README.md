# Maqbool launch animation

An original square Maqbool mark built from sixteen thin coloured bars, four
on each side, with open corners and a transparent centre. The bars assemble
at the centre with the established reveal sequence, then
the completed symbol shrinks and travels into the app's visible corner logo
while the background reveals the page. Without a visible destination, the launch
uses a short fade. No wordmark, tagline, loading text, glow, shadow or spinner
appears in the launch screen.

This directory is a standalone frontend component. It does not modify the API,
authentication, database, or headless browser client in the developing Maqbool app.

## Preview

Serve this folder with a static server and open `index.html`. Replay shows the
entrance and leaves the finished mark visible. Preview app launch also shows the
exit over the preview page. Light and dark backgrounds use the same logo colours.

```sh
python3 -m http.server 4173 --bind 127.0.0.1 --directory brand/maqbool-launch
```

## Integrate

Copy `maqbool-launch.js`, `mark.js`, `maqbool-launch.css`, and optionally
`maqbool-launch.d.ts` together into your frontend's static assets. The mark is included
in `mark.js`; no external network calls, font, runtime dependency, or raster image
is required. `assets/maqbool-symbol.svg` is a standalone static logo for other uses.

Add the stylesheet preload in the document head to make the launch appear promptly:

```html
<link rel="preload" href="/brand/maqbool-launch/maqbool-launch.css" as="style">
```

In your existing browser entry point, after the document body exists:

```js
import { mountMaqboolLaunch } from '/brand/maqbool-launch/maqbool-launch.js';

const ready = initializeApp(); // Your existing startup function.
const launch = mountMaqboolLaunch({
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
minimum hold. The assembled artwork is restored when the entrance finishes or is cancelled.

Mount once per app launch, not on every route change. Avoid overlapping instances.
For a first-party static frontend, call this near the beginning of your existing
module entry so it can cover startup. The component starts hidden while its CSS
loads, so it cannot flash an unstyled logo or obscure your app if the CSS fails.

### React / Next.js client components

```jsx
'use client';
import { useEffect } from 'react';
import { mountMaqboolLaunch } from './brand/maqbool-launch/maqbool-launch.js';

export function Launch({ ready }) {
  useEffect(() => {
    const launch = mountMaqboolLaunch({ ready, theme: 'light' });
    return () => launch.destroy();
  }, [ready]);
  return null;
}
```

Keep the `ready` promise stable (create it once in the app's startup layer). Imports
are safe during server rendering; mounting requires a browser. If your bundler
does not copy `new URL('./maqbool-launch.css', import.meta.url)`, copy the CSS to public
assets and pass `stylesheetUrl: '/brand/maqbool-launch/maqbool-launch.css'`.

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

The current square is newly drawn for Maqbool. Its geometry and palette are
recorded in [assets/SOURCE.md](assets/SOURCE.md). The SVG and embedded mark used
by the launch component share the same source. Earlier Git revisions retain the
previous supplied artwork and its attribution as historical records; those
references do not describe this replacement mark.
