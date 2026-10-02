# Maqbool triangle artwork

Copyright © 2026 Sayed Maqbool Ahmed Inamdar.
SPDX-License-Identifier: AGPL-3.0-only

The current mark was authored specifically for Maqbool as original vector geometry.
It is a flat triangular ring with a transparent triangular opening and fifteen
colored sections. It contains no traced paths, extracted imagery, third-party logo
geometry, font glyphs, raster images, or external resources. This artwork is
licensed under the repository's GNU Affero General Public License version 3 only;
see the root `LICENSE`. No rights in third-party trademarks are implied.

## Geometry

All coordinates use a square `0 0 100 100` viewBox. The outer vertices are
`(50, 8)`, `(95, 86)` and `(5, 86)`. The inner vertices are `(50, 35)`,
`(71.65, 72.5)` and `(28.35, 72.5)`. Each corresponding outer/inner side is
divided into five adjacent quadrilateral sections using linear interpolation.
A 0.3-unit stroke matching each section's fill closes antialiasing seams.
The bright palette is fixed and does not change between light and dark themes.

The `data-arm` and `data-order` attributes retain the startup animation's existing
three groups of five arrivals. Each section includes explicit reveal-line endpoints
and a 32-unit reveal width, so the motion code does not infer the geometry from
the old mark. The entrance delays, duration, easing, readiness handling, minimum
hold and movement into the app's corner logo are preserved. These attributes are
animation metadata; they do not describe a three-dimensional symbol.

## Files and reproduction

- `maqbool-symbol.svg` is the canonical static vector.
- `../mark.js` exports the exact same SVG as a JavaScript string.
- The startup animation adds temporary reveal masks and then removes them;
  it does not alter the settled logo.
- No original third-party reference image is included in this directory.

SVG SHA-256: `4d1a1a57079b408e7714ce01ff328d9d3684926225f19b2925804046b2ca0561`.
