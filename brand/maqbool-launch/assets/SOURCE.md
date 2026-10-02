# Maqbool square line artwork

Copyright © 2026 Sayed Maqbool Ahmed Inamdar.
SPDX-License-Identifier: AGPL-3.0-only

The current mark was authored specifically for Maqbool as original vector geometry.
Sixteen separate, thin, colorful rounded bars form an upright square: four parallel
lines on each side, open corners and a transparent center. The mark is entirely
two-dimensional and uses only horizontal and vertical lines. It contains no traced
paths, extracted imagery, third-party logo geometry, font glyphs, raster images, or
external resources. This artwork is licensed under the repository's GNU Affero
General Public License version 3 only; see the root `LICENSE`. No rights in
third-party trademarks are implied.

## Geometry

All coordinates use a square `0 0 100 100` viewBox. The four inset centerlines are
at 11, 19, 27 and 35 units from each corresponding outer edge. Every bar has a
3.6-unit thickness and 1.8-unit circular end caps. Each centerline ends 6 units
before its square's corners, leaving clear diagonal gaps between perpendicular
bars. Centerline lengths are 66, 50, 34 and 18 units, repeated identically on all
four sides. The color palette is fixed across light and dark themes.

The existing startup animation remains unchanged. The original fifteen arrival
slots are preserved, and the sixteenth bar shares the last slot for visual
symmetry. Delays still run from 80 to 840 ms, each reveal lasts 1180 ms and each
slide lasts 1520 ms, preserving the 2.36-second entrance. Each bar includes
explicit reveal endpoints and a 5.94-unit reveal width. Existing easing, directions,
readiness handling, minimum hold and movement into the app's corner logo are
unchanged. `data-arm` and `data-order` are retained animation metadata; the
visible artwork has four sides, recorded separately by `data-side`.

## Files and reproduction

- `maqbool-symbol.svg` is the canonical static vector.
- `../mark.js` exports the exact same SVG as a JavaScript string.
- The startup animation adds temporary reveal masks and then removes them;
  it does not alter the settled logo.
- No original third-party reference image is included in this directory.

SVG SHA-256: `c919189a60b81853db7efbff209b85f60455f514c3d05a1edc22b74e083f1930`.
