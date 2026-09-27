# Equal-size-bar adaptation

The user requested that all 15 bars have the same size. The active SVG is now an
edited variant of the earlier UK Data Service symbol, with a transparent
background and no wordmark. It is not unchanged official artwork.

## Geometry

Each bar is a filled capsule with circular ends:

- Centreline length: **26.24 SVG units**.
- Thickness: **2.544 SVG units**.
- Cap radius: **1.272 SVG units**.
- Overall length including caps: **28.784 SVG units**.

There are five bars per arm. The vertical arm points at −90°, the upper arm at
30°, and the right arm at 150°. Every capsule has identical intrinsic dimensions;
their screen-aligned bounding boxes differ because of their rotations.

For order `i` from 0 through 4, cap-centre starting anchors are:

- Left: `(41.206 + 4.545i, 92.016 + 2.625i)`.
- Top: `(63.94 − 4.545i, 52.615 + 2.625i)`.
- Right: `(86.67, 71.029 + 5.25i)`.

Each second cap centre is the starting anchor plus a 26.24-unit vector in the
arm's direction. Capsules use straight sides and SVG circular arc commands.
The `ukds-bar`, `data-arm`, and `data-order` animation hooks are retained.
The user also requested different colours. A fresh palette of 15 vibrant hues
was shuffled once; the assignment stays consistent on every launch. The viewBox remains
`37.740320597 49.320305645 52.24635988 59.229378456`.

## Reference sources

The previous geometry was extracted from page 1 of the official
[UK Data Service Strategy 2024–2030](https://ukdataservice.ac.uk/app/uploads/ukdataservicestrategy202430.pdf).
That variable-length geometry has been replaced by the equal capsules above.

The earlier reference palette came from the
[official website header PNG](https://ukdataservice.ac.uk/app/themes/ukds/dist/images/ukds-logo-col-grey.png).
It is not the active palette. The original reference extraction and refined
animation remain recoverable in `.local/ukda-reference-before-redesign.zip` in the
development project, outside this distribution.

## Current palette

| Bar | Colour |
| --- | --- |
| `ukds-left-1` | `#E05E78` |
| `ukds-left-0` | `#7857C4` |
| `ukds-left-2` | `#4C7CC9` |
| `ukds-left-3` | `#3499D0` |
| `ukds-left-4` | `#D358A0` |
| `ukds-top-0` | `#EF7669` |
| `ukds-top-4` | `#6872D8` |
| `ukds-top-3` | `#EB884A` |
| `ukds-top-2` | `#17A79D` |
| `ukds-top-1` | `#E5AD42` |
| `ukds-right-4` | `#A2BF45` |
| `ukds-right-3` | `#9A6BCC` |
| `ukds-right-2` | `#BB58A7` |
| `ukds-right-1` | `#39AD7C` |
| `ukds-right-0` | `#24ADC2` |

Current SVG SHA-256:
`92fa0938364a24170b8778c0365592c732983ae8aee61632c5431e8d70476534`.
