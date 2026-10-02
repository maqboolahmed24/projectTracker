# Bundled avatar collection

The catalogue contains **20 fixed illustrated shapes and 12 independent colours**, giving **240 combinations**. The SVG files are scalable, transparent portraits. Colour changes the shell and accessory colour while preserving the design, ink, highlights and mouth details. There are no photo uploads or arbitrary SVG/colour inputs.

`manifest.json` records each stable shape ID, descriptive label, filename, SHA-256, component selection and source provenance. The palette contains coral, amber, gold, lime, teal, mint, sky, blue, indigo, violet, rose and slate. `shape-01.svg` through `shape-20.svg` are the actual runtime assets. Consumers set the SVG `color` from the catalogue palette, or replace `currentColor` with the validated palette hex when rendering a standalone image.

The templates contain static geometry only. Local `clip-path="url(#shape-…-…)"` references bound the original shading to each silhouette. They contain no scripts, styles, animation, images, links, text/fonts, event handlers or external resource references. IDs are unique across the 20 shapes. If an interface embeds the *same* SVG more than once inline, it should use image/object isolation or namespace that instance's local IDs to avoid duplicate DOM IDs.

## Reproduce the assets

From the repository root with Node.js 24:

```sh
node assets/avatars/generate.mjs
```

The recipe runs completely offline, verifies the pinned source hash, expands only explicitly selected static components, validates an allowlist of SVG elements/attributes and writes the 20 templates and manifest deterministically. The source file is `source/critters-10.6.0.json`; it is kept for reproducibility and licence provenance, not runtime generation. Replacing source artwork or changing a released shape requires a new catalogue version so existing choices remain stable.

## Review the artwork

`preview.png` is an asset contact sheet for review, not an application screen. It shows all 20 shapes, one shape in every colour and all shapes at small profile size. To regenerate it using the project's Playwright development dependency:

```sh
node assets/avatars/preview.mjs
```

The review script defaults to the installed Google Chrome on macOS. Set `AVATAR_REVIEW_BROWSER` to another Chromium executable when needed. It parses every template as SVG/XML and rejects active or external-resource elements before rendering. `preview-validation.json` records that check. All 20 illustrations were visually inspected at contact-sheet and small-profile sizes after generation.

See `NOTICE.md` and `CC0-1.0.txt` for the artwork's origin and licence. No online service is needed to build, serve or display this collection.
