#!/usr/bin/env node
// ── tools/build-icons.mjs ─────────────────────────────────────────────────────
// Renders the toolbar icon (shield with an eye) for every ICON_STATE × ICON_SIZE combination
// into icons/<state>_<size>.png (data/constants.js ICON_STATE, ICON_SIZES, ICON_COLOR, ICON_DIR —
// the single source for the file names and colours; nothing here re-types them).
//
// Usage: node tools/build-icons.mjs
//
// Guard: writes to a fresh output directory each run (no stale sizes/states left behind from an
// earlier ICON_STATE/ICON_SIZES change) — the directory is removed and recreated before any file
// is written, then every file is written in one pass.
// ─────────────────────────────────────────────────────────────────────────────

import { mkdir, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { ICON_STATE, ICON_SIZES, ICON_COLOR, ICON_DIR } from "../data/constants.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url)) + "/..";
const OUT_DIR = path.join(ROOT, ICON_DIR);

// `sharp` is a devDependency (tools/package.json) that may not be installed locally everywhere this
// script runs — fall back to a couple of common global install locations before giving up with a
// clear instruction, rather than a bare "Cannot find package" trace.
const SHARP_FALLBACKS = Object.freeze([
  "/opt/npm-tools/node_modules/sharp/dist/index.cjs",
  "/usr/lib/node_modules/sharp/dist/index.cjs"
]);
async function loadSharp() {
  try { return (await import("sharp")).default; } catch { /* try fallbacks below */ }
  for (const p of SHARP_FALLBACKS) {
    try { return (await import(p)).default; } catch { /* next */ }
  }
  throw new Error("sharp is not installed — run `npm install sharp` (tools/package.json) before building icons");
}
const sharp = await loadSharp();

// The eye colour follows the shield's own fill: dark on the light mint/orange shields (ON/FOUND),
// a lighter grey on the dark OFF shield — so the eye always reads clearly against its own background.
const EYE_OF_STATE = Object.freeze({
  [ICON_STATE.ON]:    ICON_COLOR.EYE,
  [ICON_STATE.FOUND]: ICON_COLOR.EYE,
  [ICON_STATE.OFF]:   ICON_COLOR.EYE_OFF
});

// One shield-with-eye glyph, viewBox 0 0 24 24 — simple enough to read at 16px, SHIELD_FILL/EYE_FILL
// the only two colours (data-driven, never a hand-picked hex here).
function shieldSvg(shieldFill, eyeFill) {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
  <path d="M12 1.5 L21 5 V11.5 C21 17 17 21 12 22.5 C7 21 3 17 3 11.5 V5 Z" fill="${shieldFill}"/>
  <path d="M5.2 12.2 C7 9 9.3 7.6 12 7.6 C14.7 7.6 17 9 18.8 12.2 C17 15.4 14.7 16.8 12 16.8 C9.3 16.8 7 15.4 5.2 12.2 Z"
        fill="none" stroke="${eyeFill}" stroke-width="1.3" stroke-linejoin="round"/>
  <circle cx="12" cy="12.2" r="2.3" fill="${eyeFill}"/>
</svg>`;
}

async function renderOne(state, size) {
  const svg = shieldSvg(ICON_COLOR[stateKeyOf(state)], EYE_OF_STATE[state]);
  const png = await sharp(Buffer.from(svg)).resize(size, size).png().toBuffer();
  await writeFile(path.join(OUT_DIR, `${state}_${size}.png`), png);
}

// ICON_STATE values ("sss_on" etc.) → the matching ICON_COLOR key ("ON" etc.) — the two enums share
// the same member names, so this is a plain lookup, not a guess.
function stateKeyOf(state) {
  return Object.keys(ICON_STATE).find((k) => ICON_STATE[k] === state);
}

async function main() {
  await rm(OUT_DIR, { recursive: true, force: true });
  await mkdir(OUT_DIR, { recursive: true });
  const jobs = [];
  for (const state of Object.values(ICON_STATE)) {
    for (const size of ICON_SIZES) jobs.push(renderOne(state, size));
  }
  await Promise.all(jobs);
  console.log(`Wrote ${jobs.length} icons to ${path.relative(ROOT, OUT_DIR)}/`);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
