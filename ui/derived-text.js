// ── ui/derived-text.js — values shown in UI text, derived from their source ──────
// Any number or list a page SHOWS that also exists as a constant or registry field is rendered from
// that source here — never typed into HTML or a JS string (B2a, C39a). Changing the constant then
// updates every page.
//
// SSS 1.0.0: the level-slider/Protections/download/Show Matrix pages that used to fill most of this
// table are gone (ui/protections.*, ui/matrix.* removed; owner decision 2026-11-26 — "remove download
// guard" took the download-specific constants with it). The table is empty for now; ui/warning.js and
// ui/tamper-warning.js still call fillDerivedText(document) on load, which is a harmless no-op while
// their pages have no [data-derived] elements — add entries here (and the matching data-derived
// attribute) the next time either page needs to show a derived number or list.
//
// Public interface:
//   fillDerivedText(root)    — fills every <… data-derived="KEY"> under root from DERIVED_TEXT
//   formatScore(n)           — score with a typographic minus ("−30")
//
// HTML usage:   <span data-derived="KEY"></span>   (empty in the markup on purpose)
// Guard: an unknown key is logged and its element is marked data-derived-missing, so a typo shows up
// in the console instead of silently rendering an empty span.
// ─────────────────────────────────────────────────────────────────────────────

import { LOG_PREFIX } from "../data/constants.js";

const DERIVED_ATTR = "data-derived";
const MISSING_ATTR = "data-derived-missing";
const MINUS_SIGN   = "−";                  // typographic minus, as in the existing UI text

export function formatScore(n) {
  return n < 0 ? MINUS_SIGN + String(-n) : String(n);
}

// THE table of derived values pages may show. Key = data-derived attribute value. Empty for now — see
// the file header.
const DERIVED_TEXT = Object.freeze({});

export function fillDerivedText(root) {
  if (!root || typeof root.querySelectorAll !== "function") return;
  for (const el of root.querySelectorAll(`[${DERIVED_ATTR}]`)) {
    const key = el.getAttribute(DERIVED_ATTR);
    const derive = DERIVED_TEXT[key];
    if (!derive) {
      el.setAttribute(MISSING_ATTR, "");
      console.error(LOG_PREFIX, "derived-text: unknown key", key);
      continue;
    }
    el.textContent = derive();
  }
}
