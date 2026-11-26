// ── core/badge.js ─────────────────────────────────────────────────────────────
// Toolbar icon, per tab. SSS 1.0.0 (owner, 2026-11-26 — "I don't need badges, when icon changes color"): NO badge
// text, NO badge colour, NO Chrome block-count number — the icon itself is the only signal (data/constants.js
// ICON_STATE/ICON_COLOR, 3P-Matrix-lite's shield-and-eye):
//   grey  (ICON_STATE.OFF)   — whitelisted: every protection off on this site
//   orange(ICON_STATE.FOUND) — the worst of the site's risk check and the page's tamper rating is Suspicious or worse
//   mint  (ICON_STATE.ON)    — protected, nothing found
// This module still keeps the per-tab risk/tamper state (the popup's "This page" box needs the detail, not just the
// colour), it just never draws a badge from it.
//
// Public interface:
//   init()                              — every service-worker start: explicitly OFF (idempotent) — see guard below
//   ready()                             — Promise: per-tab state restored (await before reading)
//   resetPage(tabId)                    — new top-level page committed: the tamper rating belongs to the old page
//   setRisk(tabId, site, severity)      — remember the risk of the site in the tab
//   clearRiskIfOtherSite(tabId, site)   — committed page belongs to another site
//   setTamperRating(tabId, rating)      — the page's tamper rating (core/tamper-guard.js, via setMarkSink)
//   getRisk(tabId)                      — the site's risk (after ready())
//   allHighRisk()                       — 4.7.0: tabId[] currently at SEVERITY.PHISHING (after ready()) —
//                                         core/apply-manager.js's high-risk tab band (data/protections.js alsoHighRisk)
//   setSiteIcon(status, tabId?)         — global (no tabId) or per-tab icon; `status` is a SITE_STATUS (or null for
//                                         "not a site") — combined here with the tab's own found-state
//   releaseTab(tabId)                  — tab closed: drop everything we hold for it
//
// State — one entry per tab in a session store (core/session-map.js, SESSION_KEY.BADGE), so the risk survives a
// service-worker restart: _tabs.map  Map<tabId, { site, severity, tamper, status }>, bounded by open tabs (releaseTab
// on tabs.onRemoved). Every change waits for the restore (_tabs.ready()) and applies in arrival order.
// Render coalescing (4.5.4): a change marks the tab dirty; one timer per tab (ICON_RENDER_DELAY_MS) draws it and
// saves the session entry. The icon already shown is not redrawn.
//   _timers  Map<tabId, timeoutId>         — pending draw; cleared by releaseTab()
//   _shown   Map<tabId, string>            — the ICON_STATE already shown; deleted by releaseTab()
// ─────────────────────────────────────────────────────────────────────────────

import { ICON_STATE, ICON_RENDER_DELAY_MS, SESSION_KEY, SEVERITY, SEVERITY_ORDER, SITE_STATUS,
         TAMPER_FOUND_SEVERITY, LOG_PREFIX, ICON_SIZES, ICON_DIR } from "../data/constants.js";
import { createSessionMap } from "./session-map.js";

const _tabs = createSessionMap(SESSION_KEY.BADGE);
const _timers = new Map();
const _shown = new Map();

export function ready() { return _tabs.ready(); }

// Every service-worker start (Chrome keeps the option, setting it again is harmless). Guarded: a failure is logged,
// the icon colouring still works. Explicitly OFF — no badge text, no badge colour, no Chrome block-count number.
export function init() {
  chrome.action.setBadgeText({ text: "" }).catch((e) => console.warn(LOG_PREFIX, "clear badge:", e));
  chrome.declarativeNetRequest.setExtensionActionOptions({ displayActionCountAsBadgeText: false })
    .catch((e) => console.warn(LOG_PREFIX, "badge block count off:", e));
}

// A stored entry from before or anything unexpected counts as nothing (guard).
function severityOf(value) { return SEVERITY_ORDER.includes(value) ? value : SEVERITY.NONE; }

function entryOf(tabId) {
  if (!_tabs.map.has(tabId)) _tabs.map.set(tabId, { site: "", severity: SEVERITY.NONE, tamper: SEVERITY.NONE, status: null });
  return _tabs.map.get(tabId);
}

// The worst of the site's risk and the tamper rating, as a found/not-found flag.
function foundSomething(entry) {
  const site = severityOf(entry.severity), tamper = severityOf(entry.tamper);
  const worst = SEVERITY_ORDER.indexOf(tamper) > SEVERITY_ORDER.indexOf(site) ? tamper : site;
  return worst !== SEVERITY.NONE;
}

// Whitelisted (SITE_STATUS.OFF) always wins — "off" means every protection, including the risk/tamper
// checks that would have painted it orange, is off on that site. No status (not a web page) reads as ON:
// an extension/chrome:// page is not a risk, so the icon stays its default protected colour, not grey.
function iconStateOf(entry) {
  if (entry.status === SITE_STATUS.OFF) return ICON_STATE.OFF;
  if (foundSomething(entry)) return ICON_STATE.FOUND;
  return ICON_STATE.ON;
}

// Draws the tab now (only if the icon state changed) and saves the session store.
function draw(tabId) {
  _timers.delete(tabId);
  const entry = _tabs.map.get(tabId);
  if (!entry) return;                                         // released meanwhile
  const want = iconStateOf(entry);
  if (want !== _shown.get(tabId)) {
    const path = Object.fromEntries(ICON_SIZES.map((s) => [String(s), `${ICON_DIR}/${want}_${s}.png`]));
    chrome.action.setIcon({ path, tabId }).catch(() => { /* tab closed meanwhile */ });
    _shown.set(tabId, want);
  }
  _tabs.save();
}

function scheduleDraw(tabId) {
  if (_timers.has(tabId)) return;                            // a draw is already due: it will include this change
  _timers.set(tabId, setTimeout(() => draw(tabId), ICON_RENDER_DELAY_MS));
}

// Runs `change(entry)` once the store is restored, then schedules the draw.
function update(tabId, change) {
  if (tabId < 0) return;
  _tabs.ready().then(() => {
    if (change(entryOf(tabId)) !== false) scheduleDraw(tabId);
  });
}

// Chrome clears a tab's own icon when it navigates: forget what was shown and draw again (the site's
// risk stays when the site stays; the tamper rating belonged to the old page).
export function resetPage(tabId) {
  _shown.delete(tabId);
  update(tabId, (e) => { e.tamper = SEVERITY.NONE; });
}

// `rating`: a TAMPER_RATING (Low and unknown values give nothing).
export function setTamperRating(tabId, rating) {
  const sev = Object.prototype.hasOwnProperty.call(TAMPER_FOUND_SEVERITY, rating) ? TAMPER_FOUND_SEVERITY[rating] : SEVERITY.NONE;
  update(tabId, (e) => {
    if (e.tamper === sev) return false;                      // nothing changes: no draw
    e.tamper = sev;
    return true;
  });
}

export function getRisk(tabId) {
  const e = _tabs.map.get(tabId);
  return e && e.severity !== SEVERITY.NONE ? { site: e.site, severity: e.severity } : null;
}

export function allHighRisk() {
  const out = [];
  for (const [tabId, e] of _tabs.map) if (e.severity === SEVERITY.PHISHING) out.push(tabId);
  return out;
}

export function setRisk(tabId, site, severity) {
  update(tabId, (e) => {
    if (severity === SEVERITY.NONE) { e.site = ""; e.severity = SEVERITY.NONE; } else { e.site = site; e.severity = severity; }
  });
}

export function clearRiskIfOtherSite(tabId, site) {
  update(tabId, (e) => {
    if (e.severity === SEVERITY.NONE || e.site === site) return false;   // nothing changes: no draw
    e.site = ""; e.severity = SEVERITY.NONE;
    return true;
  });
}

export function setSiteIcon(status, tabId) {
  if (tabId === undefined) {
    const path = Object.fromEntries(ICON_SIZES.map((s) => [String(s), `${ICON_DIR}/${ICON_STATE.ON}_${s}.png`]));
    chrome.action.setIcon({ path }).catch((e) => console.warn(LOG_PREFIX, "global icon:", e));
    return;
  }
  update(tabId, (e) => {
    if (e.status === status) return false;                   // nothing changes: no draw
    e.status = status;
    return true;
  });
}

export function releaseTab(tabId) {
  clearTimeout(_timers.get(tabId));
  _timers.delete(tabId);
  _shown.delete(tabId);
  _tabs.ready().then(() => { if (_tabs.map.delete(tabId)) _tabs.save(); });
}
