// ── core/site-locks.js ────────────────────────────────────────────────────────
// SSS 1.0.0 — the whitelist (pure operations on state.siteLocks / state.siteLocksOrder /
// state.siteLocksSessionOnly) and the per-category allow entries a warning's "Always allow"/"Always
// ignore" button adds. No Chrome API calls. The whitelist IS the set of sites locked at LEVEL.ALLOW_ALL
// — the ONLY lock the user can set (there is no slider, so there is no other level to lock a site to;
// 3P-Matrix-lite's per-level lock and its free-text multi-category allow-list editor are both gone —
// owner decision 2026-11-26, "a simple whitelist").
//
// Session-only whitelisting (owner, 2026-11-26): a site the system itself already auto-elevates — adult,
// abused TLD, or risky domain (core/auto-levels.js isAutoElevated) — can still be whitelisted, but only
// for the current browsing session: background.js purges it at the next real browser start
// (chrome.runtime.onStartup), not merely a service-worker restart. Every path that adds a site to the
// whitelist (the popup switch, the whitelist page's Add, and Import) applies the same rule — nothing here
// second-guesses WHY a site is being added, so the rule is one place and cannot be skipped.
//
// Public interface:
//   isLocked(state, site)                 — site has a lock (whitelist only, so: is it whitelisted)
//   isWhitelisted(state, host)             — host's registered domain is on the whitelist
//   isSessionOnly(state, site)             — that whitelist entry is session-only (will be purged)
//   lockSite(state, site, level)           — add/replace a lock; FIFO eviction at SITE_LOCKS_CAP
//   unlockSite(state, site)                — remove a lock (no-op when absent) — releases its session-only mark too
//   toggleWhitelist(state, site)           — popup's on/off switch
//   addSiteToWhitelist(state, host)        — whitelist page "Add"
//   removeSiteFromWhitelist(state, host)   — whitelist page's per-row remove
//   clearWhitelist(state)                  — whitelist page "Delete all" (confirmed in the UI first)
//   clearSessionWhitelist(state)           — chrome.runtime.onStartup: purge every session-only entry
//   allowListSites(state)                  — [{ site, sessionOnly }], in add order
//   importWhitelist(state, hosts)          — whitelist page "Import": replaces the whole whitelist with a
//                                            validated host array (invalid/duplicate entries dropped, capped)
//   addToAllowList(state, category, host)  — "Always allow" / "Always ignore" in a warning (unchanged)
//
// Guards: siteLocks and siteLocksOrder are always changed together here (normalizeState() rebuilds them
// together too), so they cannot drift apart. siteLocksSessionOnly is always a SUBSET of siteLocksOrder —
// every function that removes a lock (unlockSite, and so clearWhitelist/clearSessionWhitelist/importWhitelist's
// reset) also drops its session-only mark in the same step, so the two can never drift apart either.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, SITE_LOCKS_CAP, ALLOW_CATEGORY_CAP, WHITELIST_CAP } from "../data/constants.js";
import { ALLOW_CATEGORY, ALLOW_CATEGORY_ORDER } from "../data/allow-categories.js";
import { isValidHost } from "../data/state-storage.js";
import { isAutoElevated } from "./auto-levels.js";
import { registeredDomain } from "../util/domain.js";

const URL_SCHEME_RE    = /^https?:\/\//i;
const AFTER_HOST_RE    = /[/:?#].*$/;

export function isLocked(state, site) {
  return Object.prototype.hasOwnProperty.call(state.siteLocks, site);
}

export function lockSite(state, site, level) {
  if (!isLocked(state, site)) {
    if (state.siteLocksOrder.length >= SITE_LOCKS_CAP) unlockSite(state, state.siteLocksOrder[0]); // FIFO
    state.siteLocksOrder.push(site);
  }
  state.siteLocks[site] = level;
}

export function unlockSite(state, site) {
  delete state.siteLocks[site];
  state.siteLocksOrder = state.siteLocksOrder.filter((s) => s !== site);
  // Guard: a released lock releases its session-only mark too — siteLocksSessionOnly never
  // outlives the lock it refers to.
  if (state.siteLocksSessionOnly.includes(site)) {
    state.siteLocksSessionOnly = state.siteLocksSessionOnly.filter((s) => s !== site);
  }
}

export function isWhitelisted(state, host) {
  return !!host && isLocked(state, registeredDomain(host)) && state.siteLocks[registeredDomain(host)] === LEVEL.ALLOW_ALL;
}

export function isSessionOnly(state, site) {
  return state.siteLocksSessionOnly.includes(site);
}

// Every whitelist-add path funnels through here: the ONE place that decides permanent vs session-only.
function whitelistSite(state, site) {
  lockSite(state, site, LEVEL.ALLOW_ALL);
  if (isAutoElevated(state, site) && !state.siteLocksSessionOnly.includes(site)) state.siteLocksSessionOnly.push(site);
}

// Popup's on/off switch: whitelisted → remove; else → add (the current page's registered domain).
export function toggleWhitelist(state, site) {
  if (isLocked(state, site)) unlockSite(state, site); else whitelistSite(state, site);
}

export function allowListSites(state) {
  return state.siteLocksOrder
    .filter((s) => state.siteLocks[s] === LEVEL.ALLOW_ALL)
    .map((site) => ({ site, sessionOnly: isSessionOnly(state, site) }));
}

// DOWNLOAD category removed (SSS 1.0.0) — every remaining category keys its entries by registered domain.
function entryOf(_category, host) { return registeredDomain(host); }

function normalizeWhitelistHost(raw) {
  const h = String(raw || "").trim().replace(URL_SCHEME_RE, "").replace(AFTER_HOST_RE, "").toLowerCase();
  return isValidHost(h) ? registeredDomain(h) : null;
}

// Whitelist page "Add" — one host (an address is cut back to its registered domain). Throws on an invalid host.
export function addSiteToWhitelist(state, host) {
  const site = normalizeWhitelistHost(host);
  if (!site) throw new Error("not a valid domain");
  whitelistSite(state, site);
  return site;
}

export function removeSiteFromWhitelist(state, host) {
  const site = normalizeWhitelistHost(host) || registeredDomain(String(host || ""));
  unlockSite(state, site);
}

// Whitelist page "Delete all" (the UI confirms first).
export function clearWhitelist(state) {
  allowListSites(state).forEach(({ site }) => unlockSite(state, site));
}

// chrome.runtime.onStartup ONLY (a real browser start, never a plain service-worker restart) — purges every
// session-only whitelist entry. Iterates a copy (unlockSite mutates siteLocksSessionOnly as it goes).
export function clearSessionWhitelist(state) {
  [...state.siteLocksSessionOnly].forEach((site) => unlockSite(state, site));
}

// Whitelist page "Import": every line/entry becomes a whitelisted site; invalid entries are dropped silently
// (the UI reports how many were kept), the whole list replaced (not merged), capped at WHITELIST_CAP. Goes
// through the same whitelistSite() path, so an imported often-abused domain is session-only too.
export function importWhitelist(state, hosts) {
  clearWhitelist(state);
  const seen = new Set();
  let kept = 0;
  for (const raw of Array.isArray(hosts) ? hosts : []) {
    if (kept >= WHITELIST_CAP) break;
    const site = normalizeWhitelistHost(raw);
    if (!site || seen.has(site)) continue;
    seen.add(site);
    whitelistSite(state, site);
    kept++;
  }
  return kept;
}

// "Always allow" / "Always ignore" in a warning: adds one site under one allow-list category
// (Firewall / Scam / Tamper — data/allow-categories.js). "All" (the whitelist) is its own path above.
export function addToAllowList(state, category, host) {
  if (!ALLOW_CATEGORY_ORDER.includes(category) || !isValidHost(host)) throw new Error("bad allow-list entry");
  if (category === ALLOW_CATEGORY.ALL) { lockSite(state, registeredDomain(host), LEVEL.ALLOW_ALL); return; }
  if (isWhitelisted(state, host)) return;                      // the whitelist already covers everything
  const entry = entryOf(category, host);
  const list = state.allowCategories[category] || [];
  if (!list.includes(entry)) state.allowCategories[category] = [...list, entry].slice(0, ALLOW_CATEGORY_CAP);
}
