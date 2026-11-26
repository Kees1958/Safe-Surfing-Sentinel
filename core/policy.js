// ── core/policy.js ────────────────────────────────────────────────────────────
// Pure policy resolution — answers "which level applies where, and which
// protections are active at that level". No Chrome API calls, no side effects.
//
// Public interface:
//   effectiveLevel(state, p)            — lock level of p's registered domain, else autoLevelOf(state, p).level
//                                         — p is a parseHttpUrl()-shaped object (host/protocol/port), or a
//                                         bare host string (accepted for lockedLevelOf's own lookup only;
//                                         autoLevelOf's structural checks need the full object — see its header)
//   lockedLevelOf(state, host)          — lock level or null (bare host string)
//   isProtectionEnabled(state, key)     — user has not unticked it, nor its master (5.1.0 `requires`)
//   isProtectionTicked(state, key)      — 5.1.0: the user's own tick only (Protections page checkboxes)
//   isProtectionActive(state, key, lvl) — enabled AND lvl >= its fromLevel
//   ruleGroups(state)                   — the rule groups the builders iterate over:
//        [{ index: 0, level: state.level, kind: "global", sites: [all locked sites] },
//         { index: L, level: L,           kind: "locked", sites: [sites locked at L] }, ...]
//     Global rules EXCLUDE every locked site; each locked group INCLUDES only its sites.
//     One group per level (not per site) keeps the rule count independent of the
//     number of locks.
//   tabBandGroups(tabsByLevel)          — 4.4.5: one TAB group per level 2–5 that has tabs, for the
//                                         session rules (core/rule-builder.js buildSessionRules):
//        [{ index: L, level: L, kind: "tab", sites: [], tabIds: [...], priorityBase: TAB_BAND_BASE }]
//   highRiskTabGroups(tabIds)           — 4.7.0: one TAB group (or []) for tabs scored phishing this
//                                         session — see data/protections.js' 4.7.0 alsoHighRisk comment:
//        [{ index: HIGH_RISK_GROUP_INDEX, level: LEVEL_MAX, kind: "tab", sites: [], tabIds: [...],
//           priorityBase: HIGH_RISK_TAB_BASE, highRiskOnly: true }]
//      highRiskOnly tells core/rule-builder.js's `on()` to require p.alsoHighRisk instead of the
//      ordinary level gate — every OTHER protection is skipped for this group, level or no level.
//   isHighRiskSite(state, host, risk)   — 4.7.0: HIGH_RISK_HOSTNAMES (static) OR `risk` (the tab's
//                                         own core/badge.js getRisk() result, passed in — this module
//                                         makes no Chrome calls) says SEVERITY.PHISHING for this site;
//                                         false when the site is allow-listed (locked at ALLOW_ALL)
//   isProtectionActiveOrHighRisk(...)   — isProtectionActive() OR (p.alsoHighRisk AND isHighRiskSite())
//   isAllowedFor(state, category, host) — 5.1.3: the host's site is on the allow list under `category`
//                                         (data/allow-categories.js; "All" = locked at level 1 — handled by the levels)
//   allowSitesOf(state, category)       — 5.1.3: that category's sites (registered domains), for exclusions
//                                         — for a mechanism that decides per request (DOWNLOAD today)
//   protectionCounts(state, level)      — 5.1.5: per Protections-page tab, for the popup's policy lines:
//                                         { firewall: { active, total, outside: { active, total } },
//                                           download: { on, active (tab protections + DNS + heuristics + VT) }, scam: { on, active }, tamper: { on, signs } }
//                                         — switches and trigger ticks are not counted as protections
//   saferRegionsApply(level)            — does the safer-regions list have any effect at this level?
//   isInSaferRegions(state, host)       — 5.1.3: is the host's site inside the safer regions (its TLD on the list)?
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL, LEVEL_MIN, LEVEL_MAX, SAFER_REGIONS_LEVELS, LOG_PREFIX, SEVERITY, FIXED_LEVEL, SITE_STATUS,
         TAB_BAND_BASE, TAB_BAND_LEVELS, TAB_BAND_TABS_MAX, HIGH_RISK_GROUP_INDEX, HIGH_RISK_TAB_BASE } from "../data/constants.js";
import { autoLevelOf, strictGroupSites, AUTO_ADULT_DOMAINS } from "./auto-levels.js";
import { isSessionOnly } from "./site-locks.js";
import { PROTECTIONS, PROTECTION_BY_KEY, PROTECTION_KEY, PROTECTION_TAB, SCOPE, tabOf } from "../data/protections.js";
import { TAMPER_RULES } from "../data/tamper-rules.js";   // 5.1.5: the popup counts tamper signs
import { HIGH_RISK_HOSTNAMES } from "../data/network-data.js";
import { registeredDomain, isInDomainList } from "../util/domain.js";
import { ALLOW_CATEGORIES_STORED } from "../data/allow-categories.js";

export const GROUP_KIND = Object.freeze({ GLOBAL: "global", LOCKED: "locked", TAB: "tab" });

// SSS 1.0.0: the only lock the user ever sets is the whitelist (LEVEL.ALLOW_ALL — "off on this site").
// Everything else is computed by core/auto-levels.js; there is no slider and no startup level.
export function lockedLevelOf(state, host) {
  if (!host) return null;
  const site = registeredDomain(host);
  return Object.prototype.hasOwnProperty.call(state.siteLocks, site) ? state.siteLocks[site] : null;
}

// 1.0.2: `p` is a parsed-URL object (util/domain.js parseHttpUrl() — { host, protocol, port, ... }), not
// a bare host string — core/auto-levels.js autoLevelOf() needs protocol/port for its structural checks
// (plain HTTP, unusual port). Every call site already has one of these in hand; a bare host string also
// still works here (p.host falls back to the string itself), since lockedLevelOf()/registeredDomain()
// only ever needed the host.
export function effectiveLevel(state, p) {
  const host = (p && typeof p === "object") ? p.host : p;
  const whitelisted = lockedLevelOf(state, host);
  return whitelisted === LEVEL.ALLOW_ALL ? LEVEL.ALLOW_ALL : autoLevelOf(state, p).level;
}

// The popup's status line (data/constants.js SITE_STATUS_TEXT) — whitelist first, then the automatic reason.
// `sessionOnly` (owner, 2026-11-26): this whitelist entry will be purged at the next browser start (the
// site was already on the combined abused-domains list when it was added) — the popup shows
// SITE_STATUS_OFF_SESSION_DETAIL instead of the ordinary "On your whitelist" detail when it's true.
export function siteStatus(state, p) {
  const host = (p && typeof p === "object") ? p.host : p;
  if (lockedLevelOf(state, host) === LEVEL.ALLOW_ALL) {
    return { status: SITE_STATUS.OFF, source: null, sessionOnly: isSessionOnly(state, registeredDomain(host)) };
  }
  return { ...autoLevelOf(state, p), sessionOnly: false };
}

// Ticked by the user — and (5.1.0) so is its master protection (`requires`, data/protections.js). One level deep by
// design: a master never has a master of its own (tools/check-protection-keys.mjs).
// A `switchable: false` protection has no tick of its own: it follows its master only.
export function isProtectionEnabled(state, key) {
  const p = PROTECTION_BY_KEY[key];
  if (!(p && p.switchable === false) && state.disabledProtections[key] === true) return false;
  return !(p && p.requires && state.disabledProtections[p.requires] === true);
}

// 5.1.0 — the user's own tick only (the Protections page shows it; a dependent keeps its tick while its master is off).
// A protection without a checkbox of its own (`switchable: false`) reads its master's tick.
export function isProtectionTicked(state, key) {
  const p = PROTECTION_BY_KEY[key];
  return state.disabledProtections[p && p.switchable === false ? p.requires : key] !== true;
}

export function isInSaferRegions(state, host) {
  return !!host && !!state.safeZone && Array.isArray(state.safeZone.tlds) && isInDomainList(registeredDomain(host), state.safeZone.tlds);
}

export function saferRegionsApply(level) {
  return SAFER_REGIONS_LEVELS.includes(level);
}

export function isProtectionActive(state, key, level) {
  const p = PROTECTION_BY_KEY[key];
  // Guard (4.2.3, audit finding 8): an unknown key is a coding error — say so loudly instead of
  // silently treating the protection as off. tools/check-protection-keys.mjs catches it statically.
  if (!p) { console.error(LOG_PREFIX, "unknown protection key:", key); return false; }
  return isProtectionEnabled(state, key) && level >= p.fromLevel;
}

// SSS 1.0.0: three kinds of "locked" group, none of them a user choice —
//   LEVEL.ALLOW_ALL  — the whitelist (state.siteLocks, the only thing the user sets)
//   LEVEL.HIGH       — adult sites (core/auto-levels.js AUTO_ADULT_DOMAINS)
//   LEVEL.SMART      — abused-TLD sites (core/auto-levels.js strictGroupSites(state) — 1.0.1: computed
//                      from `state` on every rebuild, same as state.safeZone.tlds already is elsewhere,
//                      so the safer-regions TLD whitelist and the built-in trusted-platform whitelist are
//                      both honored. 1.0.2: the domain-list (Kees1958+HaGeZi) site membership this group
//                      used to also carry is gone — see that function's own header for why; the HTTP/
//                      IP-literal/unusual-port structural conditions it's replaced by are separate DNR
//                      rules in core/rule-builder.js, not group site membership)
// Precedence is DNR priority, not group order (whitelist's allowAllRequests rule outranks every
// block rule — data/constants.js PRIORITY.ALLOW_ALL_REQUESTS), so a whitelisted site that also
// happens to sit on an abused TLD is simply allowed: no need to subtract it from the other groups.
export function ruleGroups(state) {
  const allLocked = state.siteLocksOrder.slice();                 // the whitelist only (siteLocks is ALLOW_ALL-only now)
  const strict = strictGroupSites(state);
  const groups = [{ index: 0, level: FIXED_LEVEL, kind: GROUP_KIND.GLOBAL,
    sites: [...allLocked, ...AUTO_ADULT_DOMAINS, ...strict.sites] }];
  if (allLocked.length) groups.push({ index: LEVEL.ALLOW_ALL, level: LEVEL.ALLOW_ALL, kind: GROUP_KIND.LOCKED, sites: allLocked });
  if (AUTO_ADULT_DOMAINS.length) groups.push({ index: LEVEL.HIGH, level: LEVEL.HIGH, kind: GROUP_KIND.LOCKED, sites: AUTO_ADULT_DOMAINS });
  if (strict.sites.length) {
    groups.push({ index: LEVEL.SMART, level: LEVEL.SMART, kind: GROUP_KIND.LOCKED, sites: strict.sites, excludeSites: strict.excludeSites });
  }
  return groups;
}

// tabsByLevel: Map<level, Iterable<tabId>> (core/tab-locks.js). Capped per band (guard).
export function tabBandGroups(tabsByLevel) {
  const groups = [];
  for (const level of TAB_BAND_LEVELS) {
    const tabIds = [...(tabsByLevel.get(level) || [])].slice(0, TAB_BAND_TABS_MAX);
    if (tabIds.length) groups.push({ index: level, level, kind: GROUP_KIND.TAB, sites: [], tabIds, priorityBase: TAB_BAND_BASE });
  }
  return groups;
}

// 4.7.0 — see data/constants.js' "High-risk tab override" comment: one group, reserved index/priority
// band, so it can be active on a tab at the SAME TIME as that tab's own level-lock band.
export function highRiskTabGroups(tabIds) {
  const ids = [...(tabIds || [])].slice(0, TAB_BAND_TABS_MAX);
  if (!ids.length) return [];
  return [{ index: HIGH_RISK_GROUP_INDEX, level: LEVEL_MAX, kind: GROUP_KIND.TAB, sites: [], tabIds: ids, priorityBase: HIGH_RISK_TAB_BASE, highRiskOnly: true }];
}

// 4.7.0 — `risk` is the tab's own core/badge.js getRisk(tabId) result ({ site, severity } | null), passed
// in by the caller (this module makes no Chrome calls). Allow-listed (explicit trust) always wins.
export function isHighRiskSite(state, host, risk = null) {
  if (!host) return false;
  const site = registeredDomain(host);
  if (lockedLevelOf(state, site) === LEVEL.ALLOW_ALL) return false;
  if (HIGH_RISK_HOSTNAMES.includes(site)) return true;
  return !!(risk && risk.severity === SEVERITY.PHISHING && registeredDomain(risk.site) === site);
}

// 4.7.0 — for a mechanism that decides against a specific host/request at the moment it happens,
// rather than through a declarative rule/registration.
export function isProtectionActiveOrHighRisk(state, key, level, host, risk = null) {
  if (isProtectionActive(state, key, level)) return true;
  const p = PROTECTION_BY_KEY[key];
  return !!(p && p.alsoHighRisk && isProtectionEnabled(state, key) && isHighRiskSite(state, host, risk));
}

// 5.1.0: + `outside` — the protections scoped outside safer regions (the popup's level-3 bullet). Before 5.1.0 the
// popup counted the whole level-3 GROUP, which also held blockWasmDubious (every site); groups are per tab now, so
// the count is taken from the scope itself.
// SSS 1.0.0 (owner decision 2026-11-26): the `download` tally is gone with Download Protection.
export function protectionCounts(state, level) {
  const applicable = PROTECTIONS.filter((p) => level >= p.fromLevel);
  function onTab(tab) { return applicable.filter((p) => tabOf(p) === tab); }
  function activeIn(list) { return list.filter((p) => isProtectionEnabled(state, p.key)).length; }
  function switchOn(key) { return level >= PROTECTION_BY_KEY[key].fromLevel && isProtectionEnabled(state, key); }
  const firewall = onTab(PROTECTION_TAB.BROWSING);
  const outside = firewall.filter((p) => p.scope === SCOPE.OUTSIDE_SAFER_REGIONS);
  const scamOn = switchOn(PROTECTION_KEY.ENABLE_SCAM_PROTECTION);
  const tamperOn = switchOn(PROTECTION_KEY.WATCH_TAMPER_SENSITIVE);
  return {
    firewall: { active: activeIn(firewall), total: firewall.length, outside: { active: activeIn(outside), total: outside.length } },
    // the protections under the switch (its members), not the switch itself
    scam: { on: scamOn, active: scamOn ? onTab(PROTECTION_TAB.SCAM).filter((p) => p.requires === PROTECTION_KEY.ENABLE_SCAM_PROTECTION).length : 0 },
    // the signs it watches for (data/tamper-rules.js) — the trigger ticks only choose which pages
    tamper: { on: tamperOn, signs: tamperOn ? TAMPER_RULES.length : 0 }
  };
}

// ── 5.1.3: allow-list categories (Firewall / Scam / Tamper) ──
export function allowSitesOf(state, category) {
  return ALLOW_CATEGORIES_STORED.includes(category) && state.allowCategories ? state.allowCategories[category] : [];
}
export function isAllowedFor(state, category, host) {
  return !!host && allowSitesOf(state, category).includes(registeredDomain(host));
}
