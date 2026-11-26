// ── core/auto-levels.js ───────────────────────────────────────────────────────
// Safe Surfing Sentinel 1.0.0 — zero configuration: there is no slider and no per-site lock the
// user sets. A site's level is always ONE of: whitelisted (core/site-locks.js, LEVEL.ALLOW_ALL,
// user-controlled — the only thing the user ever touches), or computed HERE from static lists plus
// two per-installation lists carried in `state` (the safer-regions TLD whitelist, the built-in
// trusted-platform whitelist), or FIXED_LEVEL.
//
// 1.0.2 (owner decision 2026-11-26): the merged Kees1958+HaGeZi domain list (data/scam-host-list.js) no
// longer drives ANY of this. A domain-list hit names a shared platform, not something about the specific
// site visited — it stays a scam/URL-score signal only (core/site-scorer.js), never a block or auto-raise
// trigger. In its place, three structural per-visit signals now drive the 3P block AND the auto-raise,
// alongside the abused-TLD check: plain HTTP, a bare public IP host, an unusual explicit port. These are
// properties of THIS navigation, not of the domain in general, so autoLevelOf() takes the full parsed URL
// (host + protocol + port — exactly what util/domain.js parseHttpUrl() already returns), not a bare host.
//
// Precedence (data/constants.js AUTO_LEVEL_RULES, first match wins; owner decisions 2026-11-26):
//   1. adult site (data/network-data.js HIGH_RISK_HOSTNAMES)                      → LEVEL.HIGH
//   2. built-in trusted-platform whitelist (data/builtin-domains.js BUILTIN_ALL)  → never raised to
//      LEVEL.SMART — wins over every check below it, however they'd otherwise score.
//   3. abused TLD (data/spam-tlds.js SPAM_TLDS, minus SPAM_TLD_EXCEPTIONS, minus the user's own
//      safer-regions TLD whitelist — state.safeZone.tlds, same list core/policy.js's
//      isInSaferRegions() checks — TLD whitelist wins here)                       → LEVEL.SMART
//   4. plain HTTP (the page itself is unencrypted)                                → LEVEL.SMART
//   5. bare public IP host (private/loopback/link-local excluded — util/domain.js isPrivateHost)
//                                                                                  → LEVEL.SMART
//   6. unusual explicit port (data/constants.js USUAL_PORTS — an IMPLICIT default port, i.e. no ":port"
//      at all in the URL, is never flagged here; see USUAL_PORTS' own comment)     → LEVEL.SMART
//   else                                                                          → FIXED_LEVEL
//
// Public interface:
//   autoLevelOf(state, p) -> { level, status, source: AUTO_LEVEL_SOURCE.* | null } — p is a parsed-URL
//                          object with .host, .protocol, .port (util/domain.js parseHttpUrl()'s shape;
//                          every caller already has one of these in hand at the point it calls this).
//   isAutoElevated(state, site) -> boolean — adult OR abused TLD (i.e. autoLevelOf's DOMAIN-level rules,
//                          with the PER-VISIT structural rules deliberately excluded: this answers "is
//                          this domain itself inherently flagged", used only to decide whether adding it
//                          to the whitelist is permanent or session-only — core/site-locks.js. Whether
//                          today's visit happened to be over HTTP or on an odd port says nothing about
//                          the DOMAIN, so it plays no part in that one decision.
//   strictGroupSites(state)   -> { sites, excludeSites } — the LEVEL.SMART DNR group's live membership:
//                          sites = SPAM_TLDS minus the user's safer-regions TLDs (domain-list membership
//                          is the only thing a static DNR site-list can express; the HTTP/IP/port block
//                          conditions are added directly as DNR rules in core/rule-builder.js instead —
//                          see that file for why: they're request-shape conditions, not site membership);
//                          excludeSites = SPAM_TLD_EXCEPTIONS + BUILTIN_ALL. Computed fresh from `state`
//                          wherever rules are rebuilt (core/policy.js ruleGroups(), core/script-builder.js),
//                          exactly like state.safeZone.tlds already is elsewhere in those two files.
//   AUTO_ADULT_DOMAINS    — HIGH_RISK_HOSTNAMES, for the LEVEL.HIGH group (static — adult sites don't
//                          depend on per-installation state).
// ─────────────────────────────────────────────────────────────────────────────

import { FIXED_LEVEL, AUTO_LEVEL_SOURCE, AUTO_LEVEL_RULES, STATUS_OF_LEVEL, USUAL_PORTS } from "../data/constants.js";
import { SPAM_TLDS, SPAM_TLD_EXCEPTIONS } from "../data/spam-tlds.js";
import { HIGH_RISK_HOSTNAMES } from "../data/network-data.js";
import { BUILTIN_ALL } from "../data/builtin-domains.js";
import { registeredDomain, isInDomainList, isIpHost, isPrivateHost } from "../util/domain.js";

export const AUTO_ADULT_DOMAINS = HIGH_RISK_HOSTNAMES;

const RULE_BY_SOURCE = Object.freeze(Object.fromEntries(AUTO_LEVEL_RULES.map((r) => [r.source, r])));

function safeZoneTlds(state) {
  return (state && state.safeZone && Array.isArray(state.safeZone.tlds)) ? state.safeZone.tlds : [];
}
function isBuiltinTrusted(site) {
  return isInDomainList(site, BUILTIN_ALL);
}
// The exact SPAM_TLDS token a site matched (e.g. "xyz", or a compound one like "co.com"), or null.
// Deliberately NOT isInDomainList(site, SPAM_TLDS) reused here with the match kept — see isAbusedTld
// below for why the exemption check needs this exact token, not a second suffix test against the site.
function matchedSpamTld(site) {
  for (const t of SPAM_TLDS) { if (site === t || site.endsWith("." + t)) return t; }
  return null;
}
// Rule 3: TLD whitelist wins over an abused-TLD hit — but the comparison is EXACT-TOKEN (is the matched
// abused TLD itself, e.g. "co.com", literally one of the user's safer-regions entries?), not a suffix
// test of the whole site against that list. A suffix test would be wrong here: safer-regions entries are
// almost always plain TLDs like "com"/"nl", and a site on a COMPOUND abused TLD such as "co.com" or
// "us.org" ends in ".com"/".org" too — isInDomainList(site, safeTlds) would then exempt every one of
// those compound abused TLDs by accident, any time the plain TLD is in the (near-universal) default
// safer-regions base set. Comparing the matched token itself avoids that: "co.com" only wins here if
// "co.com" is itself in the user's list, which real ccTLD/gTLD auto-add logic never produces.
function isAbusedTld(state, site) {
  const t = matchedSpamTld(site);
  if (!t) return false;
  if (isInDomainList(site, SPAM_TLD_EXCEPTIONS)) return false;
  return !safeZoneTlds(state).includes(t);
}
function isAdultSite(site) {
  return HIGH_RISK_HOSTNAMES.includes(site);
}
// Rule 4: the page itself is plain HTTP.
function isPlainHttp(protocol) {
  return protocol === "http:";
}
// Rule 5: a bare public IP address, not a domain name — private/loopback/link-local hosts (a home
// router, a local dev server, a printer) are explicitly NOT this: isPrivateHost already covers RFC1918,
// loopback and link-local (util/domain.js), the same check core/site-scorer.js uses to skip scoring
// private hosts entirely.
function isPublicIpLiteral(host) {
  return isIpHost(host) && !isPrivateHost(host);
}
// Rule 6: an EXPLICIT port in the URL outside USUAL_PORTS. A URL with no ":port" at all (the ordinary
// case — p.port is "") is never flagged here, same convention core/site-scorer.js's NonStandardPort
// check already uses: an implicit default port says nothing unusual on its own, and plain HTTP on its
// own default port is already caught by isPlainHttp() above, not this check.
function isUnusualPort(port) {
  return !!port && !USUAL_PORTS.includes(Number(port));
}

// Rule 2 only — adult and abused-TLD are the DOMAIN-level facts this answers about (see file header for
// why the structural per-visit signals are deliberately excluded from this one).
export function isAutoElevated(state, site) {
  if (isAdultSite(site)) return true;
  if (isBuiltinTrusted(site)) return false;    // built-in whitelist always wins
  return isAbusedTld(state, site);
}

// p → { level, status, source } — the automatic level BEFORE the whitelist override (core/policy.js
// applies the whitelist first and never calls this for a whitelisted host). p is a parsed-URL object
// ({ host, protocol, port, ... } — util/domain.js parseHttpUrl()); every call site already has one.
export function autoLevelOf(state, p) {
  const host = p ? p.host : "";
  const site = registeredDomain(host);
  if (isAdultSite(site)) { const r = RULE_BY_SOURCE[AUTO_LEVEL_SOURCE.ADULT]; return { level: r.level, status: r.status, source: r.source }; }
  if (isBuiltinTrusted(site)) return { level: FIXED_LEVEL, status: STATUS_OF_LEVEL[FIXED_LEVEL], source: null };   // rule 2
  if (isAbusedTld(state, site)) { const r = RULE_BY_SOURCE[AUTO_LEVEL_SOURCE.ABUSED_TLD]; return { level: r.level, status: r.status, source: r.source }; }
  if (p && isPlainHttp(p.protocol)) { const r = RULE_BY_SOURCE[AUTO_LEVEL_SOURCE.PLAIN_HTTP]; return { level: r.level, status: r.status, source: r.source }; }
  if (isPublicIpLiteral(host)) { const r = RULE_BY_SOURCE[AUTO_LEVEL_SOURCE.IP_LITERAL]; return { level: r.level, status: r.status, source: r.source }; }
  if (p && isUnusualPort(p.port)) { const r = RULE_BY_SOURCE[AUTO_LEVEL_SOURCE.UNUSUAL_PORT]; return { level: r.level, status: r.status, source: r.source }; }
  return { level: FIXED_LEVEL, status: STATUS_OF_LEVEL[FIXED_LEVEL], source: null };
}

// SPAM_TLDS with the user's own safer-regions TLDs removed — exact-token filter, same reasoning as
// isAbusedTld() above: a safer-regions entry like "com" must not drop a compound abused TLD like
// "co.com" just because it ends in ".com". Single source of truth for every consumer that blocks or
// auto-raises on an abused TLD: strictGroupSites() below (Level 3 auto-raise) AND
// core/rule-builder.js's 3P-script/frame and WebAssembly abused-TLD block rules.
export function effectiveAbusedTlds(state) {
  const safeTlds = safeZoneTlds(state);
  return safeTlds.length ? SPAM_TLDS.filter((tld) => !safeTlds.includes(tld)) : SPAM_TLDS;
}

// The LEVEL.SMART DNR group's live membership (core/policy.js ruleGroups(), core/script-builder.js) —
// domain-list membership only (abused TLDs) — see file header for why the structural signals (HTTP,
// IP-literal, unusual port) are NOT part of this and are instead separate DNR rules in rule-builder.js.
export function strictGroupSites(state) {
  return {
    sites: [...effectiveAbusedTlds(state)],
    excludeSites: [...SPAM_TLD_EXCEPTIONS, ...BUILTIN_ALL]
  };
}
