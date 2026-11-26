// ── core/view-models.js ───────────────────────────────────────────────────────
// What each page receives from the service worker: one function per page, state in, plain data
// out (JSON-serializable, C31). Pages hold no business logic — they render these models.
//
// SSS 1.0.0: zero configuration. The popup is the ONLY page with a model now (an on/off switch
// for the current site + a one-sentence status, uBD-style) — the level slider, the Protections
// tab counts, the DNS/allow-list/download-settings options page and Show Matrix are all gone
// (data/message-types.js, ARCHITECTURE.md). The whitelist page (ui/whitelist.*) talks to
// core/site-locks.js directly (sites: string[]) and needs no model of its own.
//
// Public interface:
//   popupModel(state, tabId, url)   — Promise (4.5.4: awaits the badge restore) — popup: whether this
//                                     site is whitelisted, its automatic status, and the "This page"
//                                     box (site risk, tamper rating, Continue once — 5.1.3, unchanged)
//   firewallBlockCount(ruleIds)     — Promise<number> — 5.1.3: of the rules Chrome says matched in the tab (the popup's
//                                     getMatchedRules), how many are block rules (all of 3P Matrix's block rules are firewall)
// ─────────────────────────────────────────────────────────────────────────────

import { SEVERITY, TAMPER_RATING, POPUP_RISK_REASONS_MAX, POPUP_MATCHED_RULES_MAX } from "../data/constants.js";
import { TAMPER_RATING_LABEL, TAMPER_RULE_BY_ID } from "../data/tamper-rules.js";
import { scoreLocal } from "./site-scorer.js";
import { isAllowedOnce } from "./navigation-guard.js";
import { pageRisk, pageFindings } from "./tamper-guard.js";
import { siteStatus } from "./policy.js";
import { getCompiledRules } from "./apply-manager.js";
import { isWhitelisted } from "./site-locks.js";
import * as Badge from "./badge.js";
import { parseHttpUrl, registeredDomain } from "../util/domain.js";

// 5.1.3 — the popup's "This page" box: only what there is to know (each part null / false when there is nothing).
//   risk      — the site check's verdict for the tab's site (core/badge.js keeps it per tab) with its top reasons
//   tamper    — the page's tamper rating when Suspicious or worse, how many findings, and (owner, 2026-11-24) the name
//               of the most serious one (`topLabel`, data/tamper-rules.js label) so the line says WHAT was found
//   continued — "Continue once" was chosen for this site in this tab (core/navigation-guard.js)
// The most serious finding's name (most points; on equal points the one found first).
function topFindingLabel(tabId) {
  const top = pageFindings(tabId).reduce((best, f) => (!best || f.points > best.points ? f : best), null);
  return top ? TAMPER_RULE_BY_ID[top.rule].label : "";
}

async function pageBox(tabId, url, p) {
  const stored = Badge.getRisk(tabId);
  const severity = stored && p && stored.site === registeredDomain(p.host) ? stored.severity : SEVERITY.NONE;
  const local = severity !== SEVERITY.NONE ? scoreLocal(url) : null;
  const risk = severity === SEVERITY.NONE ? null
    : { severity, reasons: local ? local.signals.slice(0, POPUP_RISK_REASONS_MAX) : [] };
  const t = pageRisk(tabId);
  const tamper = t && t.armed && t.rating >= TAMPER_RATING.SUSPICIOUS     // owner 2026-11-24: watched pages only
    ? { rating: t.rating, ratingLabel: TAMPER_RATING_LABEL[t.rating], findings: t.findings, topLabel: topFindingLabel(tabId) } : null;
  const continued = !!p && Number.isInteger(tabId) && await isAllowedOnce(tabId, registeredDomain(p.host));
  return { risk, tamper, continued };
}

// 4.5.4: async — waits until the badge's per-tab state is restored (core/badge.js ready()), so a popup
// that wakes the service worker still shows the site's risk.
// SSS 1.0.0: no level, no groups, no counts — `whitelisted` is the popup's one switch, `status` is its
// one status line (data/constants.js SITE_STATUS_TEXT; core/policy.js siteStatus — whitelist, else the
// automatic reason: adult / abused-TLD / risky-domain / standard).
export async function popupModel(state, tabId, url) {
  await Badge.ready();
  const p = parseHttpUrl(url || "");
  const host = p ? p.host : "";
  const site = p ? registeredDomain(host) : "";
  return {
    host, site,
    scorable: !!p,
    whitelisted: p ? isWhitelisted(state, site) : false,
    status: p ? siteStatus(state, p) : null,
    page: await pageBox(tabId, url, p)                 // 5.1.3
  };
}

// 5.1.3 — every block rule of 3P Matrix belongs to the firewall (the level rules and the Firewall protection tab's DNR
// rules; Scam protection's frame rule is a header rule, Download and Tamper protection have no DNR rules). Header and
// allow rules are not counted. Ids are those the popup got from chrome.declarativeNetRequest.getMatchedRules.
export async function firewallBlockCount(ruleIds) {
  if (!Array.isArray(ruleIds)) return 0;
  const blocks = new Set((await getCompiledRules()).filter((r) => r.action === "block").map((r) => r.id));
  return ruleIds.slice(0, POPUP_MATCHED_RULES_MAX).filter((id) => blocks.has(id)).length;
}
