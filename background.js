// ── background.js — 3P Matrix service worker (lifecycle + thin router) ───────
// No business logic here: every branch validates its input and delegates to a core/ or data/
// module (4.2.3, audit finding 6: lock/allow-list → core/site-locks.js, safer-regions edit →
// core/safer-regions.js, Show Matrix overrides → core/matrix-overrides.js, panel windows →
// core/matrix-windows.js, page models → core/view-models.js).
//
// Lifecycle
//   install          → default state, compute safer regions, apply
//   update / reload  → load state, level = startupLevel, recompute safer regions, apply
//   browser startup  → level = startupLevel, apply; the whitelist's session-only entries are purged
//   every SW start   → tab band rebuilt from the open tabs (the in-memory assignment is lost on a restart)
//
// Events
//   webRequest.onBeforeRequest (main_frame)    → 5.1.3: ONE listener for a new top-level page: tab band (4.4.5), then
//                                                one warning per navigation — XSS link first, else the stage 1 site
//                                                check (warnSuspiciousSites). (webNavigation.onBeforeNavigate: gone)
//   webNavigation.onCommitted (top frame)      → tamper mark reset, per-tab icon, tab band (after redirects)
//   webRequest.onErrorOccurred (exfiltration hosts only) → the exfiltration warning (rule-matcher attribution);
//                                                5.1.3: no blocked-request counting — the popup asks Chrome
//                                                (getMatchedRules, activeTab) when it opens
//   webRequest.onBeforeRequest (device sign-in pages only) → device-code warning (4.7.0)
//   tabs.onRemoved / windows.onRemoved         → release per-tab state and Tamper Guard warning windows (guards)
//   Tamper Guard (5.1.0)                       → page reports via the router (core/tamper-guard.js); onCommitted starts
//                                                a tracked tab's new page; tabs/windows.onRemoved release its window;
//                                                5.1.3: the password-form, skimmer and fake sign-in decisions are also
//                                                recorded as tamper findings (Tamper.recordOwnWarning)
//   alarms.onAlarm                             → Chrome out-of-date check (core/browser-update.js)
//
// Download Protection (warnRiskyDownloads/blockRiskyDownloads, VirusTotal, core/download-guard.js and the download
// UI pages) was removed entirely in SSS 1.0.0 (owner decision 2026-11-26: "remove download guard").
//
// All state mutations go through mutate(): load → change → save → apply, run
// under withStateLock() so two messages can never interleave.
// ─────────────────────────────────────────────────────────────────────────────

import { LEVEL_INFO, LOG_PREFIX, SEVERITY, WARNING_PAGE, WARNING_TARGET_PARAM, WARNING_REASON_PARAM, WARNING_REFERRER_PARAM,
         CHROME_BLOCKED_BY_CLIENT_ERROR, CHROME_NEW_TAB_URL,
         RT, TAMPER_WARNING_PAGE, TAMPER_WARNING_ID_PARAM } from "./data/constants.js";
import * as M from "./data/message-types.js";
import { defaultState, loadState, saveState, withStateLock, isValidHost } from "./data/state-storage.js";
import { PROTECTION_BY_KEY, PROTECTION_KEY } from "./data/protections.js";
import { PAGE_SCAM_REASON_BY_ID, PAGE_SCAM_KIND, LEAVE, ALLOW_FROM } from "./data/page-scam-reasons.js";
import { DEVICE_CODE_URL_PATTERNS } from "./data/device-code-pages.js";
import { siteStatus } from "./core/policy.js";
import { applyState, applySessionRules, getCompiledRules } from "./core/apply-manager.js";
import { matchOutcome } from "./core/rule-matcher.js";
import { computeSaferRegions } from "./core/safer-regions.js";   // automatic only (browser languages) — no editor (SSS 1.0.0)
import { scoreLocal } from "./core/site-scorer.js";
import { evaluateSite } from "./core/online-checks.js";
import { popupModel, firewallBlockCount } from "./core/view-models.js";
import * as Badge from "./core/badge.js";
import * as Guard from "./core/navigation-guard.js";
import * as DeviceCode from "./core/device-code-guard.js";          // 4.7.0 — warnDeviceCodePages
import { EXFIL_URL_PATTERNS } from "./data/exfil-channels.js";   // 5.1.3 — the exfiltration listener's filter
import * as XssLink from "./core/xss-link-guard.js";                // 5.1.2 — warnXssLinks
import { senderKind, isMessageAllowed, senderLabel } from "./core/message-gate.js";   // 5.0.6 — C46 sender kinds
import * as PageScam from "./core/page-scam-guard.js";               // 4.7.0 — ClickFix / ConsentFix → warning
import * as BrowserUpdate from "./core/browser-update.js";           // 4.7.0 — Chrome out-of-date band
// core/connection-matrix.js (Show Matrix) is no longer wired into the UI — SSS 1.0.0 is zero-configuration.
// Left in place, unreferenced here, rather than deleted outright (see ARCHITECTURE.md note).
import * as TabSites from "./core/tab-sites.js";
import * as TabLocks from "./core/tab-locks.js";
import * as Exfil from "./core/exfil-guard.js";                 // 4.6.0 — exfiltration block → site warning
import { leaveSite } from "./core/leave-site.js";               // 4.6.0 — "Go back" that leaves the site
import { passwordFormDecision, fakeWindowDecision } from "./core/password-form.js"; // 4.6.0 warnPasswordForms; 4.7.0 blockFakeSignInWindow
import { isWhitelisted, toggleWhitelist, allowListSites, addSiteToWhitelist, removeSiteFromWhitelist, clearWhitelist,
         clearSessionWhitelist, importWhitelist, addToAllowList } from "./core/site-locks.js";
import { exportWhitelistFile, parseWhitelistFile } from "./data/whitelist-io.js";
import * as Tamper from "./core/tamper-guard.js";                 // 5.1.0 — Tamper Guard decisions
Tamper.setMarkSink(Badge.setTamperRating);                        // 5.1.3 — the page's tamper rating on the badge ("?" / "!")
Badge.init();                                                      // 5.1.3 — every SW start: Chrome's own block count, grey
import * as TamperWarnings from "./core/tamper-warnings.js";      // 5.1.0 — its warning windows
import { ALLOW_CATEGORY } from "./data/allow-categories.js";
import { parseHttpUrl, registeredDomain } from "./util/domain.js";

// ── Core helpers ─────────────────────────────────────────────────────────────
async function commit(state) {
  const saved = await saveState(state);
  await TabLocks.rebuild(saved);                        // locks/level may have changed: re-assign every open tab first
  await applyState(saved);
  Badge.setSiteIcon(null);
  await refreshActiveTabIcon(saved);
  return saved;
}

function mutate(change) {
  return withStateLock(async () => {
    const state = await loadState();
    const result = await change(state);
    const saved = await commit(state);
    return { state: saved, result };
  });
}

async function refreshActiveTabIcon(state) {
  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    const p = tab && parseHttpUrl(tab.url || "");
    if (tab && p) Badge.setSiteIcon(siteStatus(state, p).status, tab.id);
  } catch { /* no window yet at browser start — global icon is enough */ }
}

// ── Lifecycle ────────────────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener((details) => {
  withStateLock(async () => {
    const state = details.reason === "install" ? defaultState() : await loadState();
    state.level = state.startupLevel;
    state.prevLevel = state.startupLevel;
    // Every reason (install, update, reload): the list depends on code (base TLDs, auto-add
    // scope, country data) — 0.2.4 moves users of the removed slider to the fixed Continent scope.
    state.safeZone.tlds = await computeSaferRegions(state.safeZone);
    await commit(state);
  }).catch((e) => console.error(LOG_PREFIX, "onInstalled:", e));
});

chrome.runtime.onStartup.addListener(() => {
  withStateLock(async () => {
    const state = await loadState();
    state.level = state.startupLevel;
    state.prevLevel = state.startupLevel;
    clearSessionWhitelist(state);   // a real browser start only — the "this browsing session" whitelist entries end here
    return commit(state);
  }).catch((e) => console.error(LOG_PREFIX, "onStartup:", e));
});

BrowserUpdate.init();                                    // 4.7.0 — daily alarm (idempotent)

// Tab band (4.4.5): a tab joined, left or closed its site lock's band → re-apply only the session rules.
function syncTabBand(tabId, url) {
  loadState().then((state) => (TabLocks.assign(state, tabId, url) ? applySessionRules(state) : null))
    .catch((e) => console.error(LOG_PREFIX, "tab band:", e));
}

// Every SW start: the session rules Chrome kept are still there, the in-memory assignment is not.
loadState().then(async (state) => { await TabLocks.rebuild(state); await applySessionRules(state); })
  .catch((e) => console.error(LOG_PREFIX, "tab band init:", e));

// ── Navigation / request events (registered synchronously at top level) ─────
// 5.1.3 — ONE listener for the start of a new top-level page (webRequest, main_frame only; webNavigation.onBeforeNavigate
// fired for every frame of every page): the tab band, then one warning per navigation — the XSS-link warning first
// (more specific, names the site that sent you), else the suspicious-site check (issue: two redirects used to race).
// The XSS pre-check runs before the state is loaded, as before.
chrome.webRequest.onBeforeRequest.addListener((details) => {
  if (details.tabId < 0) return;
  syncTabBand(details.tabId, details.url);              // before the page creates its frames
  const mayBeXss = XssLink.mayBeXssLink(details);
  loadState().then(async (state) => {
    const xssWarned = mayBeXss ? await XssLink.onXssLinkRequest(details, state) : false;
    await Guard.checkNavigation(details, state, !xssWarned);   // main_frame: frameId 0
  }).catch((e) => console.error(LOG_PREFIX, "navigation check:", e));
}, { urls: ["<all_urls>"], types: ["main_frame"] });

chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return;
  syncTabBand(details.tabId, details.url);              // final URL, after redirects
  Badge.resetPage(details.tabId);                       // 5.1.3: the tamper mark belongs to the page
  const p = parseHttpUrl(details.url);
  TabSites.setTopHost(details.tabId, p ? p.host : "");
  Tamper.onCommitted(details.tabId, details.url);       // 5.1.0 — a tracked tab's new page (cooldown or standby)
  if (!p) return;
  Badge.clearRiskIfOtherSite(details.tabId, registeredDomain(p.host));
  loadState().then((state) => Badge.setSiteIcon(siteStatus(state, p).status, details.tabId))
    .catch((e) => console.error(LOG_PREFIX, "tab icon:", e));
});

// 5.1.3 — the exfiltration warning only: a request to one of the exfiltration channels' hosts that was blocked (by
// any extension — rule-matcher.js replays OUR rules to be sure it was ours). Filtered to those hosts, so the service
// worker no longer wakes for every failed request on every page (the 5.1.2 blocked-request count is gone: the
// popup asks Chrome when it opens, core/view-models.js).
function onExfilRequestError(details) {
  if (details.error !== CHROME_BLOCKED_BY_CLIENT_ERROR || details.tabId < 0) return;
  Promise.all([getCompiledRules(), TabSites.topHostOf(details.tabId)]).then(([compiled, topHost]) => {
    const outcome = matchOutcome(compiled, details, topHost);
    if (outcome.action === "block") return Exfil.onBlockedRequest(details.tabId, outcome.ruleId);
    return null;
  }).catch((e) => console.warn(LOG_PREFIX, "exfiltration block attribution failed:", e));
}
// Guard (as before 5.1.3): a Chrome that does not know one of the types throws here — then listen without the type
// filter (still only the exfiltration hosts), never without a listener and never aborting the worker's start.
try {
  chrome.webRequest.onErrorOccurred.addListener(onExfilRequestError, { urls: [...EXFIL_URL_PATTERNS], types: [...RT.ALL_SUB] });
} catch (e) {
  console.warn(LOG_PREFIX, "webRequest type filter rejected — listening without it:", e);
  chrome.webRequest.onErrorOccurred.addListener(onExfilRequestError, { urls: [...EXFIL_URL_PATTERNS] });
}

// ── Device-code warning (warnDeviceCodePages, 4.7.0) — filtered to the known device sign-in pages, so the service
// worker wakes ONLY for them. `initiator` (who started the navigation — a page cannot fake or hide it, unlike the
// Referer header) exists on webRequest events, not on webNavigation, hence this separate listener. Non-blocking:
// the real page is not held (as warnSuspiciousSites), the tab races to the warning instead.
chrome.webRequest.onBeforeRequest.addListener((details) => {
  loadState().then((state) => DeviceCode.onDeviceCodeRequest(details, state))
    .catch((e) => console.error(LOG_PREFIX, "device-code check:", e));
}, { urls: [...DEVICE_CODE_URL_PATTERNS], types: ["main_frame"] });

chrome.alarms.onAlarm.addListener((alarm) => {
  BrowserUpdate.onAlarm(alarm).catch((e) => console.error(LOG_PREFIX, "browser-update check:", e));   // 4.7.0
});

// A tab swapped for another one (prerender, instant navigation): the old id is gone, the new one is re-read.
chrome.tabs.onReplaced.addListener((addedTabId, removedTabId) => {
  releaseBand(removedTabId);
  chrome.tabs.get(addedTabId).then((tab) => syncTabBand(addedTabId, tab.url || tab.pendingUrl))
    .catch(() => { /* gone already */ });
});

function releaseBand(tabId) {
  if (TabLocks.release(tabId)) loadState().then(applySessionRules).catch((e) => console.error(LOG_PREFIX, "tab band release:", e));
}

chrome.tabs.onRemoved.addListener((tabId) => {
  releaseBand(tabId);
  Badge.releaseTab(tabId);
  Guard.releaseTab(tabId);
  TabSites.releaseTab(tabId);
  Tamper.releaseTab(tabId);                             // 5.1.0 — its watch record and warning window
});

chrome.windows.onRemoved.addListener((windowId) => {
  TamperWarnings.onWindowRemoved(windowId);             // 5.1.0 — a Tamper Guard warning window closed
});

// ── Input guards (audit finding 11 — C6 / C28) ───────────────────────────────
function requireTabId(msg) {
  if (!Number.isInteger(msg.tabId) || msg.tabId < 0) throw new Error("bad tab");
  return msg.tabId;
}

// This extension's own origin ("chrome-extension://<id>/") — an extension-page sender's URL starts with it (C46).
const EXTENSION_ORIGIN = chrome.runtime.getURL("");

// The site a warning-page message is about: taken from the sender's own URL (?u=) when the
// message comes from our warning page (C28 — never trust a message field when the sender says
// it), else from msg.url (pages that act on another tab's URL, e.g. tests and the popup).
function warningTarget(msg, sender) {
  const warningPage = chrome.runtime.getURL(WARNING_PAGE);
  if (sender.url && sender.url.startsWith(warningPage)) {
    const u = new URL(sender.url).searchParams.get(WARNING_TARGET_PARAM);
    if (u) return u;
  }
  return msg.url || "";
}

// 5.1.3: the site that sent the user (deviceCode / xssLink) — ONLY from the warning page's own URL (C28); a valid host or "".
function warningReferrer(sender) {
  const warningPage = chrome.runtime.getURL(WARNING_PAGE);
  if (!sender.url || !sender.url.startsWith(warningPage)) return "";
  const r = String(new URL(sender.url).searchParams.get(WARNING_REFERRER_PARAM) || "").toLowerCase();
  return isValidHost(r) ? r : "";
}

// 4.6.0: the exfiltration channel the warning is about — ONLY from the warning page's own URL (C28).
function warningReason(sender) {
  const warningPage = chrome.runtime.getURL(WARNING_PAGE);
  return sender.url && sender.url.startsWith(warningPage) ? new URL(sender.url).searchParams.get(WARNING_REASON_PARAM) : null;
}

// 4.6.0: pages a content-script message comes from — ONLY from the sender, which Chrome vouches for (C28).
// The FRAME holding the form decides "same site or not" (a login frame posting to its own site is fine);
// leaving goes by the TAB's top page, the site the user sees.
function senderFrameUrl(sender) { return sender.url || (sender.tab && sender.tab.url) || ""; }
function senderTabUrl(sender)   { return (sender.tab && sender.tab.url) || ""; }

// 5.1.0: the Tamper Guard warning a warning-window message is about — ONLY from the sender's own URL (C28).
function tamperWarningId(sender) {
  const page = chrome.runtime.getURL(TAMPER_WARNING_PAGE);
  if (!sender.url || !sender.url.startsWith(page)) throw new Error("not the Tamper Guard warning");
  const id = new URL(sender.url).searchParams.get(TAMPER_WARNING_ID_PARAM);
  if (!id) throw new Error("bad warning id");
  return id;
}

// ── Message router ───────────────────────────────────────────────────────────
const HANDLERS = {
  [M.MSG_GET_POPUP_STATE]: async (msg) => popupModel(await loadState(), msg.tabId, msg.url),
  // 5.1.3 — the popup's firewall count and "Details" (extension pages only: the message gate refuses content scripts)
  [M.MSG_COUNT_FIREWALL_BLOCKS]: async (msg) => firewallBlockCount(msg.ruleIds),
  [M.MSG_SHOW_TAMPER_DETAILS]: async (msg) => Tamper.showDetails(requireTabId(msg)),

  // SSS 1.0.0 — zero configuration: the ONLY thing the user ever sets is the whitelist. There is no level,
  // no startup level, no per-protection tick, no safer-regions editor and no Show Matrix (3P-Matrix-lite's
  // slider, locks and panel are all gone — core/auto-levels.js decides everything else).
  [M.MSG_TOGGLE_WHITELIST]: async (msg) => {
    const p = parseHttpUrl(msg.url || "");
    if (!p) throw new Error("not a web page");
    const site = registeredDomain(p.host);
    const { state } = await mutate((s) => toggleWhitelist(s, site));
    return popupModel(state, msg.tabId, msg.url);
  },

  [M.MSG_RELOAD_TAB]: async (msg) => { await chrome.tabs.reload(requireTabId(msg)); return true; },

  [M.MSG_EVALUATE_SITE]: async (msg, sender) => {
    const state = await loadState();
    const local = scoreLocal(warningTarget(msg, sender));
    if (!local) return null;
    const full = await evaluateSite(local, state.dns);
    if (sender.tab) {
      Badge.setRisk(sender.tab.id, full.site, full.severity);
      // 4.7.0: a PHISHING verdict (or a cleared one) changes the alsoHighRisk tab band — re-apply.
      applySessionRules(state).catch((e) => console.error(LOG_PREFIX, "high-risk band (evaluate site):", e));
    }
    return { ...full, levelInfo: LEVEL_INFO };
  },

  [M.MSG_WARNING_ACTION]: async (msg, sender) => {
    const tabId = sender.tab ? sender.tab.id : msg.tabId;
    const p = parseHttpUrl(warningTarget(msg, sender));
    if (!p || tabId === undefined) throw new Error("bad warning action");
    const site = registeredDomain(p.host);
    const reason = warningReason(sender);
    // 4.7.0: a page-scam reason (data/page-scam-reasons.js) may ask for LEAVE.NEW_TAB instead of walking the site's
    // own history back (deviceCode: going back one step would return to the site that SENT the user here).
    const scam = reason ? PAGE_SCAM_REASON_BY_ID[reason] : null;
    if (msg.action === M.WARNING_ACTION.GO_BACK) {
      if (scam && scam.leave === LEAVE.NEW_TAB) { await chrome.tabs.update(tabId, { url: CHROME_NEW_TAB_URL }); return true; }
      if (reason) { await leaveSite(tabId, site); return true; }   // exfiltration or a site-leaving page scam
      try { await chrome.tabs.goBack(tabId); }
      catch { await chrome.tabs.update(tabId, { url: CHROME_NEW_TAB_URL }); }   // no history: open a new-tab page
      return true;
    }
    if (msg.action === M.WARNING_ACTION.TRUST) {
      // 5.1.3: "Always allow" / "Always ignore" — one allow-list line for the warning's category (no longer "All"):
      //   a page-scam reason → its own category and site (the page's, or the site that sent the user);
      //   an exfiltration block → Firewall, the page's site; the ordinary suspicious-site warning → Scam, the page's site.
      if (scam && scam.canTrust === false) throw new Error("this warning has no Always action");
      const category = scam ? scam.allow.category : (reason ? ALLOW_CATEGORY.FIREWALL : ALLOW_CATEGORY.SCAM);
      const allowHost = scam && scam.allow.from === ALLOW_FROM.SENDER ? warningReferrer(sender) : p.host;
      if (!allowHost) throw new Error("no site to allow");
      await mutate((s) => addToAllowList(s, category, allowHost));
      Badge.setRisk(tabId, site, SEVERITY.NONE);
      // 4.7.0: trusting the site also drops it from the alsoHighRisk tab band — re-apply.
      loadState().then(applySessionRules).catch((e) => console.error(LOG_PREFIX, "high-risk band (trust):", e));
    } else if (msg.action === M.WARNING_ACTION.CONTINUE_ONCE) {
      await Guard.allowOnce(tabId, site);                   // stored before the tab reloads (4.5.4)
    } else {
      throw new Error("unknown warning action");
    }
    await chrome.tabs.update(tabId, { url: p.url });
    return true;
  },

  // ── Password-field warnings (page from the sender only, C28) ──
  // 5.1.3 (issue 3): a warning decision is also recorded as a tamper finding (core/tamper-guard.js recordOwnWarning).
  [M.MSG_CHECK_PASSWORD_FORM]: async (msg, sender) => {
    const state = await loadState();
    const decision = passwordFormDecision(state, senderFrameUrl(sender), String(msg.actionUrl || ""));
    if (decision.warn) Tamper.recordOwnWarning(state, PROTECTION_KEY.WARN_PASSWORD_FORMS, sender, [decision.destHost]);
    return decision;
  },

  // 4.7.0 — blockFakeSignInWindow (Browser-in-the-Browser). 5.0.6: on a hit the service worker opens
  // the red warning page itself (C47 — an in-page dialog could be removed by the page); the reply only says so.
  [M.MSG_CHECK_FAKE_WINDOW]: async (msg, sender) => {
    const state = await loadState();
    const decision = fakeWindowDecision(state, senderFrameUrl(sender), String(msg.shownText || ""));
    if (!decision.warn) return { warned: false };
    Tamper.recordOwnWarning(state, PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW, sender, [decision.shownHost]);   // issue 3
    const warned = await PageScam.openPageScamWarning(state, PAGE_SCAM_KIND.FAKE_SIGN_IN_WINDOW, PROTECTION_KEY.BLOCK_FAKE_SIGNIN_WINDOW, sender);
    return { warned };
  },

  [M.MSG_PASSWORD_FORM_LEAVE]: async (msg, sender) => {
    const p = parseHttpUrl(senderTabUrl(sender));
    if (!p || !sender.tab) throw new Error("bad password-form action");
    await leaveSite(sender.tab.id, registeredDomain(p.host));
    return true;
  },

  // 4.7.0 — ClickFix / ConsentFix: a content script BLOCKED the page scam itself; this opens the matching warning
  // (core/page-scam-guard.js — tab and page from the sender only, C28).
  // 5.1.3 (issue 3): the payment skimmer is also a tamper finding — recorded before the warning page replaces the page
  // (and after "Continue once", when the block stays but no warning opens). Other kinds have no tamper rule (no-op).
  [M.MSG_PAGE_SCAM_BLOCKED]: async (msg, sender) => {
    const state = await loadState();
    const kind = String(msg.kind || "");
    const key = PageScam.protectionForKind(kind);
    if (key) Tamper.recordOwnWarning(state, key, sender);
    return PageScam.onPageScamBlocked(state, kind, sender);
  },

  // ── Tamper Guard (5.1.0) — content scripts report; core/tamper-guard.js decides from the sender (C28) ──
  [M.MSG_TAMPER_HELLO]:   async (msg, sender) => Tamper.onHello(await loadState(), sender),
  [M.MSG_TAMPER_SIGNALS]: async (msg, sender) => Tamper.onSignals(await loadState(), msg, sender),
  [M.MSG_TAMPER_REPORT]:  async (msg, sender) => Tamper.onReport(await loadState(), msg, sender),

  [M.MSG_GET_TAMPER_WARNING]: async (msg, sender) => TamperWarnings.warningModel(tamperWarningId(sender)),

  [M.MSG_TAMPER_WARNING_ACTION]: async (msg, sender) => {
    const id = tamperWarningId(sender);
    const w = TamperWarnings.warningRecord(id);
    if (!w) throw new Error("this warning is no longer available");
    // 5.1.3: "Always ignore" puts the site on the allow list under Tamper (every tamper warning there is ignored).
    if (msg.action === M.TAMPER_WARNING_ACTION.ALWAYS_IGNORE) await mutate((s) => addToAllowList(s, ALLOW_CATEGORY.TAMPER, w.site));
    else if (msg.action !== M.TAMPER_WARNING_ACTION.IGNORE) throw new Error("unknown Tamper Guard action");
    await TamperWarnings.closeWarning(id);
    return true;
  },

  [M.MSG_GET_TAMPER_VIEW]: async () => Tamper.tamperView(),


  // 4.7.0 — Chrome out-of-date band (popup)
  [M.MSG_GET_BROWSER_UPDATE]: async () => BrowserUpdate.popupBand(),

  // ── Whitelist page (the only settings SSS has) ──
  [M.MSG_GET_WHITELIST]: async () => ({ sites: allowListSites(await loadState()) }),

  [M.MSG_ADD_TO_WHITELIST]: async (msg) => {
    const { state } = await mutate((s) => { addSiteToWhitelist(s, msg.host); });
    return { sites: allowListSites(state) };
  },

  [M.MSG_REMOVE_FROM_WHITELIST]: async (msg) => {
    const { state } = await mutate((s) => { removeSiteFromWhitelist(s, msg.host); });
    return { sites: allowListSites(state) };
  },

  [M.MSG_CLEAR_WHITELIST]: async () => {
    const { state } = await mutate((s) => { clearWhitelist(s); });
    return { sites: allowListSites(state) };
  },

  [M.MSG_EXPORT_WHITELIST]: async () => {
    const state = await loadState();
    return { file: exportWhitelistFile(state, chrome.runtime.getManifest().version) };
  },

  [M.MSG_IMPORT_WHITELIST]: async (msg) => {
    const hosts = parseWhitelistFile(msg.file);               // throws on an unreadable/foreign file
    const { state, result: kept } = await mutate((s) => importWhitelist(s, hosts));
    return { sites: allowListSites(state), kept };
  }
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Guard 1: only this extension (no externally_connectable — checked anyway, C28).
  if (!sender || sender.id !== chrome.runtime.id) { sendResponse({ ok: false, error: "foreign sender" }); return false; }
  const handler = msg && HANDLERS[msg.type];
  if (!handler) { sendResponse({ ok: false, error: "unknown message" }); return false; }
  // Guard 2 (5.0.6, C46): content scripts carry this extension's id too — each message type is allowed only for
  // its sender kind (an extension page, or a content script inside a web page; data/message-types.js).
  if (!isMessageAllowed(msg.type, senderKind(sender, EXTENSION_ORIGIN))) {
    console.warn(LOG_PREFIX, "refused", msg.type, "from", senderLabel(sender));   // origin only (C52)
    sendResponse({ ok: false, error: "not allowed for this sender" });
    return false;
  }
  handler(msg, sender)
    .then((data) => sendResponse({ ok: true, data }))
    .catch((e) => { console.warn(LOG_PREFIX, msg.type, e); sendResponse({ ok: false, error: String(e && e.message || e) }); });
  return true;                                              // async response
});
