// ── ui/popup.js — Safe Surfing Sentinel toolbar popup controller ─────────────
// Zero configuration (SSS 1.0.0): the only thing this popup lets the user change is the
// whitelist switch for the site in the active tab. Everything else — the icon, the status
// title/detail, the "This page" box, the firewall count — is a status report built from the
// service worker's view model (core/view-models.js popupModel). Holds no business logic:
// every change round-trips through the service worker, which returns the fresh view model.
// All text goes into the DOM via textContent (host names and reasons are untrusted).
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { ICON_DIR, ICON_UI_SIZE, SITE_STATUS, SITE_STATUS_TEXT, SITE_STATUS_OFF_SESSION_DETAIL,
         ICON_STATE, SEVERITY, TAMPER_RATING, POPUP_MATCHED_RULES_MAX } from "../data/constants.js";
import { showError, releaseStatus } from "./status-line.js";

// ── Popup-only presentation constants (every switch/magic number here, once) ─
const RISK_TEXT = Object.freeze({ [SEVERITY.SUSPECT]: "Suspicious site", [SEVERITY.PHISHING]: "Dangerous site" });
const RISK_CLASS = Object.freeze({ [SEVERITY.SUSPECT]: "suspect", [SEVERITY.PHISHING]: "danger" });
const LIST_JOIN = ", ";
const BLOCK_COUNT_UNKNOWN = "";    // the count could not be asked (no activeTab grant, quota): nothing shown
function tamperCountText(t) { return `${t.ratingLabel} tamper ${t.findings === 1 ? "sign" : "signs"}: ${t.findings}`; }

// ── Popup state (guarded: initialised empty, replaced wholesale per response) ─
let tab = null;       // { id, url } of the active tab
let model = null;     // last view model from the service worker
let busy = false;     // guard: ignore actions while a request is in flight

function $(id) { return document.getElementById(id); }

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, tabId: tab && tab.id, url: tab && tab.url, ...extra })
    .then((res) => { if (!res || !res.ok) throw new Error(res && res.error || "no response"); return res.data; });
}

async function act(type, extra, { reloadTab = false } = {}) {
  if (busy) return;
  busy = true;
  try {
    model = await send(type, extra);
    render();
    if (reloadTab && tab && model.scorable) chrome.tabs.reload(tab.id).catch(() => { /* tab closed meanwhile */ });
  } catch (e) {
    showError($("popupStatus"), e);
  } finally {
    busy = false;                                              // release on every path
  }
}

// The status text for a site: whitelisted (session-only detail when it applies), automatic, or "not a site".
function statusTextFor(m) {
  if (!m.scorable) return SITE_STATUS_TEXT[SITE_STATUS.NOT_A_SITE];
  const text = SITE_STATUS_TEXT[m.status.status] || SITE_STATUS_TEXT[SITE_STATUS.STANDARD];
  if (m.status.status === SITE_STATUS.OFF && m.status.sessionOnly) {
    return { title: text.title, detail: SITE_STATUS_OFF_SESSION_DETAIL };
  }
  return text;
}

// The toolbar-icon state this site's status maps to — mirrors core/badge.js iconStateOf() so the popup's
// own icon always agrees with the one Chrome is showing in the toolbar.
function iconStateFor(m) {
  if (!m.scorable || m.status.status === SITE_STATUS.OFF) return ICON_STATE.OFF;
  const page = m.page;
  if ((page.risk && page.risk.severity !== SEVERITY.NONE) || page.tamper) return ICON_STATE.FOUND;
  return ICON_STATE.ON;
}

// ── Render ───────────────────────────────────────────────────────────────────
function render() {
  const m = model;
  if (!m) return;

  $("statusIcon").src = `../${ICON_DIR}/${iconStateFor(m)}_${ICON_UI_SIZE}.png`;
  $("siteHost").textContent = m.host || "—";

  const text = statusTextFor(m);
  $("statusTitle").textContent = text.title;
  $("statusDetail").textContent = text.detail;

  const toggle = $("whitelistToggle");
  toggle.checked = m.whitelisted;
  toggle.disabled = !m.scorable;

  renderPageBox(m.page);
  $("tamperDetailsBtn").hidden = !(m.page && m.page.tamper);
}

// 5.1.3 — "This page": each line only when it has something to say; the box hidden when none has.
function renderPageBox(page) {
  const risk = page && page.risk;
  const tamper = page && page.tamper;
  const continued = !!(page && page.continued);
  $("pageRisk").hidden = !risk;
  if (risk) {
    $("pageRisk").className = `page-line ${RISK_CLASS[risk.severity] || ""}`.trim();
    $("pageRiskText").textContent = RISK_TEXT[risk.severity] || "";
    $("pageRiskWhy").textContent = risk.reasons.join(LIST_JOIN);
  }
  $("pageTamper").hidden = !tamper;
  if (tamper) {
    $("pageTamper").className = `page-line page-line-row ${tamper.rating >= TAMPER_RATING.HIGH ? "danger" : "suspect"}`;
    $("pageTamperText").textContent = tamperCountText(tamper);
    $("pageTamperWorst").textContent = tamper.topLabel;
    $("pageTamperWorst").title = tamper.topLabel;
  }
  $("pageContinued").hidden = !continued;
  $("pageBox").hidden = !risk && !tamper && !continued;
}

// 5.1.3 — the firewall count, asked when the popup opens: the rules Chrome says matched in this tab (opening the
// popup grants activeTab for it), counted by the service worker (block rules only). No background counting at all.
async function renderBlockCount() {
  let text = BLOCK_COUNT_UNKNOWN;
  try {
    if (tab && model && model.scorable) {
      const info = await chrome.declarativeNetRequest.getMatchedRules({ tabId: tab.id });
      const ruleIds = (info && info.rulesMatchedInfo || []).slice(0, POPUP_MATCHED_RULES_MAX).map((x) => x.rule.ruleId);
      const n = await send(M.MSG_COUNT_FIREWALL_BLOCKS, { ruleIds });
      text = n === 0 ? "Firewall blocked nothing on this page" : `Firewall blocked ${n} ${n === 1 ? "request" : "requests"} on this page`;
    }
  } catch { /* not granted (the popup opened another way) or over Chrome's quota: no count shown */ }
  $("blockedText").textContent = text;
}

// ── Wiring ───────────────────────────────────────────────────────────────────
function wire() {
  $("whitelistToggle").addEventListener("change", () => act(M.MSG_TOGGLE_WHITELIST, {}, { reloadTab: true }));
  $("tamperDetailsBtn").addEventListener("click", async () => {
    try { await send(M.MSG_SHOW_TAMPER_DETAILS); window.close(); }
    catch (e) { showError($("popupStatus"), e, "Tamper details"); }
  });
  $("whitelistBtn").addEventListener("click", () => chrome.runtime.openOptionsPage());
  window.addEventListener("pagehide", releaseStatus);           // release status timers with the page (matches warning.js/tamper-warning.js)
}

document.addEventListener("DOMContentLoaded", async () => {
  wire();
  try {
    const [t] = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = t ? { id: t.id, url: t.url || "" } : null;
    model = await send(M.MSG_GET_POPUP_STATE);
    render();
    renderBlockCount();                                         // 5.1.3: after the first render, never in its way
  } catch (e) {
    showError($("popupStatus"), e, "Could not load");
  }
});
