// ── data/message-types.js ─────────────────────────────────────────────────────
// Named constants for every chrome.runtime message. A typo becomes a
// ReferenceError instead of a silently unhandled message.
// ─────────────────────────────────────────────────────────────────────────────

// popup → SW
// SSS 1.0.0: zero configuration. The only thing the user sets is the whitelist (MSG_TOGGLE_WHITELIST from the
// popup, MSG_*_WHITELIST from the whitelist page below) — 3P-Matrix-lite's level slider, per-site lock, per-
// protection tick, safer-regions editor and Show Matrix are all gone (core/auto-levels.js decides the rest).
export const MSG_GET_POPUP_STATE   = "GET_POPUP_STATE";    // { tabId } → view model for the popup
export const MSG_TOGGLE_WHITELIST  = "TOGGLE_WHITELIST";   // { tabId, url } — popup's on/off switch for this site
export const MSG_COUNT_FIREWALL_BLOCKS = "COUNT_FIREWALL_BLOCKS"; // { ruleIds[] } — 5.1.3: the popup's matched rules (getMatchedRules) → number of firewall blocks
export const MSG_SHOW_TAMPER_DETAILS = "SHOW_TAMPER_DETAILS";     // { tabId } — 5.1.3: the popup's "Details": open the page's tamper window again
export const MSG_RELOAD_TAB        = "RELOAD_TAB";         // { tabId }

// whitelist page → SW
export const MSG_GET_WHITELIST     = "GET_WHITELIST";      // {} → { sites: string[] }
export const MSG_ADD_TO_WHITELIST  = "ADD_TO_WHITELIST";   // { host }
export const MSG_REMOVE_FROM_WHITELIST = "REMOVE_FROM_WHITELIST"; // { host }
export const MSG_CLEAR_WHITELIST   = "CLEAR_WHITELIST";    // {} — "Delete all" (confirmed in the UI first)
export const MSG_EXPORT_WHITELIST  = "EXPORT_WHITELIST";   // {} → { file } — JSON text to save
export const MSG_IMPORT_WHITELIST  = "IMPORT_WHITELIST";   // { file } → { kept } — replaces the whole whitelist

// warning page → SW
export const MSG_EVALUATE_SITE     = "EVALUATE_SITE";      // { url } → full (stage 1 + 2) result
export const MSG_WARNING_ACTION    = "WARNING_ACTION";     // { action, url, tabId }

// password-form guard (ISOLATED content script) → SW (4.6.0, warnPasswordForms). These two string values are also
// declared in security/password-form-guard.js (content scripts cannot import); tools/check-shipped-terms.mjs keeps
// every MSG_* copy there equal to this file.
export const MSG_CHECK_PASSWORD_FORM  = "CHECK_PASSWORD_FORM";   // { actionUrl } → { warn, destHost } (page = sender, C28)
export const MSG_PASSWORD_FORM_LEAVE  = "PASSWORD_FORM_LEAVE";   // {} — "Go back": leave the sender's site (core/leave-site.js)
// 4.7.0 — same rules (copies in security/*.js kept equal by tools/check-shipped-terms.mjs):
export const MSG_CHECK_FAKE_WINDOW    = "CHECK_FAKE_WINDOW";     // { shownText } → { warned } — Browser-in-the-Browser; 5.0.6: the SW opens the warning page itself
export const MSG_PAGE_SCAM_BLOCKED    = "PAGE_SCAM_BLOCKED";     // { kind: PAGE_SCAM_KIND.* } — a page scam was blocked: open
                                                                 // the warning (page = sender tab, C28)

// 5.1.0 — Tamper Guard (copies in security/tamper-guard-bridge.js kept equal by tools/check-shipped-terms.mjs).
// Content script → SW (page and tab from the SENDER only, C28):
export const MSG_TAMPER_HELLO         = "TAMPER_HELLO";          // {} — top frame started → { arm } (core/tamper-guard.js)
export const MSG_TAMPER_SIGNALS       = "TAMPER_SIGNALS";        // { card, cardNumber, bank, hidden, frames[] } — banking/payment signals → { arm }
export const MSG_TAMPER_REPORT        = "TAMPER_REPORT";         // { rule, detail } — a finding (data/tamper-rules.js) → { arm }
// SW → content script (chrome.tabs.sendMessage, every frame of the tab): start the closer watching.
export const MSG_TAMPER_ARM           = "TAMPER_ARM";            // {}
// Tamper Guard warning window / Protections page → SW:
export const MSG_GET_TAMPER_WARNING   = "GET_TAMPER_WARNING";    // {} → warning model for the sender's ?w= (C28)
export const MSG_TAMPER_WARNING_CHANGED = "TAMPER_WARNING_CHANGED"; // { id } — service worker → warning window: fetch the model again (5.1.3)
export const MSG_TAMPER_WARNING_ACTION = "TAMPER_WARNING_ACTION"; // { action: TAMPER_WARNING_ACTION.* }
export const MSG_GET_TAMPER_VIEW      = "GET_TAMPER_VIEW";       // {} → { rules } — the signal list with points (5.1.3)

// popup → SW (4.7.0)
export const MSG_GET_BROWSER_UPDATE   = "GET_BROWSER_UPDATE";    // {} → band model or null (core/browser-update.js)

// Download/VirusTotal messages removed entirely (SSS 1.0.0, owner decision 2026-11-26: "remove download guard") —
// MSG_GET_DOWNLOAD_CHECK, MSG_DISMISS_DOWNLOAD, MSG_DOWNLOAD_ALWAYS_IGNORE, MSG_VT_KEY_PROMPT_DONE,
// MSG_DOWNLOAD_VT_UPDATE, MSG_GET_BLOCKED_DOWNLOAD, MSG_BLOCKED_DOWNLOAD_ACTION, MSG_SET_DOWNLOAD_SETTINGS,
// MSG_SET_VT_KEY are gone along with core/download-guard.js and the download UI pages.

// MSG_GET_OPTIONS / MSG_SET_DNS / MSG_SET_ALLOW_LIST / MSG_EXPORT_SETTINGS / MSG_IMPORT_SETTINGS /
// MSG_RESET_SETTINGS removed (SSS 1.0.0) — the level-slider/DNS/allow-list options page they belonged
// to (ui/protections.*) is gone; the whitelist page above is the only settings SSS has.

// Warning-dialog actions (MSG_WARNING_ACTION.action)
export const WARNING_ACTION = Object.freeze({
  GO_BACK:       "goBack",
  TRUST:         "trust",
  CONTINUE_ONCE: "continueOnce"
});

// Tamper Guard warning-window actions (MSG_TAMPER_WARNING_ACTION.action, 5.1.0)
export const TAMPER_WARNING_ACTION = Object.freeze({
  IGNORE:           "ignore",            // close this warning
  ALWAYS_IGNORE:    "alwaysIgnore"       // 5.1.3: add "Tamper: site" to the allow list (replaces never-warn site/anywhere)
});

// BLOCKED_DOWNLOAD_ACTION removed along with the download-blocked notice (SSS 1.0.0).

// ── Sender kinds (5.0.6, C46) ────────────────────────────────────────────────
// `sender.id === chrome.runtime.id` is also true for every content script this extension injects, so it does not
// tell an extension page from a content script running inside a web page. The router (background.js, via
// core/message-gate.js) refuses a message whose type is not listed for the sender's kind.
export const SENDER_KIND = Object.freeze({
  EXTENSION_PAGE: "extensionPage",   // popup, whitelist page, warning pages, notices (sender.url = this extension)
  CONTENT_SCRIPT: "contentScript"    // security/*.js running inside a web page (sender.tab set, sender.url = the page)
});

// The ONLY messages a content script may send — exactly the ones security/*.js sends (tools/test-message-gate.mjs
// checks both directions). Every other message type is extension-page only.
export const CONTENT_SCRIPT_MESSAGES = Object.freeze(new Set([
  MSG_CHECK_PASSWORD_FORM,   // security/password-form-guard.js
  MSG_PASSWORD_FORM_LEAVE,   // security/password-form-guard.js
  MSG_CHECK_FAKE_WINDOW,     // security/fake-window-guard.js
  MSG_PAGE_SCAM_BLOCKED,     // security/scam-guard-bridge.js (ClickFix, ConsentFix, shared codes), skimmer-bridge.js
  MSG_TAMPER_HELLO,          // security/tamper-guard-bridge.js (5.1.0)
  MSG_TAMPER_SIGNALS,        // security/tamper-guard-bridge.js
  MSG_TAMPER_REPORT          // security/tamper-guard-bridge.js
]));
