// ── ui/whitelist.js — Safe Surfing Sentinel whitelist page controller ────────
// The only settings page SSS has. Holds no business logic: every change round-trips through
// the service worker (core/site-locks.js), which returns the fresh site list. All host text
// goes into the DOM via textContent (untrusted — these are domains the user typed or imported).
// ─────────────────────────────────────────────────────────────────────────────

import * as M from "../data/message-types.js";
import { WHITELIST_FILE_NAME } from "../data/constants.js";
import { showStatus, showError, releaseStatus } from "./status-line.js";

let sites = [];        // [{ site, sessionOnly }] — last list from the service worker
let filter = "";        // current search text (lower-cased)
let busy = false;       // guard: ignore actions while a request is in flight

function $(id) { return document.getElementById(id); }

function send(type, extra = {}) {
  return chrome.runtime.sendMessage({ type, ...extra })
    .then((res) => { if (!res || !res.ok) throw new Error(res && res.error || "no response"); return res.data; });
}

async function act(fn) {
  if (busy) return;
  busy = true;
  try { await fn(); }
  catch (e) { showError($("pageStatus"), e); }
  finally { busy = false; }
}

// ── Render ───────────────────────────────────────────────────────────────────
function render() {
  const shown = filter ? sites.filter((s) => s.site.includes(filter)) : sites;
  $("countText").textContent = sites.length ? `${sites.length} site${sites.length === 1 ? "" : "s"}` : "";
  $("emptyText").hidden = sites.length !== 0;
  $("siteList").hidden = sites.length === 0;

  $("siteList").replaceChildren(...shown.map((entry) => {
    const row = document.createElement("li");
    row.className = "site-row";
    const name = document.createElement("span");
    name.className = "site-name";
    name.textContent = entry.site;
    row.append(name);
    if (entry.sessionOnly) {
      const tag = document.createElement("span");
      tag.className = "session-tag";
      tag.textContent = "This session only";
      tag.title = "Already flagged as adult, an often-abused domain, or a risky TLD — whitelisting it lasts only until the browser next starts.";
      row.append(tag);
    }
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "remove-btn";
    remove.setAttribute("aria-label", `Remove ${entry.site}`);
    remove.textContent = "✕";
    remove.addEventListener("click", () => act(async () => {
      ({ sites } = await send(M.MSG_REMOVE_FROM_WHITELIST, { host: entry.site }));
      render();
      showStatus($("pageStatus"), `Removed ${entry.site}.`);
    }));
    row.append(remove);
    return row;
  }));
}

// ── Add / search ─────────────────────────────────────────────────────────────
function addHost() {
  const host = $("hostInput").value.trim();
  if (!host) return;
  act(async () => {
    ({ sites } = await send(M.MSG_ADD_TO_WHITELIST, { host }));
    $("hostInput").value = "";
    render();
    showStatus($("pageStatus"), `Added ${host}.`);
  });
}

// ── Export / import ──────────────────────────────────────────────────────────
function downloadFile(name, text) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  a.download = name;
  a.click();
  URL.revokeObjectURL(a.href);
}

function exportWhitelist() {
  act(async () => {
    const { file } = await send(M.MSG_EXPORT_WHITELIST);
    downloadFile(WHITELIST_FILE_NAME, file);
    showStatus($("pageStatus"), "Exported.");
  });
}

function importWhitelist(file) {
  act(async () => {
    const text = await file.text();
    const { sites: newSites, kept } = await send(M.MSG_IMPORT_WHITELIST, { file: text });
    sites = newSites;
    render();
    showStatus($("pageStatus"), `Imported ${kept} site${kept === 1 ? "" : "s"}.`);
  });
}

// ── "Delete all" confirmation ────────────────────────────────────────────────
function openConfirm() { $("confirmDialog").hidden = false; $("confirmOk").focus(); }
function closeConfirm() { $("confirmDialog").hidden = true; }

// ── Wiring ───────────────────────────────────────────────────────────────────
function wire() {
  $("addBtn").addEventListener("click", addHost);
  $("hostInput").addEventListener("keydown", (e) => { if (e.key === "Enter") addHost(); });

  $("searchInput").addEventListener("input", (e) => { filter = e.target.value.trim().toLowerCase(); render(); });

  $("exportBtn").addEventListener("click", exportWhitelist);
  $("importBtn").addEventListener("click", () => $("importFile").click());
  $("importFile").addEventListener("change", (e) => {
    const file = e.target.files[0];
    e.target.value = "";                                       // guard: same file re-selectable next time
    if (file) importWhitelist(file);
  });

  $("clearBtn").addEventListener("click", openConfirm);
  $("confirmCancel").addEventListener("click", closeConfirm);
  $("confirmDialog").addEventListener("click", (e) => { if (e.target === $("confirmDialog")) closeConfirm(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && !$("confirmDialog").hidden) closeConfirm(); });
  $("confirmOk").addEventListener("click", () => act(async () => {
    closeConfirm();
    ({ sites } = await send(M.MSG_CLEAR_WHITELIST));
    render();
    showStatus($("pageStatus"), "Whitelist cleared.");
  }));
  window.addEventListener("pagehide", releaseStatus);           // release status timers with the page (matches warning.js/tamper-warning.js/popup.js)
}

document.addEventListener("DOMContentLoaded", async () => {
  wire();
  try {
    ({ sites } = await send(M.MSG_GET_WHITELIST));
    render();
  } catch (e) {
    showError($("pageStatus"), e, "Could not load");
  }
});
