// ── data/whitelist-io.js ───────────────────────────────────────────────────────
// Whitelist page "Export"/"Import" — the ONE settings file SSS has (there is no level, no protection
// ticks, no DNS, no download settings left to export: core/site-locks.js, data/message-types.js).
// Pure functions: no Chrome API calls, no state mutation (core/site-locks.js's importWhitelist does
// the actual replace-and-validate, under the usual mutate()/withStateLock() guard in background.js).
//
// Public interface:
//   exportWhitelistFile(state, extensionVersion) — the whitelist as a pretty-printed JSON string
//   parseWhitelistFile(fileText)                 — JSON string → string[] of hosts (throws on a
//                                                  file that isn't a whitelist export of ANY version
//                                                  we still read; core/site-locks.js validates each host)
// ─────────────────────────────────────────────────────────────────────────────

import { WHITELIST_FILE_FORMAT, WHITELIST_FILE_VERSION } from "./constants.js";
import { allowListSites } from "../core/site-locks.js";

export function exportWhitelistFile(state, extensionVersion) {
  const payload = {
    format: WHITELIST_FILE_FORMAT,
    version: WHITELIST_FILE_VERSION,
    exportedAt: new Date().toISOString(),
    extensionVersion: extensionVersion || null,
    sites: allowListSites(state)
  };
  return JSON.stringify(payload, null, 2);
}

// `sites` entries are { site, sessionOnly } (our own export, core/site-locks.js allowListSites) or, as a
// convenience, bare host strings (hand-written, or exported by another tool) — either way this returns a
// flat string[] of hosts. core/site-locks.js's importWhitelist() re-decides session-only itself (whether a
// host is on the abused list today, not whatever this file happened to say) — that flag is never read back.
function hostOf(entry) { return typeof entry === "string" ? entry : (entry && entry.site) || ""; }

// Accepts our own export (format+version+sites) and, as a convenience, a bare JSON array of hosts
// (e.g. hand-written or exported by another tool) — anything else throws so the UI can say why.
export function parseWhitelistFile(fileText) {
  let data;
  try { data = JSON.parse(String(fileText ?? "")); }
  catch { throw new Error("not a valid whitelist file (bad JSON)"); }

  if (Array.isArray(data)) return data.map(hostOf);
  if (data && typeof data === "object" && Array.isArray(data.sites)) {
    if (data.format && data.format !== WHITELIST_FILE_FORMAT) throw new Error("not a Safe Surfing Sentinel whitelist file");
    return data.sites.map(hostOf);
  }
  throw new Error("not a valid whitelist file");
}
