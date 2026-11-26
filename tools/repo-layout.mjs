// ── tools/repo-layout.mjs ─────────────────────────────────────────────────────
// Ported from 3P Matrix 5.1.10's tools/repo-layout.mjs (owner decision 2026-11-26): THE declaration of
// where the extension, the docs and the tools are, for both layouts this package runs in (one
// declaration; every default folder and every walker of the extension tree takes it from here):
//
//   repo layout     (GitHub): <repo>/ is the extension AND holds the project documents at its top level
//                   (plus store/, flattened one level into the docs zip); this package is <repo>/tools/.
//   release layout  (the three zips unpacked side by side): Safe-Surfing-Sentinel/ ·
//                   Safe-Surfing-Sentinel-docs/ · Safe-Surfing-Sentinel-tools/ (this).
//
// In the repo layout a top-level file belongs to the extension only when it is in EXTENSION_ROOT_FILES;
// every other top-level file, plus everything inside store/, is a document (docs zip) unless it is in
// REPO_ONLY_FILES. Folders in NON_EXTENSION_DIR_NAMES are never extension code in either layout.
//
// Difference from 3P Matrix's own repo-layout.mjs: SSS has a store/ folder (CWS listing + permissions
// text for the Chrome Web Store submission) that 3P Matrix has no equivalent of. It is docs material,
// not runtime — kept out of the extension zip and carried into the docs zip (as its own store/ subfolder,
// not flattened — see listDocsFiles). SSS also has no ARCHITECTURE.md ↔ README.md rename like 3P Matrix's
// (no file needs renaming between the repo and the docs zip), so DOCS_ZIP_NAMES stays empty.
//
// Public interface (same shape as 3P Matrix's repo-layout.mjs):
//   defaultRoots(toolsDir)              → { layout, extension, docs } — used when --extension / --docs are not given
//   isSameRoot(a, b)                    → true when extension and docs are the same folder (repo layout)
//   listExtensionFiles(ext, opts)       → absolute paths of the extension's files
//                                         opts: { skipDirs: [names], exts: [".js", …] } (both optional)
//   listDocsFiles(docs, ext)            → absolute paths of the docs' files (repo layout: top-level documents + store/)
//   docsZipName(name)                   → the name a repo-layout document has in the docs zip (DOCS_ZIP_NAMES)
// Dependencies: none (node:fs, node:path). State owned: none.
// ─────────────────────────────────────────────────────────────────────────────

import { existsSync, readdirSync, statSync } from "node:fs";
import { join, resolve, relative, sep } from "node:path";

// ── Settings (one place) ─────────────────────────────────────────────────────
export const LAYOUT = Object.freeze({ REPO: "repo", RELEASE: "release" });
export const RELEASE_EXTENSION_FOLDER = "Safe-Surfing-Sentinel";
export const RELEASE_DOCS_FOLDER = "Safe-Surfing-Sentinel-docs";
export const TOOLS_DIR_NAME = "tools";
export const STORE_DIR_NAME = "store";   // SSS-only: CWS listing/permissions text, carried into the docs zip
const MANIFEST_FILE = "manifest.json";
// Folders that are never extension code (this package inside the repo, the store-listing text,
// dependencies, version control).
export const NON_EXTENSION_DIR_NAMES = Object.freeze(new Set([TOOLS_DIR_NAME, STORE_DIR_NAME, "node_modules", ".git"]));
// The only top-level files the extension ships (runtime entry point + the licence texts a user needs).
export const EXTENSION_TEXT_FILES = Object.freeze(["LICENSE.txt", "THIRD_PARTY_LICENSES.md"]);
export const EXTENSION_ROOT_FILES = Object.freeze([MANIFEST_FILE, "background.js", ...EXTENSION_TEXT_FILES]);
// Top-level files of the repo that belong to no release zip: housekeeping, the GitHub license-detection
// file (bare "LICENSE", separate from the "LICENSE.txt" copy shipped inside the extension), the
// GitHub/Web Store front page, and the privacy policy.
// builtin-whitelist.json (found during this port): carries extension:"Safe Surfing Sentinel" but
// version:"4.6.0" — a 3P Matrix version number, not one of SSS's own (1.0.x) — generated 2026-11-06, and
// nothing in core/, data/ or manifest.json references it (the real built-in-whitelist mechanism is the
// data/builtin-domains.js module). Looks like a stray debug/state-export snapshot, not source data either
// zip needs. Kept out of both pending the owner's call on whether to delete it from the repo outright.
export const REPO_ONLY_FILES = Object.freeze([".gitignore", ".gitattributes", "README.md", "PRIVACY.md", "LICENSE", "builtin-whitelist.json"]);
const REPO_ONLY_RE = /\.pdf$/i;
// SSS has no renamed docs (no ARCHITECTURE.md ↔ README.md split like 3P Matrix's) — empty on purpose.
export const DOCS_ZIP_NAMES = Object.freeze({});
const OS_LITTER = Object.freeze(new Set([".DS_Store", "Thumbs.db"]));

export function defaultRoots(toolsDir) {
  const up = resolve(toolsDir, "..");
  if (existsSync(join(up, MANIFEST_FILE))) return { layout: LAYOUT.REPO, extension: up, docs: up };
  return { layout: LAYOUT.RELEASE, extension: join(up, RELEASE_EXTENSION_FOLDER), docs: join(up, RELEASE_DOCS_FOLDER) };
}

export function isSameRoot(a, b) { return !!a && !!b && resolve(a) === resolve(b); }

function walk(dir, skip, out) {
  for (const name of readdirSync(dir)) {
    if (OS_LITTER.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) { if (!skip.has(name)) walk(p, skip, out); }
    else out.push(p);
  }
  return out;
}

export function listExtensionFiles(ext, { skipDirs = [], exts = null } = {}) {
  const root = resolve(ext);
  const skip = new Set([...NON_EXTENSION_DIR_NAMES, ...skipDirs]);
  return walk(root, skip, [])
    .filter((p) => relative(root, p).includes(sep) || EXTENSION_ROOT_FILES.includes(relative(root, p)))
    .filter((p) => !exts || exts.some((e) => p.endsWith(e)))
    .sort();
}

// Repo layout: top-level documents (as 3P Matrix) PLUS everything under store/, carried in as its own
// store/ subfolder inside the docs zip (SSS-only difference — see header).
export function listDocsFiles(docs, ext) {
  const root = resolve(docs);
  if (!isSameRoot(docs, ext)) return walk(root, new Set([TOOLS_DIR_NAME, "node_modules", ".git"]), []).sort();
  const topLevel = readdirSync(root)
    .filter((n) => !OS_LITTER.has(n) && !EXTENSION_ROOT_FILES.includes(n) && !REPO_ONLY_FILES.includes(n) && !REPO_ONLY_RE.test(n) && n !== STORE_DIR_NAME)
    .map((n) => join(root, n))
    .filter((p) => statSync(p).isFile());
  const storeDir = join(root, STORE_DIR_NAME);
  const storeFiles = existsSync(storeDir) ? walk(storeDir, new Set(), []) : [];
  return [...topLevel, ...storeFiles].sort();
}

export function docsZipName(name) { return DOCS_ZIP_NAMES[name] || name; }
