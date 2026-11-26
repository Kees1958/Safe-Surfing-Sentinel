# Safe Surfing Sentinel — technical history

The detailed record: what changed, **why** it was done that way, how, known limitations, the source
version worked from, and which of the three zips changed. Written for big changes only (a new feature, a
bug-class fix, a refactor, a batch of principle fixes); every tools version gets at least a
`**tools x.y.z:**` line. The short user-facing summary is `CHANGELOG.md`. Both files live in the docs zip
only — never in the extension zip. Same two-tier convention as 3P Matrix — content firewall's own
CHANGELOG_HISTORY.md, since SSS was forked from that project's runtime.

---

## 1.0.2
Compare at 1.0.1. Changed zips: extension, tools, docs.

- **Owner decision 2026-11-26: domain-reputation lists no longer drive hard blocks, only risk scores.**
  A domain-list hit names a shared platform, not something about the specific request being made — so it
  now only feeds `core/site-scorer.js`'s risk score, never an outright DNR block. Removed
  `ID.WASM_DUBIOUS_HOST` (the WebAssembly-only hard block keyed on `data/scam-host-list.js`'s domain list)
  from `core/rule-builder.js`. `WASM_DUBIOUS_TLD` (abused-TLD, not list-driven) and `WASM_OUTSIDE_SAFER`
  (safer-region check) are structural signals and unaffected. (An earlier redesign pass, carried over from
  3P Matrix, had already removed the equivalent general-traffic hard block, `ID.SUSP_HOSTING`.)
- **`data/constants.js`: `NON_STANDARD_PORT_REGEX` fixed.** Its hand-built RE2 digit-exclusion trie was
  still excluding `:80`/`:8080` as "usual" after `USUAL_PORTS` had already become `[443, 8443]` — stale
  relative to that rename. Rewritten to exclude only 443/8443; verified against all five port-length cases
  by direct regex test.
- **`data/protections.js`: `BLOCK_SUSPICIOUS_3P` and `BLOCK_WASM_DUBIOUS` labels/descriptions updated** to
  drop "DDNS hosts" / "dubious host" wording now that those hard blocks are gone (`BLOCK_WASM_DUBIOUS` now
  says "abused TLDs" instead, matching what it actually still blocks).
- **`core/policy.js`:** stale doc comment fixed — `effectiveLevel(state, host)` renamed in signature to
  `effectiveLevel(state, p)` years ago but the comment still said `host`; `p` is the `parseHttpUrl()`-shaped
  object actually passed in.
- **`store/CWS-LISTING.md`:** full description rewrite (owner-provided text) plus a new bullet describing
  skimming/tamper protection — fake tracking-pixel payment overlays and password fields rigged to submit
  elsewhere, watched closely on banking/payment pages.
- **Ported into SSS this release: 3P Matrix's three-artifact release tooling** (`tools/repo-layout.mjs`,
  `tools/package-release.mjs`) — adapted copies, not a shared codebase (SSS and 3P Matrix are separate
  repos with independent release cadences; see each file's own header for the SSS-specific differences:
  `store/` is carried into the docs zip, there's no `README.md` doc requirement, no `package-lock.json`
  requirement yet). `tools/package.json` itself was a stale, uncorrected copy of 3P Matrix's own (wrong
  name, wrong description, scripts pointing at files that don't exist in this repo) — fixed as part of
  this port, not left to drift further.

**tools 1.0.2:** `tools/repo-layout.mjs`, `tools/package-release.mjs` added (ported from 3P Matrix 5.1.10);
`tools/package.json` corrected (name, description, scripts, devDependencies — see above).

## 1.0.1
Compare at 1.0.0. Changed zips: extension, docs.

- **Dark mode fixed (owner report):** the UI assumed light mode — native form controls rendered with
  light-mode assumptions because `color-scheme` wasn't declared on themed pages. Every page now declares
  `color-scheme` explicitly per `prefers-color-scheme` branch (`ui/common.css`); every themed colour token
  re-checked against WCAG AA contrast in both branches.
- **Programming-principles audit** run against the shared 3P-Matrix-lite / uBlock-Stripped-Dynamic basis
  this extension was forked from; found issues batched into this release at the owner's request rather
  than shipped piecemeal.

## 1.0.0
First release. Forked from 3P Matrix — content firewall 5.1.9's runtime (single baseline commit:
"Baseline: 3P Matrix 5.1.9 runtime") and redesigned as a zero-configuration offshoot:

- Firewall, download protection, scam guard and tamper guard all run with no settings to get wrong; the
  only thing exposed in the options page (`ui/whitelist.*`) is a single whitelist.
- Toolbar icon alone shows status (mint = protected, orange = something found, grey = off/whitelisted) — no
  badge text, no blocked-count number (unlike 3P Matrix's own badge).
- Default safer-regions TLD whitelist derived from the browser's own `navigator.languages`, not a manual
  region picker.
- Whitelisting a domain already on the combined Kees1958/HaGeZi abused-TLD or risky-domain lists is
  session-only (purged at next browser start), never permanent — adult sites are exempt from this
  session-only restriction.
- New icon set (`icons/sss_*.png`), replacing 3P Matrix's own.

**tools 1.0.0:** `tools/build-icons.mjs` (renders the toolbar icon for every state × size).
