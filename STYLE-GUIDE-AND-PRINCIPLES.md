# Style guide & programming principles — mandatory for this extension

*These rules are mandatory for every change to Safe Surfing Sentinel, not
suggestions. They carry over the same standards already applied to
3P-Matrix-lite / uBlock-Stripped-Dynamic (see that project's own
programming-principles audit doc for the fuller history/rationale);
this file is SSS's own copy, kept current here so it travels with this
repo rather than living only in chat history.*

## 1. Visual / UI standards (mandatory)

- **Follow the browser's colour scheme.** Every themeable page uses
  `@media (prefers-color-scheme: light)` to override a light palette;
  nothing is hardcoded to "always dark." (`ui/common.css`)
- **`color-scheme` must be declared explicitly**, one value per branch
  (`dark` by default, `light` inside the media query). Without it,
  Chrome renders native form-control chrome (placeholders, focus
  rings, scrollbars) with light-mode assumptions regardless of the
  page's own CSS — this was a real bug found and fixed in 1.0.1.
- **WCAG AA minimum, with headroom, not a bare pass.** Every text/
  background colour pair must be checked: 4.5:1 for normal text, 3:1
  for large text (≥18px, or ≥14px bold) and UI components. A colour
  that clears AA by less than ~0.3 is treated as a defect, not a pass —
  "faint in practice" is a real failure mode even when the number
  technically clears the bar (see the `--dim` token's own comments in
  `ui/common.css` for two worked examples, one per theme).
- **Every themeable colour is a CSS custom property**, declared once in
  `ui/common.css`. No page-level CSS file may hardcode a hex colour
  that should vary by theme; if a new colour is needed, it becomes a
  new token in the single root block (and its light-mode override, if
  it needs one), with a comment explaining the contrast ratio if that
  ratio isn't obviously safe.
- **Placeholder text, focus rings, and other native-control styling**
  must be explicitly themed (not left to the browser's default), the
  same way `::placeholder` is handled here.

## 2. Structured / defensive programming (mandatory, carried over)

- **Single source of truth.** Variables, enums/switches, and magic
  numbers are declared in exactly one place, with a comment explaining
  what they control. A value repeated in two files is a bug waiting to
  happen, not a convenience.
- **No hardcoded values anywhere, tests included** — only named
  constants from that single declaration point.
- **End-to-end changes only.** A fix applied in one consumer of a
  shared fact/list/engine but not its siblings (e.g. a heuristics
  change made to the download check but not the site-visit check) is a
  bug, not a partial success. Before calling a change "done," state
  explicitly which other consumers of the same logic were checked.
- **Guards: initialise, clear, and release resources.** Anything that
  allocates memory, storage, listeners, or timers must have a
  corresponding teardown path. A listener added in one page's script
  without a matching removal (e.g. on `pagehide`/`unload`) is a defect.
- **Reuse, don't reinvent.** If a fact or list is already computed
  somewhere (e.g. host-risk scoring), a new feature that needs the same
  fact reuses that engine rather than building a second copy of it.
- **Always ask before zipping a new version, and always bump the
  version** (manifest included). Keep the version number in the zip's
  *filename* only — never wrap the zip's contents in a version-named
  top-level folder (see `/preferences.md` — this now applies to 3P
  Matrix's packaging too, not just SSS).
- **Don't assume — verify or ask.** A guess about the user's setup or
  about a bug's cause is stated as a guess, not as fact, until checked.
- **An unanswered question gets re-asked, not just flagged once.** When
  a report notes an open design decision or an inconsistency ("left as
  an open question", "flagging this for later") and the user's next
  message doesn't answer it, ask it again at the next natural point —
  don't let it quietly ride along across turns as a mention nobody
  resolved. Silence is never read as "resolved" or "fine as is." (Real
  incident 2026-11-26: the WASM-dubious-host hard block was flagged as
  an open question in both SSS and 3P Matrix; the user had to say "ask
  them again" before it got re-raised instead of staying parked in a
  report.) Shared with 3P Matrix's own principles doc.

## 2a. Chrome Web Store submission constraints (mandatory)

- **`manifest.json`'s `description` field must stay ≤ 132 characters** —
  CWS rejects the upload otherwise ("Er is een probleem opgetreden bij
  het uploaden van het bestand... Het veld description in het manifest
  is te lang"). Check the length whenever that field is edited; found
  at 179 chars in 1.0.0, fixed to 121 in the 1.0.1 batch.

## 3. How this file is used

- Read before any UI/CSS change, and before any change touching a
  shared engine/list/constant.
- Updated whenever a new standing rule is agreed (same way this file
  itself came out of the 1.0.1 dark-mode-readability fix) — not
  rewritten wholesale, just appended/amended in place.
- The upcoming programming-principles audit (versus the 3PM/uBD basis)
  checks the rest of the codebase against this file; findings get
  fixed under the 1.0.1 batch now being collected.
