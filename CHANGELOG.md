# Safe Surfing Sentinel — changelog

(Started with 1.0.0. SSS is a zero-configuration offshoot of 3P Matrix — content firewall; shared
protection logic carries its own history in that project's own CHANGELOG.md / CHANGELOG_HISTORY.md.)

## 1.0.2
- **Two domain-list hard blocks are now risk-score signals only, not outright blocks** — same redesign as
  3P Matrix 5.1.10: a domain being on a reputation list says something about a shared platform, not about
  this specific request, so it no longer blocks outright; it still feeds the site-visit risk score.
- **Fixed: an unusual-port block also caught :80 and :8080**, which are common and no longer meant to be
  flagged (:443 and :8443 are the two "usual" explicit ports).
- **Protection wording updated to match** the above.
- **Store listing updated** with a dedicated skimming/tamper-protection description (fake payment overlays
  and hijacked password fields on banking and payment pages).

## 1.0.1
- **Dark mode fixed:** the UI now follows the browser/OS colour scheme (`prefers-color-scheme`) instead of
  assuming light mode; native form controls were rendering with light-mode assumptions because
  `color-scheme` wasn't declared. Every themed colour token re-checked against WCAG AA contrast.
- **Programming-principles audit** run against the shared 3P-Matrix-lite / uBlock-Stripped-Dynamic basis;
  issues found were batched into this release rather than shipped piecemeal.

## 1.0.0
- **First release.** A zero-configuration offshoot of 3P Matrix — content firewall: firewall, download
  protection, scam guard and tamper guard all run with no settings to get wrong; the only thing exposed in
  the options page is a single whitelist.
- Toolbar icon alone shows status (mint = protected, orange = something found, grey = off/whitelisted) — no
  badge text or blocked-count number.
- Default safer-regions TLD whitelist derived from the browser's own languages.
