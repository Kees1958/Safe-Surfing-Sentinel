# Chrome Web Store — permission justifications

*For the "Permission justification" fields in the CWS developer dashboard
submission form. One paragraph per manifest permission, written for a
human reviewer — plain, specific, honest about what each one is used
for and what it is never used for.*

## declarativeNetRequest

Safe Surfing Sentinel is a third-party-tracker and script firewall. It
uses `declarativeNetRequest` to block known-abusive third-party trackers,
scripts, and frames, entirely inside Chrome's own rule engine, with no
network inspection or rule evaluation happening outside the browser.
This is the core blocking mechanism the extension exists to provide.

## storage

Used to save the user's own whitelist (sites they've chosen to exempt)
and a small amount of local housekeeping state, such as which sites were
auto-exempted only for the current browser session. All of this is
stored locally with `storage.local` and is never transmitted anywhere.

## webNavigation

Used to detect when a tab navigates to a new page, so the extension can
evaluate the destination (is it on an abused TLD, a known-risky host, or
otherwise flagged) before or as the page loads, and show a warning page
when appropriate. No browsing history is retained; each navigation is
evaluated and then discarded.

## webRequest

Used in **observe-only** mode (the extension does not request
`webRequestBlocking` and performs no blocking through this API —
blocking is done entirely through `declarativeNetRequest`). It is used
to detect when a declarativeNetRequest rule blocked a request on the
current page, so the popup can tell the user something was blocked
there.

## tabs

Used to read the URL/host of the active tab so the popup can show the
site's protection status, and to reload the current tab after the user
changes its whitelist status so the new rules take effect immediately.
No tab content or browsing history is read or stored beyond this.

## scripting

Used to inject the extension's own protective content scripts — for
example, scripts that detect common scam-page patterns (fake "your
account is locked" overlays, keyboard-lock tricks) and signs of
in-page tampering. These scripts run locally in the page and report
findings back to the extension; they do not transmit page content
anywhere.

## alarms

Used to schedule small periodic housekeeping tasks inside the
extension's own service worker — for example, clearing out
session-only whitelist exemptions at the next browser start. Not used
for any tracking or reporting purpose.

## activeTab

Used alongside `tabs` so the extension can act on the tab the user is
currently looking at when they interact with the popup, without needing
broader standing access beyond what `host_permissions` already grants
for the firewall itself.

## host_permissions: `<all_urls>`

Safe Surfing Sentinel's entire purpose is to protect the user no matter
which site they visit next — it cannot work from a fixed list of sites,
because the threats it blocks (malicious third-party trackers, scam
pages, abused TLDs) can appear on any site. `<all_urls>` is what lets
the `declarativeNetRequest` rules and navigation checks apply
everywhere, the same way a firewall or antivirus needs to see all
traffic to do its job. No data from these pages is collected, stored,
or transmitted outside the user's own device — see `PRIVACY.md`.
