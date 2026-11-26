# Privacy Policy — Safe Surfing Sentinel

*Plain-language policy. Last updated: 2026-11-26 (version 1.0.0).*

## The short version

Safe Surfing Sentinel (SSS) does not collect, store, transmit, or sell any
of your data, anywhere, ever. Everything it does happens locally, inside
your own browser, on your own device. There is no company server behind
this extension receiving anything from it.

## What SSS looks at, and where that information goes

To decide whether a site or a download is safe, SSS looks at things like:

- the web address (URL/host) of the page you're on or about to visit,
- the third-party domains a page tries to load scripts or trackers from,
- signals on the page that look like tampering, scams, or phishing.

All of that checking happens **on your device**, against lists bundled
inside the extension itself (see `THIRD_PARTY_LICENSES.md` for where
those lists come from). None of it is sent anywhere — not to us, not to
any third party, not for "analytics," not for anything.

## What SSS stores, and where

The only thing SSS saves is your own whitelist (the sites you've chosen
to exempt) and a small amount of housekeeping state (such as "this site
was auto-elevated this session"). This is stored using Chrome's own
`storage.local`, which lives only on your device and is never
transmitted anywhere by SSS. You can see, edit, export, or delete it at
any time from the whitelist page, and removing the extension removes it.

## What SSS does **not** do

- It does not keep a history of the sites you visit. By design, nothing
  about your browsing is logged or retained beyond the current check —
  see the "no history" rule in the extension's own source comments.
- It does not use analytics, telemetry, crash reporting, or any
  background "phone home" of any kind.
- It does not share, sell, or disclose data to anyone, because it does
  not collect any to begin with.
- It does not require you to create an account, sign in, or provide any
  personal information.

## Why SSS needs the browser permissions it asks for

See `store/CWS-PERMISSIONS.md` in this repository for a plain-language,
permission-by-permission explanation of what each one is used for and
why. None of them are used to collect or transmit personal data.

## Changes to this policy

If this policy changes, the updated version will be published at this
same location in the GitHub repository, with the date above updated.

## Contact

Questions about this policy can be raised as a GitHub issue on this
repository.
