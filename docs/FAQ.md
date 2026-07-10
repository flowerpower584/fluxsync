# FAQ

## Why is there no iOS app?

Background clipboard capture — the core thing FluxSync does — isn't possible on iOS. Apple doesn't give third-party apps a way to observe clipboard changes while running in the background; an app can only read the clipboard while it's in the foreground, and even then iOS shows the user a notification/prompt on most reads. That's a deliberate iOS privacy boundary, not a gap FluxSync can code around.

A share-sheet-based "companion" app — where you explicitly share text/links into FluxSync instead of it capturing copies automatically — is a plausible post-1.1 addition, since that only needs foreground, user-initiated access. It would be a fundamentally different interaction model from the automatic sync FluxSync does on its other platforms, not a drop-in port.

## Why LAN-only? Why not a cloud/relay option?

Because the trust model is the product. FluxSync's entire pitch is "your clipboard — which regularly contains passwords, OTP codes, private links, addresses — never leaves your local network and never touches a server anyone operates." The moment there's a relay in the loop, that promise weakens to "a server we run doesn't currently log your traffic," which is a much weaker (and much less verifiable) claim.

There's no cloud relay today, by design. See [`SECURITY.md`](./SECURITY.md) §2.5 for what a future opt-in relay's threat model would look like if one is ever added — it's designed to preserve end-to-end encryption even then (the relay would only ever see ciphertext and peer-id hashes, never hold a key), but nothing ships today.

If you need clipboard sync across two networks (home ↔ office, laptop ↔ phone on cellular), FluxSync works over a self-hosted overlay network like Tailscale — see the README's Quickstart. That's you extending your own "LAN" with a tool you already trust, not FluxSync adding a relay of its own.

## Why does FluxSync ask for Accessibility permission on Android?

See [`WHY-ACCESSIBILITY.md`](./WHY-ACCESSIBILITY.md) for the full explanation — short version: Android blocks background clipboard reads since Android 10, Accessibility is the only supported way around that for a background sync app, and FluxSync uses it only to catch copy-shaped events (selection change, long-click, click-on-a-copy-labeled-control), never for input injection or general screen reading. It's optional and revocable at any time in Settings → Accessibility.

## What if Android ships a universal clipboard feature (e.g. cross-device clipboard with a PC)?

Google and OEMs have shipped versions of this, and it's likely to keep improving — but every implementation so far is scoped to a single vendor's ecosystem: Android ↔ Windows via a specific OEM's companion app, or Android ↔ ChromeOS via a Google account. None of them sync Android ↔ macOS or Android ↔ Linux, and none of them work across different phone brands without that vendor's own app.

FluxSync exists for the mixed household/desk: an Android phone next to a Mac, a Linux box, and a Windows machine from three different vendors, all needing one clipboard, with no vendor account tying them together. That gap doesn't close until someone ships a cross-vendor, cross-OS standard — which isn't on the table today.

## Why sideload instead of the Play Store? Is F-Droid coming?

The Accessibility Service use described above — a background service used for clipboard capture — runs against Google Play's Accessibility API policy, which restricts Accessibility usage to apps whose primary function requires it in ways Play's review process interprets narrowly. Rather than compromise the feature to fit that review, FluxSync ships as a direct APK download (sideload) from GitHub Releases.

F-Droid is planned as an additional distribution channel (F-Droid's review model is source-based and doesn't carry the same Play-specific Accessibility restriction), but it isn't live yet — check the README for current status.
