# Why FluxSync asks for Accessibility permission on Android

Short version: it's the only supported way for a background clipboard-sync app to reliably catch a copy on modern Android, it's used for exactly that, and you can turn it off at any time without uninstalling the app.

## The Android problem this solves

Since Android 10, apps running in the background cannot read the system clipboard at all — this is a deliberate OS privacy restriction, not a FluxSync limitation. A normal `ClipboardManager` listener only fires reliably while your app is in the foreground. FluxSync's entire purpose is syncing clipboard content *between devices without you having to switch to it first*, so a foreground-only listener would defeat the app.

The Accessibility API is the one Android capability that can observe UI events (including copy actions) while running as a background service. It was not designed for clipboard sync — apps use it for this because Android currently offers no purpose-built "background clipboard access" permission. This is a known, widely-discussed trade-off in the Android developer community, not something specific to FluxSync.

## What FluxSync actually does with it

FluxSync's Accessibility Service (`FluxsyncAccessibilityService.kt`, in `apps/android`) is a **fallback**, not the primary path. The primary clipboard capture is a normal `ClipboardManager.OnPrimaryClipChangedListener`, which works whenever the app process is alive. The Accessibility Service only exists to catch the cases where a copy never reaches that listener — for example, some in-app "share" or "copy link" actions in third-party apps that don't always trigger the standard system clipboard broadcast.

The service is configured to listen for exactly three UI event types:

- **Text selection changed** — records the text the user just selected.
- **Long click on a view** — records the label/description of the long-clicked control (a fallback for links, buttons, and images that use a long-press-to-copy pattern).
- **Click on a view** — checked only to see whether the clicked control's label or description contains a word like "copy"/"copier"; if so, the previously captured selection/long-click text is treated as a completed copy.

For each of these events, FluxSync reads the text of **the single UI node tied to that event** — never a full-screen dump. There is no code path that walks the rest of the visible view tree, and no scheduled or periodic screen scan.

## What FluxSync never does

- **No keylogging.** The service does not listen for key events or IME input; it only reacts to selection/click/long-click events.
- **No general screen-content collection.** It reads the label or text of the specific node involved in a copy-shaped event, nothing else on screen.
- **No input injection.** FluxSync never simulates taps, gestures, or button presses through this service — it only observes events the user already generated.
- **No network access beyond your paired LAN peers.** Whatever is captured goes straight into the same end-to-end-encrypted Noise IK pipeline as clipboard content from any other source, sent only to devices you've explicitly paired with, over your local network. Nothing is ever sent to a server FluxSync operates, because there is no such server — see the main [README](../README.md) and [`SECURITY.md`](./SECURITY.md).

## How to verify this yourself

FluxSync is fully open source. You don't have to take this document's word for it:

- The service implementation: `apps/android/app/src/main/java/sn/kaolack/fluxsync/FluxsyncAccessibilityService.kt`.
- Its declared capabilities: `apps/android/app/src/main/res/xml/accessibility_service_config.xml` — the `android:accessibilityEventTypes` and `android:canRetrieveWindowContent` attributes are the OS-enforced ceiling on what the service can even ask for; compare them against what's described above.
- Absence of anything further: there is no `dispatchGesture`, `performGlobalAction`, or input-injection call anywhere in the Android app's source — search for yourself.
- Network behavior: capture your own LAN traffic (e.g. with Wireshark) while using FluxSync. You'll see UDP traffic only to devices you've paired, only on your local network, and it will be opaque ChaCha20-Poly1305 ciphertext — see [`PROTOCOL.md`](./PROTOCOL.md) for the wire format.

## How to disable it

Accessibility permission is optional and revocable at any time:

**Settings → Accessibility → FluxSync → turn off.**

With it off, FluxSync still syncs clipboard content it can capture via the normal foreground `ClipboardManager` path — you'll just lose the fallback capture for the third-party apps/actions described above. Nothing else in the app is affected, and you don't need to uninstall or re-pair anything.

If you'd rather not grant Accessibility at all, you can still use FluxSync one-way or opportunistically (copy while the app is open/foregrounded), or use it purely as a receiver on that device.
