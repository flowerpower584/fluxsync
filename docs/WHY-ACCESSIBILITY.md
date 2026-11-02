# Why FluxSync asks for Accessibility permission on Android

Short version: it's the only supported way for a background clipboard-sync app to reliably catch a copy on modern Android, it's used for exactly that, and you can turn it off at any time without uninstalling the app.

## The Android problem this solves

Since Android 10, apps running in the background cannot read the system clipboard at all — this is a deliberate OS privacy restriction, not a FluxSync limitation. A normal `ClipboardManager` listener only fires reliably while your app is in the foreground. FluxSync's entire purpose is syncing clipboard content *between devices without you having to switch to it first*, so a foreground-only listener would defeat the app.

The Accessibility API is the one Android capability that can observe UI events (including copy actions) while running as a background service. It was not designed for clipboard sync — apps use it for this because Android currently offers no purpose-built "background clipboard access" permission. This is a known, widely-discussed trade-off in the Android developer community, not something specific to FluxSync.

## What FluxSync actually does with it

Android only lets the app **in front** (or your keyboard) read the clipboard. So FluxSync's Accessibility Service (`FluxsyncAccessibilityService.kt`, in `apps/android`) doesn't read the clipboard itself. It watches for the **signs that you just copied something**, and then lets FluxSync read the clipboard the way Android allows: in front, for an instant.

The signs it looks at (and nothing else):

- **A tap on a "Copy" button or menu item** — the clicked control's label or description contains a word like "copy" / "copier" / "copiar".
- **A "Copied" message** — a toast whose text says "copied" / "copié" / "copiado"…
- **The system clipboard bubble** — the small preview Android 13+ and Samsung One UI show after a copy (a window whose class name mentions the clipboard).
- **Text selection and long-press** — remembered only as a fallback (below).

When it sees one, it opens an **invisible FluxSync screen for a fraction of a second**: that screen is in front, so Android lets it read the clipboard. It sends the copy to your paired devices if it's new, and closes. Android 12+ shows its usual "FluxSync pasted from your clipboard" notice when this happens — that's Android being transparent about it, and it's expected.

Opening that screen from the background is allowed by Android for an app whose accessibility service you turned on (a documented exception to the background-activity rules). If your phone blocks it anyway (some manufacturers have a "show pop-up windows while running in the background" switch — on Xiaomi, turn it on for FluxSync), FluxSync falls back to sending the text you had selected when you tapped "Copy".

You can always send by hand too: the **Send clipboard** button on FluxSync's notification, the quick-settings tile, or **Share → FluxSync**.

## What FluxSync never does

- **No keylogging.** The service does not listen for key events or IME input; it only reacts to the copy signs listed above.
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

With it off, copies made on the phone are only sent when FluxSync is open, or by hand (notification button, tile, Share). What you copy on your other devices still arrives on the phone. Nothing else in the app is affected, and you don't need to uninstall or re-pair anything.

If you'd rather not grant Accessibility at all, you can still use FluxSync one-way or opportunistically (copy while the app is open/foregrounded), or use it purely as a receiver on that device.
