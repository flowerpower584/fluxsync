# FluxSync macOS tray (Tauri v2)

Menu-bar app. Talks to `fluxsyncd` over its UNIX socket — no daemon
code is linked into this binary; the tray is a pure IPC client.

## Layout

```
apps/macos-tray/
├── package.json          # Tauri CLI entry (npm-managed)
├── src/                  # Static frontend (no bundler)
│   ├── index.html        # Popup (320 × 460)
│   ├── pair.html         # Pair window (420 × 540)
│   ├── styles.css        # Design tokens (FS.dark)
│   ├── app.js            # Popup logic
│   └── pair.js           # Pair window logic
├── src-tauri/
│   ├── Cargo.toml        # Standalone (NOT in the workspace)
│   ├── tauri.conf.json
│   ├── build.rs
│   ├── capabilities/default.json
│   └── src/
│       ├── main.rs       # 1-line shim → lib::run()
│       ├── lib.rs        # Tauri builder + tray + IPC commands
│       └── ipc.rs        # UNIX socket client
└── icons/                # PNG/ICNS for the tray + bundle (drop here)
```

## Prerequisites

- Rust ≥ 1.75 (stable)
- Node ≥ 18 (for the Tauri CLI; the frontend itself ships zero JS deps)
- Xcode CLT (macOS code-signing + bundling)
- `fluxsyncd` running on the same machine (or pointed at via
  `FLUXSYNC_IPC_PATH=/path/to/sock`)

## Tray icon

Tauri v2 needs `icons/icon.png` and `icons/icon.icns` for the bundle.
Drop a 16 × 16 (and @2x: 32 × 32) PNG black-on-transparent silhouette
that mirrors `frame-android.jsx`'s `TrayGlyph`. macOS treats the file
as a template image (set in `tauri.conf.json`), so you do **not**
need a colored asset — it inherits the menu-bar tint automatically.

```sh
mkdir -p icons
# Put icons/icon.png + icons/icon.icns here. The bundler also wants
# 32x32, 128x128, 128x128@2x — see tauri.conf.json `bundle.icon`.
```

## Dev loop

```sh
cd apps/macos-tray
npm install                # one-shot, installs @tauri-apps/cli
npm run dev                # opens the tray icon + a hot-reloading WebView
```

The popup window is created hidden in `tauri.conf.json`; clicking the
tray icon shows it. Right-click the tray for the native menu (Pair /
Preferences / Quit).

## Production build

```sh
npm run build              # → src-tauri/target/release/bundle/macos/FluxSync.app
                           #   src-tauri/target/release/bundle/dmg/FluxSync_*.dmg
```

The Tauri build runs an optimised `cargo build --release` of the
standalone `fluxsync-macos-tray` crate (NOT part of the workspace —
mixing it in fights workspace `cargo check` invariants).

## Distribution

The intended path is via `brew install fluxsync`, which builds + 
installs `fluxsyncd` and `fluxctl` (see `packaging/homebrew/fluxsync.rb`)
and sets up `brew services` for auto-start. The tray app itself is a
separate `.dmg` — install it manually until the cask is published in
v0.2.

```sh
brew tap flowerpower584/fluxsync
brew install fluxsync
brew services start fluxsync
# Then drag FluxSync.app from the .dmg into /Applications.
```
