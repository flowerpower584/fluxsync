# FluxSync release checklist

Reference for shipping `vX.Y.Z`. Read top-to-bottom on every release.

## 0. Preconditions

- [ ] `main` is the branch being released. NO feature branch tags.
- [ ] Working tree clean (`git status` empty).
- [ ] Confirm exact commit being shipped (`git rev-parse HEAD`).
- [ ] No open `WIP:` / `XXX:` / `TODO(blocker):` in touched files.
- [ ] Pending memory log entries for this version closed.

## 1. Quality gate (MANDATORY, no skip)

```bash
cd /Users/dethiekaire/fluxsync
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
cargo audit
```

Per-app extras:

```bash
# macOS tray
cd apps/macos-tray && pnpm tsc --noEmit && pnpm build && cd -

# Android
cd apps/android && JAVA_HOME="$ANDROID_JBR" ./gradlew lint test && cd -
```

ALL must be green. Any failure = stop, fix, restart this section.

## 2. Security gate (for any release touching crypto / transport / IPC / pairing)

- [ ] Re-read `references/THREAT-MODEL-summary.md`.
- [ ] Run `differential-review` skill against `vPrev..HEAD`.
- [ ] Run `constant-time-analysis` on touched crypto.
- [ ] Run `zeroize-audit` on touched secret-handling.
- [ ] Run `rust-dependency-audit` + `supply-chain-risk-auditor`.
- [ ] Update `docs/THREAT-MODEL.md` if any cell changes.
- [ ] Confirm no `FS-052..061` ticket regressed.

## 3. Version bump

- [ ] Root `Cargo.toml`: bump `[workspace.package] version`.
- [ ] Verify per-crate `Cargo.toml` inherits via `version.workspace = true`. Bump explicit overrides.
- [ ] `apps/android/app/build.gradle.kts`: bump `versionName` + `versionCode`.
- [ ] `apps/macos-tray/src-tauri/tauri.conf.json`: bump `version`.
- [ ] `apps/macos-tray/src-tauri/Cargo.toml`: bump `version`.
- [ ] `packaging/homebrew/fluxsync.rb`: bump `version` (SHA256 updated post-release).
- [ ] `Cargo.lock`: regenerate via `cargo update -p fluxsync-core` (or affected workspace member).
- [ ] Commit: `release: bump to vX.Y.Z`.

## 4. CHANGELOG

- [ ] Add section `## [vX.Y.Z] — YYYY-MM-DD` at top.
- [ ] One-line subtitle (e.g. "Clipboard reliability.").
- [ ] Group entries: Added / Changed / Fixed / Security / Deprecated / Removed.
- [ ] Each entry = past tense, user-facing impact, NOT internal diff.
- [ ] Link any FS-XXX ticket closed.
- [ ] Commit: `docs: changelog vX.Y.Z`.

## 5. Build artifacts

| Platform | Command | Output |
|----------|---------|--------|
| macOS universal DMG | `cd apps/macos-tray && pnpm tauri build --target universal-apple-darwin` | `src-tauri/target/.../FluxSync_X.Y.Z_universal.dmg` |
| Windows NSIS x64 | `cargo xwin build --release --target x86_64-pc-windows-msvc -p fluxsyncd -p fluxctl && cd apps/macos-tray && pnpm tauri build --target x86_64-pc-windows-msvc` | `Setup.exe` (NSIS, embedBootstrapper, currentUser) |
| Windows NSIS ARM64 | `pnpm tauri build --target aarch64-pc-windows-msvc` | `Setup.exe` |
| Linux x86_64 deb | `cargo build --release --target x86_64-unknown-linux-musl -p fluxsyncd -p fluxctl` + dpkg-deb | `fluxsync_X.Y.Z_amd64.deb` |
| Linux AppImage | linuxdeploy + AppImageTool | `FluxSync-X.Y.Z.AppImage` |
| Android APK | `cd apps/android && ./gradlew assembleRelease` | `app/build/outputs/apk/release/app-release.apk` (signed) |

All artifacts:
- [ ] SHA256 computed and recorded.
- [ ] macOS: notarized via `xcrun notarytool submit … --wait`.
- [ ] Windows: signed via `signtool` (if cert available).
- [ ] Android: signed with release keystore (NOT debug).

## 6. Tag + push

- [ ] `git tag -s vX.Y.Z -m "FluxSync vX.Y.Z"` (GPG-signed).
- [ ] `git push origin main && git push origin vX.Y.Z`.
- [ ] CI green on tag.

## 7. GitHub Release

- [ ] `gh release create vX.Y.Z --title "vX.Y.Z" --notes-from-tag` (or `--notes-file`).
- [ ] Upload artifacts from §5.
- [ ] Pin matching CHANGELOG section in release notes.
- [ ] If pre-release: `--prerelease` flag.

## 8. Brew formula update

- [ ] In `flowerpower584/homebrew-fluxsync` tap repo:
  - [ ] Update `Formula/fluxsync.rb`: `url`, `sha256`, `version`.
  - [ ] Test: `brew install --build-from-source ./Formula/fluxsync.rb`.
  - [ ] PR + merge.
- [ ] In FluxSync repo `packaging/homebrew/fluxsync.rb`: mirror updated SHA256.
- [ ] Commit: `packaging: brew formula vX.Y.Z`.

## 9. Post-release verification

- [ ] Fresh macOS install: `brew tap flowerpower584/fluxsync && brew install fluxsync && fluxsyncd --version`.
- [ ] Fresh DMG install: download GH release DMG, drag to Applications, launch, verify tray.
- [ ] Fresh Windows install: Setup.exe → run → confirm tray + WebView2 bootstrap.
- [ ] Fresh Android: install APK on test device (S21 Ultra historically), pair with Mac, send text + image both directions.
- [ ] `fluxctl pair show` → `pair from-uri` → SAS match → `pair confirm --accept` on both ends → clipboard sync works.

## 10. Communications

- [ ] Tweet / Mastodon post: title + 1 demo GIF + GH release link.
- [ ] If milestone (x.0.0 / first cross-platform / etc.): HN Show post Tuesday/Wednesday 8am PT.
  - Title: "FluxSync vX.Y.Z — local-only clipboard sync between Mac, Windows, Linux, Android (Rust, no server)".
  - Comment with technical detail in first reply.
- [ ] Update memory: log `fluxsync_release_vX_Y_Z.md`.
- [ ] If donation tier touched: NEVER. Repo stays donations-only (Sponsors / Ko-fi / crypto).

## 11. Rollback procedure (if release is broken post-tag)

- [ ] DO NOT delete tag if release was downloaded by anyone (CDN caches).
- [ ] Cut `vX.Y.Z+1` as patch with revert.
- [ ] GH release: mark broken `vX.Y.Z` as `--draft` if zero downloads; otherwise leave + add release notes warning.
- [ ] Brew tap: revert formula PR or fast-forward to `vX.Y.Z+1`.
- [ ] Post-mortem in `docs/post-mortems/vX.Y.Z.md`.

## Last-shipped baseline

- v0.5.2 = `main @ 744c035` (2026-05-17). Clipboard reliability + Revoke/Unpair fix.
- v0.6.0 plan @ `b6f161e` (2026-05-19, NOT pushed at memory time — verify before tag).

## Anti-patterns this checklist exists to prevent

- Tagged before CI green.
- Brew formula SHA256 mismatch → users blocked.
- macOS DMG unnotarized → Gatekeeper blocks first-run.
- Windows installer missing WebView2 bootstrapper → blank window on fresh Win11.
- Android APK signed with debug key → can't update from store.
- Version bumped in some Cargo.toml files but not all → workspace incoherent.
- Wrong tap account (`dethie/*` vs `flowerpower584/*`). Confirm before push.
