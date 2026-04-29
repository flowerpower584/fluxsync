# Contributing to FluxSync

> Small project, strict bar. Read this once, then `cargo test`.

---

## 1. Toolchain

- **Rust**: stable, MSRV `1.75`. Pinned in `rust-toolchain.toml`.
- **Cargo extras** (install once):
  ```sh
  rustup component add rustfmt clippy llvm-tools-preview
  cargo install cargo-llvm-cov cargo-deny
  ```
- **Cross builds (Android)**:
  ```sh
  rustup target add aarch64-linux-android
  cargo install cross
  ```

No `nightly`. No unstable cargo features. If you need one, open an issue first.

---

## 2. Workspace cheatsheet

```sh
# all the things, once
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace

# one crate at a time
cargo test -p fluxsync-core

# coverage (must stay >= 80% on fluxsync-core)
cargo llvm-cov --workspace --fail-under-lines 80

# the daemon
cargo run -p fluxsyncd

# the CLI
cargo run -p fluxctl -- status
```

---

## 3. Code style

- **Formatting**: `cargo fmt` is the law. Do not hand-format.
- **Lints**: `clippy::all` is **denied** (CI bar). `clippy::pedantic` is **warn-only**: triage at PR review and either fix or suppress with `#[allow(clippy::xxx)]` plus a one-line comment explaining why. We don't fight pedantic on green-field code, but a regression on `clippy::all` blocks the merge.
- **Errors**: `thiserror` for libraries (typed errors), `anyhow` for binaries (CLI, daemon `main`). Never `unwrap()` or `panic!()` outside `#[cfg(test)]`.
- **Logging**: `tracing` only. JSON to stderr from binaries. INFO is the default; DEBUG behind `--verbose`. Use `tracing::instrument` on async fns where the span is useful.
- **Friendly logs**: any event the user might read (UI's logs view) goes through the `friendly!()` macro in `fluxsyncd::logs`. The macro emits the structured `tracing` event **and** a plain-English copy on the IPC `logs` channel.
- **`unsafe`**: forbidden outside FFI. If unavoidable, prefix the block with `// SAFETY: <invariant>`.
- **Comments**: explain *why*, not *what*. The code should already say *what*. Default to no comment.

---

## 4. Layering rule (do not break)

```
fluxsync-proto   →  no other fluxsync crates
fluxsync-crypto  →  proto
fluxsync-core    →  proto
fluxsyncd        →  core, crypto, proto
fluxctl          →  proto only (talks to fluxsyncd over IPC; no shared state)
fluxsync-mobile-ffi → core, crypto, proto, fluxsyncd as a library
```

If your change requires breaking this layering, propose the new shape in the PR description before writing the code.

---

## 5. Testing rules

- Every `fluxsync-core` module ships with unit tests in the same file (`#[cfg(test)] mod tests`).
- Property tests (`proptest`) live next to the type they exercise. For CBOR types in `fluxsync-proto`, the round-trip test is mandatory.
- Daemon integration tests live in `crates/fluxsyncd/tests/`. The `two_daemons.rs` test uses `fluxsync_crypto::pair_for_test` (gated `test-util` feature) so a sync regression does not look like a pairing regression.
- No test takes longer than 5 s on a recent laptop. If yours does, mark it `#[ignore]` and document the trigger.
- Coverage on `fluxsync-core` must stay `>= 80%`. The CI gate is `cargo llvm-cov --fail-under-lines 80 -p fluxsync-core`.

---

## 6. Commits & PRs

- One concept per commit. `git rebase -i` before opening the PR.
- Subject line: imperative, ≤ 72 chars. Example: `core: dedup ring buffer drops duplicates by hash`.
- Body: the *why*. The diff already says the *what*.
- PR title mirrors the lead commit. PR body lists user-visible changes and tradeoffs.
- Sign your commits if you can (`git commit -S`). Not enforced in v0.1.

---

## 7. Security

If you find a security bug, **do not open a public issue**. Email Dethie (address in `Cargo.toml`). See `docs/SECURITY.md` §5.

---

## 8. Definition of done

A PR can land when:
- [ ] `cargo fmt --check` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] `cargo test --workspace` passes
- [ ] Coverage on touched code does not regress
- [ ] PR description explains the *why*
- [ ] Docs updated if behaviour changed (README, ARCHITECTURE.md, PROTOCOL.md, SECURITY.md)

---

## 9. Anti-goals (do not propose)

- Adding a GUI dependency to `fluxsyncd`. The daemon is headless on purpose.
- Adding a network call that is not over the documented Noise channel.
- Adding a feature flag that hides backwards-compat shims. Either change it everywhere, or do not change it.
- Generating documentation files (`*.md`) without explicit ask.
- Telemetry. Of any kind.
