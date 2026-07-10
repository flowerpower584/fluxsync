# Release keystore

This directory holds the Android release signing key (DIR-P4-02). The
keystore file itself (`fluxsync-release.keystore`) and its credentials
(`../keystore.properties`, one level up in `apps/android/`) are both
gitignored — `git status` must never show either as trackable. Only
this README is committed.

## What lives here

- `keystore/fluxsync-release.keystore` — PKCS12 keystore, one key pair,
  alias `fluxsync-release`, RSA 4096, self-signed, valid 30 years
  (2026-07-08 → 2056-07-08).
- `../keystore.properties` — `storeFile`, `storePassword`, `keyAlias`,
  `keyPassword` read by `app/build.gradle.kts` to sign the `release`
  build type. Not present → `assembleRelease` silently falls back to
  debug signing (see the warning Gradle prints during configuration).

Note: PKCS12 keystores use a single password for both the store and
the key — `storePassword` and `keyPassword` in `keystore.properties`
are intentionally the same value here (`keytool` enforces this; a
distinct `-keypass` is silently ignored for PKCS12).

## CRITICAL — losing this file is unrecoverable

Android requires every update to an app to be signed with the **same**
key as the version currently installed on a user's device. If this
keystore is lost, or the passwords in `keystore.properties` are
forgotten:

- No future release can ever be signed to match past releases.
- Every existing install becomes a dead end — users **must uninstall
  the app and reinstall the new release from scratch**, losing any
  local-only app data that isn't synced elsewhere.
- There is no recovery path. Regenerating a new keystore produces a
  *different* signing identity, not a replacement for this one.

**Back up both `fluxsync-release.keystore` and `keystore.properties`
off this disk immediately** — e.g. a password manager attachment plus
an encrypted offline copy (external drive, cold storage). Do not rely
solely on this machine's disk. Do not commit them to git, Slack them,
or email them unencrypted.

## Regenerating (only if starting a new signing identity on purpose)

```
keytool -genkeypair -v \
  -keystore keystore/fluxsync-release.keystore \
  -alias fluxsync-release \
  -keyalg RSA -keysize 4096 -validity 10958 \
  -storetype PKCS12
```

Then recreate `../keystore.properties` alongside it with the four
properties listed above. Understand that doing this on an app already
shipped to users breaks their upgrade path (see above) — only do this
for a fresh applicationId / fresh install base.
