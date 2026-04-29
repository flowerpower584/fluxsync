# FluxSync Android (v0.1 skeleton)

This is a **skeleton**. The Compose UI lands in v0.1.1.

What ships in v0.1:
- Gradle project that loads `libfluxsync_mobile_ffi.so` for `arm64-v8a`.
- A single `MainActivity` that calls `FluxsyncHandle.start(...)`,
  installs a `StateObserver`, and prints each state JSON to a
  `TextView` (and logcat).
- No persistence, no notifications, no QR pairing UI.

## Build

```sh
# 1. Build the Rust .so for android
cargo install cargo-ndk
cargo ndk -t arm64-v8a build --release -p fluxsync-mobile-ffi
cp ../../target/aarch64-linux-android/release/libfluxsync_mobile_ffi.so \
   app/src/main/jniLibs/arm64-v8a/

# 2. Generate Kotlin bindings
cargo install uniffi-bindgen-cli
uniffi-bindgen-cli generate \
  --library ../../target/aarch64-linux-android/release/libfluxsync_mobile_ffi.so \
  --language kotlin \
  --out-dir app/src/main/java

# 3. Assemble
./gradlew assembleDebug
```

## Identity persistence

`start(... identitySecretB64 = null)` regenerates a fresh keypair on every
boot. v0.1.1 will persist via the Android Keystore. If you want to manage
the keypair yourself today, store 32 random bytes in the Keystore, base64
them, and pass as `identitySecretB64`.

## What the FFI exposes

Six entry points only — see `crates/fluxsync-mobile-ffi/src/lib.rs`:

```kotlin
val h = FluxsyncHandle.start(peerName, ipcPath, udpPort, identitySecretB64)
h.observeState(observer)            // verbatim JSON per state change
h.pushText("hello")
h.setBatteryThreshold(20u)          // 5..=50
h.setChargeOverride(true)
h.stop()
```
