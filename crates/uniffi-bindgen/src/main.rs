//! Thin wrapper around `uniffi`'s built-in CLI. Adding this as a
//! workspace member means the Android build can run the bindgen with
//! `cargo run -p uniffi-bindgen -- generate ...` instead of relying on
//! a `cargo install` step that drifts between developer machines.
fn main() {
    uniffi::uniffi_bindgen_main();
}
