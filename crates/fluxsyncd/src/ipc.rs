//! Cross-platform IPC abstraction.
//!
//! Linux/macOS: `AF_UNIX SOCK_STREAM` at `~/.fluxsync/sock`. The socket
//! is created with mode `0600` via a process-wide `umask(0o077)` call
//! around `bind` so there is **no race window** between `bind` and a
//! follow-up `chmod` (user reminder #3 from CHECKPOINT 5). The parent
//! directory is forced to `0700` as defense-in-depth so even the brief
//! moment the socket inode exists is invisible to other UIDs.
//!
//! Windows: Named Pipe stub. v0.1 ships Linux/macOS only; a Named Pipe
//! implementation lands in v0.1.1 (the trait surface is shaped to make
//! the port mechanical — handlers depend only on the
//! `IpcServer`/`IpcConn` API, never on `tokio::net::UnixListener`
//! directly).

use std::io;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(unix)]
mod sys {
    use super::{io, Path, PathBuf};
    use nix::fcntl::{Flock, FlockArg};
    use nix::sys::stat::{umask, Mode};
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    pub struct IpcServer {
        listener: UnixListener,
        path: PathBuf,
        _lock: Flock<std::fs::File>,
    }

    pub struct IpcConn {
        pub(crate) stream: UnixStream,
    }

    impl IpcServer {
        pub async fn bind(path: &Path) -> io::Result<Self> {
            // Parent dir 0700 — defense in depth.
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent).await?;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
            }

            // [REMEDIATION] Atomic Locking: Use a .lock file to prevent double-daemon split-brain.
            let lock_path = path.with_extension("lock");
            let lock_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)?;

            // Try to acquire an exclusive lock. If it fails, another daemon is already running.
            let lock = match Flock::lock(lock_file, FlockArg::LockExclusiveNonblock) {
                Ok(l) => l,
                Err((file, e)) => {
                    drop(file);
                    return Err(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!(
                            "FluxSync daemon already running (lock held at {}): {}",
                            lock_path.display(),
                            e
                        ),
                    ));
                }
            };

            // Remove any stale socket.
            if path.exists() {
                std::fs::remove_file(path)?;
            }
            // Tighten umask, bind, restore. The umask call is a process-
            // wide setting so we keep the window as short as possible.
            let prev = umask(Mode::from_bits_truncate(0o077));
            let bind_result = UnixListener::bind(path);
            let _ = umask(prev);
            let listener = bind_result?;
            // Belt-and-braces chmod (no race here because the umask
            // already gave us 0600 at create time).
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                listener,
                path: path.to_path_buf(),
                _lock: lock,
            })
        }

        pub async fn accept(&self) -> io::Result<IpcConn> {
            let (stream, _) = self.listener.accept().await?;
            Ok(IpcConn { stream })
        }
    }

    impl Drop for IpcServer {
        fn drop(&mut self) {
            // Unlink our socket inode on exit so a stale path doesn't
            // linger and read as "daemon running". The flock in `_lock`
            // releases on drop too. Best-effort: a failure is harmless —
            // `bind()` removes a stale socket before re-binding anyway.
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(windows)]
#[allow(unsafe_code)]
// Windows Named Pipe with an explicit DACL — see PIPE_SDDL below.
// All `unsafe` here wraps Win32 security-descriptor APIs and tokio's
// raw security-attributes entry point. Every block carries a Safety
// comment describing the invariants it relies on.
mod sys {
    use super::{io, Path, PathBuf};
    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    /// SDDL: protected DACL (`P`) that grants `Generic All` to the
    /// pipe's creator owner (`OW`, the current process user) and to
    /// `LocalSystem` (`SY`). Without `P`, the DACL would inherit ACEs
    /// from the parent that could re-add `Authenticated Users`; with
    /// `P`, only the ACEs listed here apply.
    ///
    /// This replaces the named-pipe default DACL (`Authenticated
    /// Users` get read access, `Everyone` gets read/write via the
    /// `Anonymous` group on some configs) so a second local account
    /// cannot send `Push` / `Unpair` / `Revoke` / `PairAccept`
    /// requests to our IPC.
    const PIPE_SDDL: &str = "D:P(A;;GA;;;OW)(A;;GA;;;SY)";

    /// Holds the security descriptor allocated by Win32; freed on
    /// drop with `LocalFree` so leaving the daemon does not leak it.
    /// The `SECURITY_ATTRIBUTES` value we hand to tokio borrows the
    /// pointer; we keep the descriptor alive for the lifetime of
    /// `IpcServer`.
    struct PipeSecurity {
        sd: *mut c_void,
        sa: SECURITY_ATTRIBUTES,
    }

    // Safety: the pointed-at security descriptor is allocated by
    // `LocalAlloc` (via the conversion function) and freed only on
    // drop. The struct is never sent or shared across threads in the
    // server loop.
    unsafe impl Send for PipeSecurity {}
    unsafe impl Sync for PipeSecurity {}

    impl PipeSecurity {
        fn new() -> io::Result<Self> {
            let sddl_w: Vec<u16> = std::ffi::OsStr::new(PIPE_SDDL)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut sd: *mut c_void = ptr::null_mut();
            // Safety: `sddl_w` is a NUL-terminated UTF-16 string; the
            // output pointer is written by the API on success.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl_w.as_ptr(),
                    SDDL_REVISION_1,
                    std::ptr::addr_of_mut!(sd),
                    ptr::null_mut(),
                )
            };
            if ok == 0 || sd.is_null() {
                return Err(io::Error::last_os_error());
            }
            let sa = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .expect("SECURITY_ATTRIBUTES fits in u32"),
                lpSecurityDescriptor: sd,
                bInheritHandle: 0,
            };
            Ok(Self { sd, sa })
        }

        fn as_ptr(&self) -> *const c_void {
            std::ptr::from_ref::<SECURITY_ATTRIBUTES>(&self.sa).cast::<c_void>()
        }
    }

    impl Drop for PipeSecurity {
        fn drop(&mut self) {
            if !self.sd.is_null() {
                // Safety: `sd` was allocated by `LocalAlloc` inside
                // `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
                unsafe {
                    LocalFree(self.sd.cast());
                }
            }
        }
    }

    pub struct IpcServer {
        path: PathBuf,
        next: tokio::sync::Mutex<NamedPipeServer>,
        // Kept alive for the lifetime of the server so subsequent
        // `accept()` calls can hand the same SECURITY_ATTRIBUTES back
        // to `create_with_security_attributes_raw`.
        security: PipeSecurity,
    }

    pub struct IpcConn {
        pub(crate) stream: NamedPipeServer,
    }

    impl IpcServer {
        // `bind` is `async` on every platform to keep the trait surface
        // identical with the Unix path; the Windows body itself does
        // no awaiting.
        #[allow(clippy::unused_async)]
        pub async fn bind(path: &Path) -> io::Result<Self> {
            let security = PipeSecurity::new()?;
            // Safety: `security.as_ptr()` returns a pointer to a
            // valid `SECURITY_ATTRIBUTES` whose lifetime exceeds the
            // pipe handle's. tokio dereferences it during creation
            // and does not retain it.
            let first = unsafe {
                ServerOptions::new()
                    .first_pipe_instance(true)
                    .create_with_security_attributes_raw(path, security.as_ptr().cast_mut())?
            };
            Ok(Self {
                path: path.to_path_buf(),
                next: tokio::sync::Mutex::new(first),
                security,
            })
        }

        pub async fn accept(&self) -> io::Result<IpcConn> {
            let mut lock = self.next.lock().await;
            lock.connect().await?;
            // Safety: see `bind`. The same security descriptor is
            // reused for every subsequent pipe instance.
            let next = unsafe {
                ServerOptions::new().create_with_security_attributes_raw(
                    &self.path,
                    self.security.as_ptr().cast_mut(),
                )?
            };
            let stream = std::mem::replace(&mut *lock, next);
            Ok(IpcConn { stream })
        }
    }
}

pub use sys::{IpcConn, IpcServer};

impl IpcConn {
    /// Split the connection into a read half and a write half. Required
    /// because IPC subscribers read commands while the daemon
    /// concurrently pushes state events.
    #[cfg(unix)]
    #[must_use]
    pub fn split(self) -> (impl AsyncRead + Unpin, impl AsyncWrite + Unpin) {
        self.stream.into_split()
    }

    #[cfg(windows)]
    #[must_use]
    pub fn split(self) -> (impl AsyncRead + Unpin, impl AsyncWrite + Unpin) {
        tokio::io::split(self.stream)
    }
}
