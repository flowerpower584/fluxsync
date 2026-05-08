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
        _path: PathBuf,
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
                _path: path.to_path_buf(),
                _lock: lock,
            })
        }

        pub async fn accept(&self) -> io::Result<IpcConn> {
            let (stream, _) = self.listener.accept().await?;
            Ok(IpcConn { stream })
        }
    }
}

#[cfg(windows)]
mod sys {
    use super::{io, Path, PathBuf};
    use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

    pub struct IpcServer {
        path: PathBuf,
        next: tokio::sync::Mutex<NamedPipeServer>,
    }

    pub struct IpcConn {
        pub(crate) stream: NamedPipeServer,
    }

    impl IpcServer {
        pub async fn bind(path: &Path) -> io::Result<Self> {
            let first = ServerOptions::new()
                .first_pipe_instance(true)
                .create(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                next: tokio::sync::Mutex::new(first),
            })
        }

        pub async fn accept(&self) -> io::Result<IpcConn> {
            let mut lock = self.next.lock().await;
            lock.connect().await?;
            let stream = std::mem::replace(&mut *lock, ServerOptions::new().create(&self.path)?);
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
    pub fn split(self) -> (impl AsyncRead + Unpin, impl AsyncWrite + Unpin) {
        self.stream.into_split()
    }

    #[cfg(windows)]
    pub fn split(self) -> (impl AsyncRead + Unpin, impl AsyncWrite + Unpin) {
        tokio::io::split(self.stream)
    }
}
