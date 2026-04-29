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
    use nix::sys::stat::{umask, Mode};
    use std::os::unix::fs::PermissionsExt;
    use tokio::net::{UnixListener, UnixStream};

    pub struct IpcServer {
        listener: UnixListener,
        _path: PathBuf,
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

    pub struct IpcServer {
        _path: PathBuf,
    }

    pub struct IpcConn {
        // Phantom — never constructed in v0.1.
        _stream: tokio::io::DuplexStream,
    }

    impl IpcServer {
        pub async fn bind(_path: &Path) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Named Pipe IPC for Windows is not implemented in v0.1; \
                 Linux/macOS only. v0.1.1 will add it via \
                 tokio::net::windows::named_pipe.",
            ))
        }

        pub async fn accept(&self) -> io::Result<IpcConn> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows IPC not implemented",
            ))
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
        tokio::io::split(self._stream)
    }
}
