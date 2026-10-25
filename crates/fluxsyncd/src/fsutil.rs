//! Crash-safe file writes shared by every on-disk store (keystore, vault,
//! sequence horizon).

use anyhow::{Context, Result};
use std::fs;
use std::io::Write;
use std::path::Path;

/// Replace `path` with `bytes` atomically: write a private (0600 on unix)
/// temp file `tmp` beside it, fsync it, rename it over `path`, then fsync
/// the directory so the rename itself is durable. Without that last step a
/// power cut right after a "successful" save can roll the file back to its
/// previous contents — or lose a first write entirely.
pub(crate) fn write_atomic(path: &Path, tmp: &Path, bytes: &[u8]) -> Result<()> {
    {
        let mut opts = fs::OpenOptions::new();
        opts.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts
            .open(tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    sync_dir_of(path);
    Ok(())
}

/// Best-effort fsync of `path`'s directory. Unix only: Windows has no
/// directory handle to flush (NTFS journals the rename itself). A failure
/// is logged, not returned — the new contents are already in place.
fn sync_dir_of(path: &Path) {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(d) if !d.as_os_str().is_empty() => d,
            _ => Path::new("."),
        };
        if let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all()) {
            tracing::debug!(dir = %dir.display(), error = %e, "directory fsync failed");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::write_atomic;

    #[test]
    fn replaces_contents_and_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let tmp = dir.path().join("state.json.tmp");
        write_atomic(&path, &tmp, b"one").unwrap();
        write_atomic(&path, &tmp, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!tmp.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
