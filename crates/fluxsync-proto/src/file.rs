//! Payload framing for [`crate::Kind::File`] items: the file's name travels
//! with its bytes, so a receiver can save it under the same name.
//!
//! Layout: name length (u16, big-endian) · name (UTF-8) · file bytes.

/// Longest file name carried, in bytes. Longer names are cut at a char
/// boundary.
pub const MAX_NAME: usize = 255;

/// Frame `name` + `bytes` into one `Kind::File` payload. Only the final
/// path component of `name` is kept.
#[must_use]
pub fn encode(name: &str, bytes: &[u8]) -> Vec<u8> {
    let name = sanitize(name);
    let mut out = Vec::with_capacity(2 + name.len() + bytes.len());
    #[allow(clippy::cast_possible_truncation)] // `sanitize` caps it at MAX_NAME
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Split a `Kind::File` payload into a safe file name and the file bytes.
/// `None` for a malformed payload.
#[must_use]
pub fn decode(payload: &[u8]) -> Option<(String, &[u8])> {
    let len = usize::from(u16::from_be_bytes([*payload.first()?, *payload.get(1)?]));
    let name = std::str::from_utf8(payload.get(2..2 + len)?).ok()?;
    Some((sanitize(name), &payload[2 + len..]))
}

/// A file name that is safe to create in a downloads folder: no directory
/// parts, no control characters, not empty or a dot-name, at most
/// [`MAX_NAME`] bytes.
#[must_use]
pub fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let mut clean: String = base
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, ':' | '*' | '?' | '"' | '<' | '>' | '|') {
                '_'
            } else {
                c
            }
        })
        .collect();
    clean = clean.trim().trim_start_matches('.').to_string();
    if clean.is_empty() {
        clean = "file".to_string();
    }
    while clean.len() > MAX_NAME {
        clean.pop();
    }
    clean
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_name_and_bytes() {
        let p = encode("report.pdf", b"%PDF-1.7");
        let (name, bytes) = decode(&p).unwrap();
        assert_eq!(name, "report.pdf");
        assert_eq!(bytes, b"%PDF-1.7");
    }

    #[test]
    fn names_cannot_escape_the_folder() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize("C:\\Users\\a\\x.txt"), "x.txt");
        assert_eq!(sanitize(".."), "file");
        assert_eq!(sanitize(".bashrc"), "bashrc");
        assert_eq!(sanitize("a\nb?.txt"), "a_b_.txt");
        assert_eq!(sanitize(&"é".repeat(200)).len(), 254);
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        assert!(decode(&[]).is_none());
        assert!(decode(&[0, 9, b'a']).is_none());
        assert!(decode(&[0xff, 0xfe, 0xa0]).is_none());
    }
}
