//! Serde adapter for the `Vec<u8>` payload fields on the wire.
//!
//! serde's default for `Vec<u8>` is a sequence, which ciborium writes as a
//! CBOR array of integers: every byte ≥ 0x18 then costs two bytes, so a
//! 1 KiB chunk went out as ~2 KiB and every datagram fragmented at the IP
//! layer (a single lost fragment drops the whole datagram). This writes a
//! CBOR byte string instead — one header plus the raw bytes.
//!
//! It is wire-compatible in both directions without a `PROTOCOL_VERSION`
//! bump: decoding here accepts both byte strings and the legacy arrays, and
//! older builds already decode byte strings, because ciborium's
//! `deserialize_seq` (what a plain `Vec<u8>` field asks for) accepts a byte
//! string header and yields its bytes as the sequence.

use serde::{de, Deserializer, Serializer};
use std::fmt;

/// Upper bound on the up-front allocation trusted from a peer's length
/// hint; the vector still grows to the real length if it is larger.
const MAX_PREALLOC: usize = 64 * 1024;

#[allow(clippy::ptr_arg)] // serde `with` passes `&Vec<u8>`.
pub(crate) fn serialize<S: Serializer>(bytes: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_bytes(bytes)
}

pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    d.deserialize_byte_buf(BytesVisitor)
}

struct BytesVisitor;

impl<'de> de::Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte string or an array of bytes")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
        Ok(v)
    }

    fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_PREALLOC));
        while let Some(b) = seq.next_element::<u8>()? {
            out.push(b);
        }
        Ok(out)
    }
}

/// The same treatment for 32-byte identifiers (content hashes, item ids,
/// device ids): a 34-byte byte string instead of an array that averages
/// ~60 bytes. Older builds decode it (`[u8; 32]` asks ciborium for a tuple,
/// which it reads through `deserialize_seq`), and arrays still decode here.
pub(crate) mod array32 {
    use serde::{de, Deserializer, Serializer};
    use std::fmt;

    pub(crate) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        d.deserialize_byte_buf(Array32Visitor)
    }

    struct Array32Visitor;

    impl<'de> de::Visitor<'de> for Array32Visitor {
        type Value = [u8; 32];

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("32 bytes, as a byte string or an array")
        }

        fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<[u8; 32], E> {
            <[u8; 32]>::try_from(v).map_err(|_| E::invalid_length(v.len(), &self))
        }

        fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<[u8; 32], E> {
            self.visit_bytes(&v)
        }

        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 32], A::Error> {
            let mut out = [0u8; 32];
            for (i, slot) in out.iter_mut().enumerate() {
                *slot = seq
                    .next_element::<u8>()?
                    .ok_or_else(|| de::Error::invalid_length(i, &self))?;
            }
            if seq.next_element::<u8>()?.is_some() {
                return Err(de::Error::invalid_length(33, &self));
            }
            Ok(out)
        }
    }
}
