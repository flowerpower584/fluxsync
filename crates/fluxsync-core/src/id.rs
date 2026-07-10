//! Mesh identity primitives: `DeviceId` and `EventId`.
//!
//! These are the foundation for true multi-device sync (FluxMesh). They are
//! deliberately minimal and live in the pure core so the FSM/coordinator can
//! be exercised without any I/O.
//!
//! `EventId` is the one piece of an "event layer" we actually need: a content
//! hash alone cannot prevent a clipboard item from looping around a mesh
//! (A→B→C→A) or being re-applied after the 50-item content ring evicts it.
//! Tagging every item with `{origin device, per-origin seq}` lets each node
//! suppress an item it has already applied/forwarded — independently of the
//! content-hash echo guard, which keeps doing its own job (OS clipboard
//! read-back suppression).

use serde::{Deserialize, Serialize};

/// Stable identity of a device in the mesh.
///
/// These are the same 32 bytes already used as `peer_id` on the wire and in
/// `State` — the BLAKE3-derived id of a device's Noise static public key. A
/// newtype keeps "device identity" distinct from a raw `[u8; 32]` (which is
/// also a content hash, a public key, …) at the type level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceId([u8; 32]);

impl DeviceId {
    /// The all-zero sentinel. Used before a peer's real id is known (matches
    /// the `[0u8; 32]` placeholder the daemon already uses for an unset peer).
    pub const ZERO: DeviceId = DeviceId([0u8; 32]);

    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    #[must_use]
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    #[must_use]
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl From<[u8; 32]> for DeviceId {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

/// Mesh identity of a clipboard event, distinct from its content hash.
///
/// `origin` is the device that first introduced the item; `seq` is that
/// device's strictly-increasing per-origin counter. Crucially, two nodes
/// forwarding the same item quote the *same* `EventId` — that shared identity
/// is what lets a node recognise "I have already seen this item" no matter
/// which path it arrives by. `seq` is monotonic only at the origin; a node
/// may legitimately receive a *lower* `seq` from the same origin later (a
/// delayed item on a different path), so anti-loop must be membership-based,
/// never a per-origin high-water mark.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EventId {
    pub origin: DeviceId,
    pub seq: u64,
}

impl EventId {
    #[must_use]
    pub const fn new(origin: DeviceId, seq: u64) -> Self {
        Self { origin, seq }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_zero() {
        assert!(DeviceId::ZERO.is_zero());
        assert!(DeviceId::from_bytes([0; 32]).is_zero());
        assert!(!DeviceId::from_bytes([1; 32]).is_zero());
    }

    #[test]
    fn round_trips_bytes() {
        let b = [7u8; 32];
        let d = DeviceId::from(b);
        assert_eq!(d.as_bytes(), &b);
        assert_eq!(d.into_bytes(), b);
    }

    #[test]
    fn event_id_orders_by_origin_then_seq() {
        let a = EventId::new(DeviceId::from([1; 32]), 5);
        let b = EventId::new(DeviceId::from([1; 32]), 6);
        let c = EventId::new(DeviceId::from([2; 32]), 0);
        assert!(a < b); // same origin, higher seq
        assert!(b < c); // higher origin wins
    }

    #[test]
    fn event_id_equality_is_origin_and_seq() {
        let a = EventId::new(DeviceId::from([9; 32]), 3);
        let b = EventId::new(DeviceId::from([9; 32]), 3);
        let c = EventId::new(DeviceId::from([9; 32]), 4);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn serde_round_trip() {
        let e = EventId::new(DeviceId::from([0xAB; 32]), 42);
        let j = serde_json::to_string(&e).unwrap();
        let back: EventId = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }
}
