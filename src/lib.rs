//! manifestus — the ferros storage engine. Every block guards itself; the guards verify each other.
//!
//! A crash-proof keyed object store over mirrored 4KB block devices: spine ring (generation-numbered commit objects, binary-searched) + tract (plow-managed log ring) + COW HAMT (the index, living in the tract it indexes). Power loss at any byte boundary is normal operation; the committed generation defines exactly what exists.
//!
//! Layering: [`Vault`] composes [`ring::Ring`] + [`tract::Tract`] + [`hamt::Hamt`] over a [`Mirror`] of [`BlockDev`]s. Host backs devices with [`FileDev`] (O_DIRECT discipline); the ferros kernel backs them with UFS/SD HAL. Design contract: the ferros specs (RING.md / VAULT.md / HAMT.md) + the host-profile resolutions in the README.
//!
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod block;
pub mod error;
pub mod events;
pub mod hamt;
#[cfg(all(feature = "std", any(unix, windows)))]
pub mod host;
pub mod inspect;
pub mod mirror;
pub mod ring;
pub mod tract;
pub mod vault;

pub use block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
pub use events::{EventSink, NullSink, StorageEvent};
#[cfg(all(feature = "std", any(unix, windows)))]
pub use host::FileDev;
pub use inspect::{inspect, InspectOptions, InspectReport};
pub use mirror::Mirror;
pub use vault::{verified_replicate, LiveSet, RepairReport, Replicated, Vault};
pub use hamt::{lone_capacity, max_runs, DanglingPointer, Delta, Hamt, StalePointer};
pub use tract::{sealed_hp, Liveness, NoLive, Reloc, Tract};
/// What "delete" physically does to a value's blocks — a REQUIRED open parameter so every embedder (and every future port) answers the question consciously instead of inheriting an assumption (Nick's verdict, 2026-09-08).
///
/// The physics that forces the choice: `ZeroIsErase` is a TRUE secure erase only on hardware where this engine commands the raw NAND and erased-state == zero (the ferros-on-owned-flash design in VAULT.md). Everywhere else — a host file on CoW filesystems (BTRFS snapshots keep every generation), ANY device with a vendor FTL between us and the flash (every Pixel/phone/SSD: the controller remaps, the old page survives until its GC feels like it) — the zero-write erases NOTHING and frees NOTHING (the stale-index + plow-reap is what reclaims the slot); it just burns a full-value write of wear. On those targets delete is SPACE RECLAMATION ONLY, and the honest security boundary is the vault key gated at boot: snapshots and stray NAND pages hold ciphertext.
///
/// So: `UnlinkOnly` for hosts and vendor-FTL hardware (all current targets, including Pixel-ferros); `ZeroIsErase` only when the port owns the NAND stack end to end. If you are porting to new hardware and unsure — you are UnlinkOnly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeletePolicy {
    /// Delete = COW-unlink + reap (space reclaim). Blocks are left intact; a crash mid-delete resurrects the value (re-deletable) instead of leaving a zeroed leaf.
    UnlinkOnly,
    /// Delete = zero every block on both mirrors, then unlink. Correct ONLY where zero IS the erased state of flash this engine commands directly.
    ZeroIsErase,
}

pub use ring::{any_sealed_block, append_root, block_is_sealed, classify, read_root, zero_ring, zero_ring_at, Classified, Ring, RootEntry, SpineEntry, FENCE_K, HOST_RING_LOG2, ROOT_SLOTS};
pub use error::{Error, Result};
