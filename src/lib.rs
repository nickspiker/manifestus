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
pub use vault::{verified_replicate, LiveSet, Replicated, Vault};
pub use hamt::{lone_capacity, max_runs, Delta, Hamt};
pub use tract::{sealed_hp, Liveness, Reloc, Tract};
pub use ring::{any_sealed_block, append_root, block_is_sealed, classify, read_root, zero_ring, zero_ring_at, Classified, Ring, RootEntry, SpineEntry, FENCE_K, HOST_RING_LOG2, ROOT_SLOTS};
pub use error::{Error, Result};
