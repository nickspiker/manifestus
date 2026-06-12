//! custodes — the ferros storage engine. Every block guards itself; the guards verify each other.
//!
//! A crash-proof keyed object store over mirrored 4KB block devices: spine ring (generation-numbered commit objects, binary-searched) + tract (plow-managed log ring) + COW HAMT (the index, living in the tract it indexes). Power loss at any byte boundary is normal operation; the committed generation defines exactly what exists.
//!
//! Layering: [`Vault`] composes [`ring::Ring`] + [`tract::Tract`] + [`hamt::Hamt`] over a [`Mirror`] of [`BlockDev`]s. Host backs devices with [`FileDev`] (O_DIRECT discipline); the ferros kernel backs them with UFS/SD HAL. Design contract: the ferros specs (RING.md / VAULT.md / HAMT.md) + CUSTODES.md.
//!
//! The `record`/`store`/`dual` modules are the LEGACY Layer-0 engine (append-log + scan-rebuild) that photon currently rides; they are superseded by the architecture above and will be removed when photon's FlatStorage reskins onto [`Vault`].

pub mod block;
pub mod dual;
pub mod error;
pub mod hamt;
#[cfg(unix)]
pub mod host;
pub mod mirror;
pub mod record;
pub mod ring;
pub mod store;
pub mod tract;
pub mod vault;

pub use block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
pub use dual::DualStore;
#[cfg(unix)]
pub use host::FileDev;
pub use mirror::Mirror;
pub use vault::{verified_replicate, LiveSet, Replicated, Vault};
pub use hamt::{lone_capacity, Delta, Hamt};
pub use tract::{sealed_hp, Advance, Liveness, Reloc, Tract};
pub use ring::{any_sealed_block, block_is_sealed, classify, zero_ring, Classified, Ring, SpineEntry, FENCE_K, HOST_RING_LOG2};
pub use error::{Error, Result};
pub use record::{EntryKey, FLAG_EXPIRES, FLAG_PINNED, FLAG_TOMBSTONE};
pub use store::{EntryMeta, Store};
