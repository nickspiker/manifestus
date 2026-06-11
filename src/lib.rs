//! custodes Layer 0 (LEGACY — superseded by CUSTODES.md architecture) — append-only keyed store with self-validating records and crash-safe recovery.
//!
//! This crate ships only the storage primitive ([`Store`]). Higher layers (multi-index manager, query engine, transactions) live in this same crate but are gated behind features and not implemented yet — they come online when a real DB consumer asks for them.
//!
//! # Properties
//!
//! - **Append-only writes**: no in-place mutation, ever. Updates supersede; deletes tombstone.
//! - **Per-record HMAC**: every record self-validates under the caller's `anchor_key`. Torn writes and tampering both surface as decode failures at the affected record.
//! - **Silent recovery**: `open_or_create` scans front-to-back and truncates at the first invalid record. No `Recovered` variant exposed; callers see a consistent store. Atomicity all the way down.
//! - **Sub-100 MB target**: the in-memory pointer table is rebuilt on every open by scanning the file. Fine for vault-scale data; if custodes ever grows past that scale we'll persist the index.
//! - **No encryption in this layer**: bodies are opaque bytes. Encrypt at the caller level if you want it (e.g. photon-vault layers per-entry AEAD on top).

pub mod dual;
pub mod error;
pub mod record;
pub mod store;

pub use dual::DualStore;
pub use error::{Error, Result};
pub use record::{EntryKey, FLAG_EXPIRES, FLAG_PINNED, FLAG_TOMBSTONE};
pub use store::{EntryMeta, Store};
