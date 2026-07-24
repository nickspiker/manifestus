//! The engine's outbound event leg — the fourth side of its contract beside `read(lba)` / `write(lba)` / `flush()`.
//!
//! manifestus core carries no logger and no destination knowledge; it calls `emit` on an injected sink and the embedder decides where events land.
//! Photon (host) sinks to `log.vsf`; the ferros kernel sinks survivable events to `Ledger::Vault::Repair` / `Ledger::Vault::Reap` (see ferros LEDGER.md).
//! Engine-fatal conditions (cannot commit, both mirrors failing) are NOT events — they are `Err` returns, and the embedder routes them outside the vault (RAM diag ring, framebuffer, pstore), because the ledger is a tenant of the vault and the vault cannot record its own death.
//!
//! v0 skeleton: the trait and the event set exist; emit-site wiring through `Vault`/`Mirror` is the follow-up pass, so the event taxonomy can be reviewed before it fans out through signatures.

/// A survivable engine event — something the engine noticed, handled, and continued past.
/// Notify-always: the RATE of repairs is the flash-death early warning, so even silently-handled repairs must reach the sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageEvent {
    /// A write's read-back mismatched and the retry succeeded. (lba)
    VerifyRetried { lba: u64 },
    /// A block failed verification and its content was relocated forward. (from, to)
    BlockRelocated { from: u64, to: u64 },
    /// A secondary mirror failed and was dropped for the session; the vault is running unmirrored.
    MirrorDegraded,
    /// A reap window completed. (scanned, live, moved — block counts)
    ReapWindow { scanned: u64, live: u64, moved: u64 },
}

/// The injected sink. Implementations must be cheap and non-blocking from the engine's point of view — buffering and durability are the embedder's problem, not the engine's.
/// `Send` because embedders hold the storage (and the boxed sink inside it) across threads — kete's FlatStorage is cloned into worker threads thruout photon, and an un-Send sink poisons every one of those spawns.
pub trait EventSink: Send {
    fn emit(&mut self, event: StorageEvent);
}

/// Discards everything. The default when an embedder has no destination yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullSink;

impl EventSink for NullSink {
    fn emit(&mut self, _event: StorageEvent) {}
}
