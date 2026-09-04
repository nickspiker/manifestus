//! Write-verify-then-mirror, per RING.md verbatim.
//!
//! Never write to the second device until the first is verified. A block is "written" only after it has been read back and compared — an unverified byte is not a written byte. A generation is committed when at least one device holds a verified copy.
//!
//! Failure semantics:
//! - Primary write/verify fails → retry once → hard error, secondary untouched (RING.md: "do not proceed").
//! - Secondary fails → dropped for the session, `degraded` flips, the op succeeds — the primary has it.
//!
//! The comparison is byte equality against the just-written buffer — strictly stronger than the kernel's BLAKE3-against-expected-hash check (we hold both byte strings; the kernel holds only the hash).
//!
//! Hybrid write path: the bulk *data* blocks of a commit go through [`Mirror::write_verified_batch`], which writes both rings concurrently (each ring is its own disk — the ferros two-device case, in software for now) and verifies both, reconciled with the same primary-authoritative rule. The single-block [`Mirror::write_verified`] stays sequential and is what the authoritative spine commit uses, so "one device defines the committed generation" is unchanged.

use alloc::boxed::Box;
use crate::block::{Block, BlockDev, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::events::{EventSink, NullSink, StorageEvent};

/// Below this many blocks a batch writes sequentially — spawning threads to mirror a handful of 4KB blocks costs more than it saves. Bulk writes (furrow shards, large flushes) clear it easily; a prototype knob to tune against benchmarks.
#[cfg(feature = "std")]
const PAR_BATCH_THRESHOLD: usize = 4;

/// Write + verify every block of a batch on one device, with a device-local scratch (so concurrent device threads never share the read-back buffer).
/// ONE flush for the whole batch, not one per block (field 2026-08-25: per-block F_FULLFSYNC made a one-note put cost 12-20 drive-cache flushes — a flat, size-independent 0.3-1.4s; ferros boots faster). The crash contract needs ORDERING (everything a spine entry references on media before the spine lands), which the caller's final spine write_one still provides; the media read-back property (F_NOCACHE) is preserved because verification happens AFTER the single flush. A verify miss retries write+flush+verify once for just the failed block — write_one's exact discipline, paid only on damage.
#[cfg(feature = "std")]
fn write_each<D: BlockDev>(dev: &mut D, blocks: &[(u64, &Block)]) -> Result<()> {
    let mut scratch = ZERO_BLOCK;
    for &(lba, buf) in blocks {
        dev.write(lba, buf)?;
    }
    dev.flush()?;
    for &(lba, buf) in blocks {
        dev.read(lba, &mut scratch)?;
        if &scratch != buf {
            write_one(dev, lba, buf, &mut scratch)?;
        }
    }
    Ok(())
}

pub struct Mirror<A: BlockDev, B: BlockDev> {
    a: Option<A>,
    b: Option<B>,
    degraded: bool,
    scratch: Block,
    /// Outbound event sink. Defaults to [`NullSink`]; the embedder attaches its own via [`Mirror::with_events`] (Photon → log.vsf, kernel → Ledger::Vault). Off the hot path — emitted only when a mirror drops to degraded, never per block.
    events: Box<dyn EventSink>,
}

impl<A: BlockDev, B: BlockDev> Mirror<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self {
            a: Some(a),
            b: Some(b),
            degraded: false,
            scratch: ZERO_BLOCK,
            events: Box::new(NullSink),
        }
    }

    /// Attach an event sink. Builder-style so no construction call site changes — the default is silent.
    pub fn with_events(mut self, sink: Box<dyn EventSink>) -> Self {
        self.events = sink;
        self
    }

    /// Assemble from whatever survived open — a missing mirror starts the session degraded. Errors if neither device is present.
    pub fn from_parts(a: Option<A>, b: Option<B>) -> Result<Self> {
        if a.is_none() && b.is_none() {
            return Err(Error::Corrupt("mirror requires at least one device".into()));
        }
        let degraded = a.is_none() || b.is_none();
        Ok(Self {
            a,
            b,
            degraded,
            scratch: ZERO_BLOCK,
            events: Box::new(NullSink),
        })
    }

    /// Write `buf` at `lba` on every present device, verifying each by read-back before touching the next. See module docs for the failure matrix.
    pub fn write_verified(&mut self, lba: u64, buf: &Block) -> Result<()> {
        match (self.a.as_mut(), self.b.as_mut()) {
            (Some(a), b) => {
                // Primary must land or the op fails — secondary deliberately untouched on primary failure.
                write_one(a, lba, buf, &mut self.scratch)?;
                if let Some(b) = b {
                    if write_one(b, lba, buf, &mut self.scratch).is_err() {
                        self.b = None;
                        self.degraded = true;
                        self.events.emit(StorageEvent::MirrorDegraded);
                    }
                }
                Ok(())
            }
            (None, Some(b)) => write_one(b, lba, buf, &mut self.scratch),
            (None, None) => Err(Error::Corrupt("mirror has no devices".into())),
        }
    }

    /// Concurrent bulk write: fan the whole batch out to both rings on separate threads (each writes + read-back-verifies its own device with a private scratch), then reconcile. The primary stays authoritative — its failure fails the op; a secondary failure drops the ring and flips `degraded`. This is the hybrid for the data-block phase of a commit; the authoritative spine commit still uses the sequential [`write_verified`]. A single device, or a batch below [`PAR_BATCH_THRESHOLD`], falls back to sequential. Per-block discipline is unchanged: write → flush → read back → compare → retry once.
    pub fn write_verified_batch(&mut self, blocks: &[(u64, &Block)]) -> Result<()> {
        // The parallel fan-out needs std threads; the kernel profile always takes the sequential path below (per-block discipline is identical, wall-clock is the only difference).
        #[cfg(feature = "std")]
        {
            let both = self.a.is_some() && self.b.is_some();
            if both && blocks.len() >= PAR_BATCH_THRESHOLD {
                let a = self.a.as_mut().unwrap();
                let b = self.b.as_mut().unwrap();
                let (a_res, b_ok) = std::thread::scope(|s| {
                    let bh = s.spawn(move || write_each(b, blocks));
                    let a_res = write_each(a, blocks);
                    (a_res, matches!(bh.join(), Ok(Ok(()))))
                });
                // Primary authoritative: the secondary's writes landed in uncommitted COW slack, so dropping the ring on failure loses nothing committed.
                a_res?;
                if !b_ok {
                    self.b = None;
                    self.degraded = true;
                    self.events.emit(StorageEvent::MirrorDegraded);
                }
                return Ok(());
            }
        }
        // Sequential (single device / small batch): the same one-flush-per-device discipline — the smallest batches are the commonest (a one-note put), exactly where per-block flushing hurt most. The kernel profile keeps the per-block loop (no std, and its flush is not a drive-cache round-trip).
        #[cfg(feature = "std")]
        {
            match (self.a.as_mut(), self.b.as_mut()) {
                (Some(a), b) => {
                    write_each(a, blocks)?;
                    if let Some(b) = b {
                        if write_each(b, blocks).is_err() {
                            self.b = None;
                            self.degraded = true;
                            self.events.emit(StorageEvent::MirrorDegraded);
                        }
                    }
                    return Ok(());
                }
                (None, Some(b)) => return write_each(b, blocks),
                (None, None) => return Err(Error::Corrupt("mirror has no devices".into())),
            }
        }
        #[cfg(not(feature = "std"))]
        {
            for &(lba, buf) in blocks {
                self.write_verified(lba, buf)?;
            }
            Ok(())
        }
    }

    /// Extend every present device to `new_blocks`, same failure matrix as writes: primary must grow or the op fails; a secondary that refuses is dropped for the session (`degraded` flips) — the primary carries the new geometry alone.
    pub fn grow(&mut self, new_blocks: u64) -> Result<()> {
        match (self.a.as_mut(), self.b.as_mut()) {
            (Some(a), b) => {
                a.grow(new_blocks)?;
                if let Some(b) = b {
                    if b.grow(new_blocks).is_err() {
                        self.b = None;
                        self.degraded = true;
                        self.events.emit(StorageEvent::MirrorDegraded);
                    }
                }
                Ok(())
            }
            (None, Some(b)) => b.grow(new_blocks),
            (None, None) => Err(Error::Corrupt("mirror has no devices".into())),
        }
    }

    /// Read from the first healthy device. Content validation (hp / Empty / Corrupt classification) is the layer above — the mirror only routes.
    ///
    /// TODO(read-repair): "healthy" here means *present*, not *this block verified* — a Corrupt block on the primary is returned even when the sibling holds a clean copy. The intended design is relocation-not-repair (see README "Bad-block relocation"), and it SPLITS BY STORAGE PROFILE:
    ///   - Host profile (managed flash): the FTL below already remaps bad blocks, so stay stateless —
    ///     relocate forward + rewrite the ref (tract) / burn a generation (ring), re-try the sector next
    ///     pass, no tombstone map of our own.
    ///   - Kernel profile (raw NAND we manage): a bad block stays bad, so read/check a bad-block tombstone
    ///     (distinct from the deleted-zero) on both paths before write/verify; a map only if that check
    ///     proves too costly.
    /// Both rings lock-step relocate to stay byte-identical; the ref re-point (tract) / new spine entry
    /// (ring) is the commit, tombstones advisory. Needed before the calls/attachments layer (one bad block in a large recording must self-heal, not surface as Corrupt).
    pub fn read(&mut self, lba: u64, buf: &mut Block) -> Result<()> {
        if let Some(a) = self.a.as_mut() {
            return a.read(lba, buf);
        }
        if let Some(b) = self.b.as_mut() {
            return b.read(lba, buf);
        }
        Err(Error::Corrupt("mirror has no devices".into()))
    }

    pub fn flush(&mut self) -> Result<()> {
        if let Some(a) = self.a.as_mut() {
            a.flush()?;
        }
        if let Some(b) = self.b.as_mut() {
            b.flush()?;
        }
        Ok(())
    }

    /// Smallest capacity across present devices — the addressable envelope.
    pub fn block_count(&self) -> u64 {
        let a = self.a.as_ref().map(|d| d.block_count());
        let b = self.b.as_ref().map(|d| d.block_count());
        match (a, b) {
            (Some(x), Some(y)) => x.min(y),
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => 0,
        }
    }

    /// Sticky for the session: a device was missing at open, died mid-session, or failed verification.
    pub fn degraded(&self) -> bool {
        self.degraded
    }

    /// Emit an engine event thru the mirror's sink — for layers (tract, ring) that route their I/O thru the mirror and have no sink of their own.
    pub fn emit(&mut self, event: StorageEvent) {
        self.events.emit(event);
    }

    pub fn has_a(&self) -> bool {
        self.a.is_some()
    }

    pub fn has_b(&self) -> bool {
        self.b.is_some()
    }

    /// Direct access for replication / per-device search (verified_replicate reads both sides independently).
    pub fn devices(&mut self) -> (Option<&mut A>, Option<&mut B>) {
        (self.a.as_mut(), self.b.as_mut())
    }
}

/// write → flush → read back → compare; one retry; then hard error. The flush before read-back makes the verification meaningful on O_DIRECT paths and bounds data loss on buffered fallbacks.
fn write_one<D: BlockDev>(dev: &mut D, lba: u64, buf: &Block, scratch: &mut Block) -> Result<()> {
    for attempt in 0..2 {
        dev.write(lba, buf)?;
        dev.flush()?;
        dev.read(lba, scratch)?;
        if scratch == buf {
            return Ok(());
        }
        if attempt == 0 {
            continue;
        }
    }
    Err(Error::Verify(lba))
}
