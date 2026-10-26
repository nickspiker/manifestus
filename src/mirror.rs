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
use alloc::vec::Vec;
use crate::block::{Block, BlockDev, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::events::{EventSink, NullSink, StorageEvent};

/// Below this many blocks a batch writes sequentially — spawning threads to mirror a handful of 4KB blocks costs more than it saves. Bulk writes (furrow shards, large flushes) clear it easily; a prototype knob to tune against benchmarks.
#[cfg(feature = "std")]
const PAR_BATCH_THRESHOLD: usize = 4;

/// Write + verify every block of a batch on one device, with a device-local scratch (so concurrent device threads never share the read-back buffer).
/// ONE flush for the whole batch, not one per block (field 2026-08-25: per-block F_FULLFSYNC made a one-note put cost 12-20 drive-cache flushes — a flat, size-independent 0.3-1.4s; ferros boots faster). The crash contract needs ORDERING (everything a spine entry references on media before the spine lands), which the caller's final spine write_one still provides; the media read-back property (F_NOCACHE) is preserved because verification happens AFTER the single flush. A verify miss retries write+flush+verify once for just the failed block — write_one's exact discipline, paid only on damage.
/// Consecutive positions go as one run each way (BlockDev::write_run / read_run): a commit's appends are runs, and one I/O per 4KB block was a device round trip each.
#[cfg(feature = "std")]
fn write_each<D: BlockDev>(dev: &mut D, blocks: &[(u64, &Block)]) -> Result<()> {
    let mut scratch = ZERO_BLOCK;
    let runs = runs_of(blocks);
    for r in &runs {
        let bufs: alloc::vec::Vec<&Block> = blocks[r.clone()].iter().map(|&(_, b)| b).collect();
        dev.write_run(blocks[r.start].0, &bufs)?;
    }
    dev.flush()?;
    let mut back: alloc::vec::Vec<Block> = alloc::vec::Vec::new();
    for r in &runs {
        back.clear();
        back.resize(r.len(), ZERO_BLOCK);
        dev.read_run(blocks[r.start].0, &mut back)?;
        for (i, got) in back.iter().enumerate() {
            let (lba, buf) = blocks[r.start + i];
            if got != buf {
                write_one(dev, lba, buf, &mut scratch)?;
            }
        }
    }
    Ok(())
}

/// The batch cut where positions stop being consecutive: index ranges of runs.
#[cfg(feature = "std")]
fn runs_of(blocks: &[(u64, &Block)]) -> alloc::vec::Vec<core::ops::Range<usize>> {
    let mut out = alloc::vec::Vec::new();
    let mut start = 0;
    for i in 1..=blocks.len() {
        if i == blocks.len() || blocks[i].0 != blocks[i - 1].0 + 1 {
            out.push(start..i);
            start = i;
        }
    }
    out
}

pub struct Mirror<A: BlockDev, B: BlockDev> {
    a: Option<A>,
    b: Option<B>,
    degraded: bool,
    scratch: Block,
    /// Outbound event sink. Defaults to [`NullSink`]; the embedder attaches its own via [`Mirror::with_events`] (Photon → log.vsf, kernel → Ledger::Vault). Off the hot path — emitted only when a mirror drops to degraded, never per block.
    events: Box<dyn EventSink>,
    /// Appends staged and not yet written ([`Mirror::stage`]), in order. Reads see them first; every other write, a flush and a grow write them out before themselves, as one verified batch — so a spine entry still lands only after everything it can reference is verified on media.
    /// Kept as batches, each allocated once at its size and never grown: one vector of every staged block reallocated as appends arrived, and a large value's furrows plus the one leaf after them briefly held the furrows twice (2026-10-26: a 2.78 MB put peaked at 5.7x the value). No batch is empty.
    pending: Vec<Vec<(u64, Block)>>,
    /// Blocks the index walk read ([`Mirror::read_cached`]): position, last use, contents; sorted by position. Any write to a position drops it, so a hit is exactly what the device holds. The walk re-read the same nodes from the media on every get and put (2026-10-25: thirty-odd single-block reads a put).
    cache: Vec<(u64, u64, Box<Block>)>,
    uses: u64,
}

/// Blocks the index cache holds: 4 MB.
const CACHE_BLOCKS: usize = 1 << 10;

impl<A: BlockDev, B: BlockDev> Mirror<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self {
            a: Some(a),
            b: Some(b),
            degraded: false,
            scratch: ZERO_BLOCK,
            events: Box::new(NullSink),
            pending: Vec::new(),
            cache: Vec::new(),
            uses: 0,
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
            pending: Vec::new(),
            cache: Vec::new(),
            uses: 0,
        })
    }

    /// Stage appended blocks (the tract's appends, which no committed generation references): written, flushed and verified together by the next [`Self::drain`], which every other write, flush and grow runs first. A commit's furrows, leaves and index nodes thus go out as one batch per device — one flush each, contiguous runs as one I/O — instead of a write-flush-verify round per append (2026-10-25: about six sequential drive flushes per put, 35-90 ms on a desktop SSD).
    pub fn stage(&mut self, blocks: &[(u64, &Block)]) {
        if blocks.is_empty() {
            return;
        }
        let mut batch = Vec::with_capacity(blocks.len());
        for &(lba, b) in blocks {
            self.forget(lba);
            batch.push((lba, *b));
        }
        self.pending.push(batch);
    }

    /// Room for `n` blocks in a batch of their own, for the [`Self::stage_one`] calls that follow (a caller that makes its blocks one at a time, and need not hold them all first).
    pub fn reserve_staged(&mut self, n: usize) {
        if n > 0 {
            self.pending.push(Vec::with_capacity(n));
        }
    }

    /// Stage one block, into the last batch while it has room, else into a batch of its own.
    pub fn stage_one(&mut self, lba: u64, b: &Block) {
        self.forget(lba);
        match self.pending.last_mut() {
            Some(batch) if batch.len() < batch.capacity() => batch.push((lba, *b)),
            _ => {
                let mut batch = Vec::with_capacity(1);
                batch.push((lba, *b));
                self.pending.push(batch);
            }
        }
    }

    /// A position about to be written leaves the cache.
    fn forget(&mut self, lba: u64) {
        if let Ok(i) = self.cache.binary_search_by_key(&lba, |e| e.0) {
            self.cache.remove(i);
        }
    }

    /// [`Self::read`] for the index walk, kept in a small cache of recently read blocks (the least recently used goes when it is full). For the walk's blocks only: furrows, reap windows and verification read the media.
    pub fn read_cached(&mut self, lba: u64, buf: &mut Block) -> Result<()> {
        if let Some((_, b)) = self.pending.iter().rev().flat_map(|batch| batch.iter().rev()).find(|(l, _)| *l == lba) {
            buf.copy_from_slice(b);
            return Ok(());
        }
        self.uses += 1;
        match self.cache.binary_search_by_key(&lba, |e| e.0) {
            Ok(i) => {
                self.cache[i].1 = self.uses;
                buf.copy_from_slice(&self.cache[i].2[..]);
                Ok(())
            }
            Err(_) => {
                self.read(lba, buf)?;
                if self.cache.len() >= CACHE_BLOCKS {
                    let oldest = (0..self.cache.len()).min_by_key(|&i| self.cache[i].1).unwrap();
                    self.cache.remove(oldest);
                }
                let at = self.cache.binary_search_by_key(&lba, |e| e.0).unwrap_err();
                self.cache.insert(at, (lba, self.uses, Box::new(*buf)));
                Ok(())
            }
        }
    }

    /// Write out everything staged: one verified batch on each device (see [`Self::write_verified_batch`]). A position staged twice keeps its last block.
    pub fn drain(&mut self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let pending = core::mem::take(&mut self.pending);
        // Last write wins, then position order so runs coalesce: references to the staged blocks in staging order, a stable sort keeps a position's stagings in order, and the dedup keeps the last of each. The blocks themselves are not copied (a deduplicated copy was a second copy of a large value, 2026-10-26). `dedup_by` hands (later, earlier): the later reference takes the earlier one's place.
        let mut refs: Vec<(u64, &Block)> = pending.iter().flatten().map(|(l, b)| (*l, b)).collect();
        refs.sort_by_key(|&(lba, _)| lba);
        refs.dedup_by(|later, earlier| {
            if later.0 == earlier.0 {
                *earlier = *later;
                true
            } else {
                false
            }
        });
        self.write_verified_batch_now(&refs)
    }

    /// Write `buf` at `lba` on every present device, verifying each by read-back before touching the next. See module docs for the failure matrix. Staged appends are written out first.
    pub fn write_verified(&mut self, lba: u64, buf: &Block) -> Result<()> {
        self.drain()?;
        self.forget(lba);
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
        self.drain()?;
        self.write_verified_batch_now(blocks)
    }

    fn write_verified_batch_now(&mut self, blocks: &[(u64, &Block)]) -> Result<()> {
        for &(lba, _) in blocks {
            self.forget(lba);
        }
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
        self.drain()?;
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
        // A staged append reads as staged (the last staging of the position).
        if let Some((_, b)) = self.pending.iter().rev().flat_map(|batch| batch.iter().rev()).find(|(l, _)| *l == lba) {
            buf.copy_from_slice(b);
            return Ok(());
        }
        if let Some(a) = self.a.as_mut() {
            return a.read(lba, buf);
        }
        if let Some(b) = self.b.as_mut() {
            return b.read(lba, buf);
        }
        Err(Error::Corrupt("mirror has no devices".into()))
    }

    /// Consecutive blocks from `lba` from the first healthy device as one I/O (a value's furrows are a run); a run touching a staged append reads block by block, so the staging is seen.
    pub fn read_run(&mut self, lba: u64, out: &mut [Block]) -> Result<()> {
        let end = lba + out.len() as u64;
        if self.pending.iter().flatten().any(|(l, _)| (lba..end).contains(l)) {
            for (i, b) in out.iter_mut().enumerate() {
                self.read(lba + i as u64, b)?;
            }
            return Ok(());
        }
        if let Some(a) = self.a.as_mut() {
            return a.read_run(lba, out);
        }
        if let Some(b) = self.b.as_mut() {
            return b.read_run(lba, out);
        }
        Err(Error::Corrupt("mirror has no devices".into()))
    }

    /// Scattered blocks from the first healthy device, with reads in flight together ([`BlockDev::read_many`]); with appends staged, block by block so they are seen.
    pub fn read_many(&mut self, lbas: &[u64], out: &mut [Block]) -> Result<()> {
        if !self.pending.is_empty() {
            for (&lba, b) in lbas.iter().zip(out.iter_mut()) {
                self.read(lba, b)?;
            }
            return Ok(());
        }
        if let Some(a) = self.a.as_mut() {
            return a.read_many(lbas, out);
        }
        if let Some(b) = self.b.as_mut() {
            return b.read_many(lbas, out);
        }
        Err(Error::Corrupt("mirror has no devices".into()))
    }

    pub fn flush(&mut self) -> Result<()> {
        self.drain()?;
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
        debug_assert!(self.pending.is_empty(), "raw device access with appends staged");
        // Raw access may write: nothing cached survives it.
        self.cache.clear();
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
