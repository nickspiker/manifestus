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
    crate::block::write_pairs(dev, blocks)?;
    dev.flush()?;
    for i in crate::block::mismatches(dev, blocks)? {
        let (lba, buf) = blocks[i];
        write_one(dev, lba, buf, &mut scratch)?;
    }
    Ok(())
}

pub struct Mirror<A: BlockDev, B: BlockDev> {
    a: Option<A>,
    b: Option<B>,
    /// The second device on a thread of its own, once [`Mirror::follow`] moved it there: the primary's writes are acknowledged on the primary alone and copied behind it in order (see [`follow`]).
    #[cfg(feature = "std")]
    follower: Option<follow::Follower<B>>,
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
            #[cfg(feature = "std")]
            follower: None,
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
            #[cfg(feature = "std")]
            follower: None,
            degraded,
            scratch: ZERO_BLOCK,
            events: Box::new(NullSink),
        })
    }

    /// Write `buf` at `lba` on every present device, verifying each by read-back before touching the next. See module docs for the failure matrix.
    pub fn write_verified(&mut self, lba: u64, buf: &Block) -> Result<()> {
        #[cfg(feature = "std")]
        if self.following() {
            write_one(self.a.as_mut().unwrap(), lba, buf, &mut self.scratch)?;
            self.send(follow::Job::Ordered(lba, Box::new(*buf)));
            return Ok(());
        }
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
        if self.following() {
            write_each(self.a.as_mut().unwrap(), blocks)?;
            self.send(follow::Job::Data(blocks.iter().map(|&(lba, b)| (lba, *b)).collect()));
            return Ok(());
        }
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

    /// A commit's data run AND its spine entry, under ONE flush per device (the verified head, 2026-10-22): write the run, write the entry, flush, read every block back. The entry carries the run's hash, so a crash that lands the entry without all of its run is caught at open and the vault steps back one generation — which is what lets the flush between data and spine go.
    /// The primary is authoritative as everywhere: its failure fails the commit. A follower receives the run then the entry as an ordered write (it keeps its own data-then-spine flush, off the caller's path); a synchronous second device gets the same single-flush treatment after the primary.
    pub fn write_commit(&mut self, data: &[(u64, &Block)], spine: (u64, &Block)) -> Result<()> {
        #[cfg(feature = "std")]
        {
            if self.following() {
                commit_one(self.a.as_mut().unwrap(), data, spine)?;
                if !data.is_empty() {
                    self.send(follow::Job::Data(data.iter().map(|&(lba, b)| (lba, *b)).collect()));
                }
                self.send(follow::Job::Ordered(spine.0, Box::new(*spine.1)));
                return Ok(());
            }
            return match (self.a.as_mut(), self.b.as_mut()) {
                (Some(a), b) => {
                    commit_one(a, data, spine)?;
                    if let Some(b) = b {
                        if commit_one(b, data, spine).is_err() {
                            self.b = None;
                            self.degraded = true;
                            self.events.emit(StorageEvent::MirrorDegraded);
                        }
                    }
                    Ok(())
                }
                (None, Some(b)) => commit_one(b, data, spine),
                (None, None) => Err(Error::Corrupt("mirror has no devices".into())),
            };
        }
        #[cfg(not(feature = "std"))]
        {
            self.write_verified_batch(data)?;
            self.write_verified(spine.0, spine.1)
        }
    }

    /// Extend every present device to `new_blocks`, same failure matrix as writes: primary must grow or the op fails; a secondary that refuses is dropped for the session (`degraded` flips) — the primary carries the new geometry alone.
    pub fn grow(&mut self, new_blocks: u64) -> Result<()> {
        #[cfg(feature = "std")]
        if self.following() {
            self.a.as_mut().unwrap().grow(new_blocks)?;
            self.send(follow::Job::Grow(new_blocks));
            if let Some(f) = self.follower.as_mut() {
                f.blocks = f.blocks.max(new_blocks);
            }
            return Ok(());
        }
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

    /// Read consecutive blocks from the first healthy device, in one transfer where the device can.
    pub fn read_run(&mut self, lba: u64, out: &mut [Block]) -> Result<()> {
        if let Some(a) = self.a.as_mut() {
            return a.read_run(lba, out);
        }
        if let Some(b) = self.b.as_mut() {
            return b.read_run(lba, out);
        }
        Err(Error::Corrupt("mirror has no devices".into()))
    }

    pub fn flush(&mut self) -> Result<()> {
        if let Some(a) = self.a.as_mut() {
            a.flush()?;
        }
        #[cfg(feature = "std")]
        self.sync_follower();
        if let Some(b) = self.b.as_mut() {
            b.flush()?;
        }
        Ok(())
    }

    /// Smallest capacity across present devices — the addressable envelope.
    pub fn block_count(&self) -> u64 {
        let a = self.a.as_ref().map(|d| d.block_count());
        #[cfg(feature = "std")]
        let b = self.b.as_ref().map(|d| d.block_count()).or(self.follower.as_ref().map(|f| f.blocks));
        #[cfg(not(feature = "std"))]
        let b = self.b.as_ref().map(|d| d.block_count());
        match (a, b) {
            (Some(x), Some(y)) => x.min(y),
            (Some(x), None) => x,
            (None, Some(y)) => y,
            (None, None) => 0,
        }
    }

    /// Sticky for the session: a device was missing at open, died mid-session, or failed verification.
    pub fn degraded(&mut self) -> bool {
        #[cfg(feature = "std")]
        self.following();
        self.degraded
    }

    /// Emit an engine event thru the mirror's sink — for layers (tract, ring) that route their I/O thru the mirror and have no sink of their own.
    pub fn emit(&mut self, event: StorageEvent) {
        self.events.emit(event);
    }

    pub fn has_a(&self) -> bool {
        self.a.is_some()
    }

    pub fn has_b(&mut self) -> bool {
        #[cfg(feature = "std")]
        if self.following() {
            return true;
        }
        self.b.is_some()
    }

    /// Direct access for replication / per-device search (verified_replicate reads both sides independently). A following second device is on its thread and answers None.
    pub fn devices(&mut self) -> (Option<&mut A>, Option<&mut B>) {
        (self.a.as_mut(), self.b.as_mut())
    }
}

/// One device's share of [`Mirror::write_commit`]: run, entry, one flush, then read everything back; a block that reads back wrong gets the single-block rewrite discipline.
#[cfg(feature = "std")]
fn commit_one<D: BlockDev>(dev: &mut D, data: &[(u64, &Block)], spine: (u64, &Block)) -> Result<()> {
    crate::block::write_pairs(dev, data)?;
    dev.write(spine.0, spine.1)?;
    dev.flush()?;
    let mut scratch = ZERO_BLOCK;
    for i in crate::block::mismatches(dev, data)? {
        let (lba, buf) = data[i];
        write_one(dev, lba, buf, &mut scratch)?;
    }
    dev.read(spine.0, &mut scratch)?;
    if &scratch != spine.1 {
        write_one(dev, spine.0, spine.1, &mut scratch)?;
    }
    Ok(())
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

#[cfg(feature = "std")]
impl<A: BlockDev, B: BlockDev + 'static> Mirror<A, B> {
    /// Move the second device onto a thread of its own (Nick 2026-10-22, the lazy second copy). From here a write is acknowledged once the PRIMARY holds it, flushed and read back; the second device receives the same writes in the same order behind it, flushing its data before every ordered single-block write (a spine entry above all), so at every moment it holds a whole, older vault — never a mix.
    /// Losing the primary between a commit and its copy loses that commit; anything else (a kill, a crash) leaves the copy a few generations behind, which the next open's replicate copies across as a tail.
    /// A second device that fails a write or its read-back is dropped and the mirror turns degraded, as before. No-op without a second device or when already following.
    pub fn follow(&mut self) {
        if self.follower.is_some() {
            return;
        }
        if let Some(b) = self.b.take() {
            self.follower = Some(follow::Follower::spawn(b));
        }
    }
}

#[cfg(feature = "std")]
impl<A: BlockDev, B: BlockDev> Mirror<A, B> {
    /// Whether a follower is live — and the edge where a failed one is noticed: dropped, the mirror marked degraded, the event emitted once.
    fn following(&mut self) -> bool {
        let Some(f) = self.follower.as_ref() else { return false };
        if f.failed() {
            self.follower = None;
            self.degraded = true;
            self.events.emit(StorageEvent::MirrorDegraded);
            return false;
        }
        true
    }

    fn send(&mut self, job: follow::Job) {
        if let Some(f) = self.follower.as_mut() {
            f.send(job);
        }
    }

    /// Wait until the second device holds everything written so far, flushed and verified. Free without a follower.
    pub fn sync_follower(&mut self) {
        if let Some(f) = self.follower.as_mut() {
            f.sync();
        }
        self.following();
    }
}

#[cfg(feature = "std")]
impl<A: BlockDev, B: BlockDev> Drop for Mirror<A, B> {
    /// A clean close leaves both devices equal: the follower drains its queue before the mirror is gone.
    fn drop(&mut self) {
        if let Some(f) = self.follower.as_mut() {
            f.sync();
        }
    }
}

/// The second device's thread. Jobs arrive in the primary's write order; the thread writes them in that order, so the device it owns is always a valid vault at some generation.
#[cfg(feature = "std")]
pub(crate) mod follow {
    use super::{write_one, ZERO_BLOCK};
    use crate::block::{Block, BlockDev};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
    use std::sync::Arc;

    /// Jobs queued ahead of the copy before the primary waits for it: enough to absorb a burst of commits, few enough that a lagging copy holds back the writer instead of RAM.
    const QUEUE: usize = 256;

    pub(crate) enum Job {
        /// A commit's data run: written as it comes, flushed and verified before the next ordered write.
        Data(Vec<(u64, Block)>),
        /// A single block whose order matters (spine entries, ring and root zeroing, an erase): everything before it is flushed and verified first, then it is written, flushed and verified.
        Ordered(u64, Box<Block>),
        Grow(u64),
        /// Flush what is outstanding and answer.
        Sync(SyncSender<()>),
    }

    pub(crate) struct Follower<B> {
        tx: Option<SyncSender<Job>>,
        handle: Option<std::thread::JoinHandle<()>>,
        failed: Arc<AtomicBool>,
        /// The device's size as the primary asked for it — answered here while the device itself is on the thread.
        pub(crate) blocks: u64,
        _device: core::marker::PhantomData<B>,
    }

    impl<B: BlockDev> Follower<B> {
        pub(crate) fn spawn(dev: B) -> Self
        where
            B: 'static,
        {
            let blocks = dev.block_count();
            let (tx, rx) = sync_channel(QUEUE);
            let failed = Arc::new(AtomicBool::new(false));
            let flag = failed.clone();
            let handle = std::thread::Builder::new().name("manifestus-follower".into()).spawn(move || run(dev, rx, flag)).expect("follower thread");
            Self { tx: Some(tx), handle: Some(handle), failed, blocks, _device: core::marker::PhantomData }
        }

        pub(crate) fn failed(&self) -> bool {
            self.failed.load(Ordering::Acquire)
        }

        pub(crate) fn send(&mut self, job: Job) {
            if let Some(tx) = &self.tx {
                if tx.send(job).is_err() {
                    self.failed.store(true, Ordering::Release);
                }
            }
        }

        pub(crate) fn sync(&mut self) {
            let (ack, done) = sync_channel(1);
            self.send(Job::Sync(ack));
            let _ = done.recv();
        }
    }

    impl<B> Drop for Follower<B> {
        fn drop(&mut self) {
            self.tx = None;
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn run<B: BlockDev>(mut dev: B, rx: Receiver<Job>, failed: Arc<AtomicBool>) {
        // Data written since the last flush, kept to read back once that flush lands.
        let mut unflushed: Vec<(u64, Block)> = Vec::new();
        let mut scratch = ZERO_BLOCK;
        let mut ok = true;
        for job in rx {
            if !ok {
                // Dropped: keep draining so the writer never blocks on a dead queue; answer syncs.
                if let Job::Sync(ack) = job {
                    let _ = ack.send(());
                }
                continue;
            }
            let r = match job {
                Job::Data(blocks) => {
                    let pairs: Vec<(u64, &Block)> = blocks.iter().map(|(l, b)| (*l, b)).collect();
                    let r = crate::block::write_pairs(&mut dev, &pairs);
                    drop(pairs);
                    r.map(|_| unflushed.extend(blocks))
                }
                Job::Ordered(lba, block) => settle(&mut dev, &mut unflushed, &mut scratch).and_then(|_| write_one(&mut dev, lba, &block, &mut scratch)),
                Job::Grow(n) => dev.grow(n),
                Job::Sync(ack) => {
                    let r = settle(&mut dev, &mut unflushed, &mut scratch);
                    let _ = ack.send(());
                    r
                }
            };
            if r.is_err() {
                ok = false;
                failed.store(true, Ordering::Release);
            }
        }
        if ok && settle(&mut dev, &mut unflushed, &mut scratch).is_err() {
            failed.store(true, Ordering::Release);
        }
    }

    /// Flush the data written since the last flush and read every block of it back; a mismatch gets the one rewrite every verified write gets.
    fn settle<B: BlockDev>(dev: &mut B, unflushed: &mut Vec<(u64, Block)>, scratch: &mut Block) -> crate::error::Result<()> {
        if unflushed.is_empty() {
            return Ok(());
        }
        dev.flush()?;
        let pairs: Vec<(u64, &Block)> = unflushed.iter().map(|(l, b)| (*l, b)).collect();
        for i in crate::block::mismatches(dev, &pairs)? {
            let (lba, b) = pairs[i];
            write_one(dev, lba, b, scratch)?;
        }
        drop(pairs);
        unflushed.clear();
        Ok(())
    }
}
