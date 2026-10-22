//! The tract — two-cursor log ring. VAULT.md mechanics (plow + reap), host profile.
//!
//! Two cursors in one monotone domain: the PLOW (append head) and the REAP (cleaning head), with reap ≤ plow ≤ reap + len. Occupied space [reap, plow) is a mix of live and dead blocks; clean space [plow, reap + len) contains NO live blocks, by invariant. Appends therefore write blindly — no read, no classification, no relocation on the write path — and every multi-block value lands as one contiguous run (split at most once by ring wrap). Reclamation is the vault's windowed reap:
//! survivors of a window are re-appended at the plow (source and target can never overlap — the target is clean), their references repaired, and the reap advanced by one commit. See VAULT.md "The Reap".
//!
//! Cursors are MONOTONE totals since genesis — wrapped position is `cursor % len`, and the rollback fence is a pure integer compare (`plow < fence_limit`). Wrapped positions are lap-ambiguous; totals are not.
//!
//! Killswitch posture: appends land in space no committed generation references (the clean invariant, enforced by the fence: appends stay below min(reap_i + len_i) over the K-window). Reap copies are written BEFORE the commit that references them; originals remain sealed at their old positions, which stay unwritable until the retiring commit is K generations deep. Crash at any byte: the committed HAMT points at originals, which are intact. Orphans (copies whose commit never landed) sit in previously-clean space and are reaped on a later window.
//!
//! The tract interprets NOTHING about block contents beyond sealedness (RÅ + hp).
//! Liveness is the caller's knowledge (the HAMT), injected via [`Liveness`].

use alloc::vec::Vec;
use crate::block::{Block, BlockDev};
use crate::error::{Error, Result};
use crate::mirror::Mirror;
use crate::ring::MAGIC;
use vsf::decoding::parse::parse;
use vsf::types::VsfType;

/// Extract the sealing hp from a block if (and only if) the seal verifies. Schema-agnostic: spine entries, HAMT nodes, furrows, lone leaves all answer. One code path for the reap's liveness scan.
pub fn sealed_hp(block: &Block) -> Option<[u8; 32]> {
    if block[..4] != MAGIC {
        return None;
    }
    let mut ptr = 4usize;
    let Ok(VsfType::hp(stored)) = parse(block, &mut ptr) else {
        return None;
    };
    if block.get(ptr) != Some(&b'>') {
        return None;
    }
    if blake3::hash(&block[ptr + 1..]).as_bytes() != stored.as_slice() {
        return None;
    }
    stored.try_into().ok()
}

/// The caller's knowledge of what is referenced. The vault implements this over its (in-memory, batch-current) HAMT: live iff the index maps this hp to exactly this lba.
pub trait Liveness {
    fn is_live(&self, lba: u64, hp: &[u8; 32]) -> bool;
    /// Whether ANY committed pointer references this lba, hp-independent — the append lap guard's question. `is_live` answers "is this exact block current"; this answers "would writing here destroy something the index still points at".
    fn is_referenced(&self, lba: u64) -> bool;
}

/// The nothing-is-referenced oracle: genesis paths and tests, where no committed index exists to lap.
pub struct NoLive;

impl Liveness for NoLive {
    fn is_live(&self, _lba: u64, _hp: &[u8; 32]) -> bool {
        false
    }
    fn is_referenced(&self, _lba: u64) -> bool {
        false
    }
}

/// A live block that moved during a reap window: the caller must update its index (batched into the retiring spine commit).
#[derive(Debug, Clone, PartialEq)]
pub struct Reloc {
    pub hp: [u8; 32],
    pub from: u64,
    pub to: u64,
}

/// Appends held in RAM until the commit that references them (group commit, 2026-10-22): their positions are taken at append time — fence, lap guard and placement exactly as before — but the bytes reach the devices in one contiguous write per device at [`Tract::write_staged`], just before the spine entry. A put used to cost a flush pair per leaf, per furrow run and per index node; a commit now costs one data write and one spine write per device, whatever it holds.
/// Staged blocks are provisional like any uncommitted append: a crash loses them, and the committed head never referenced them. Reads of a staged position are served from here, so the batch sees its own work.
#[derive(Default)]
pub struct Staging {
    /// Off (the default) writes every append through at once — the behaviour bare tracts in tests and tools rely on. The vault turns it on.
    pub enabled: bool,
    /// Monotone plow position of the first staged block; the rest follow contiguously.
    start: u64,
    blocks: Vec<Block>,
}

/// Staged bytes past this are written out early (data only — no spine entry references them yet, so the early write is as safe as the late one). 16 MiB keeps a large batch's RAM bounded.
const STAGE_MAX_BLOCKS: usize = 1 << 12;

/// Two-cursor state for one tract. Pure state — the mirror is borrowed per operation so the spine ring (which owns the mirror's lower blocks) and the tract can interleave.
pub struct Tract {
    /// Device lba where the tract begins (= N on host; G#C0000 on ferros).
    pub base: u64,
    /// Tract length in blocks. Arbitrary — never assumed power of two.
    pub len: u64,
    /// Append head: monotone total blocks appended since genesis. Wrapped position = plow % len.
    pub plow: u64,
    /// Cleaning head: monotone total blocks retired since genesis. reap ≤ plow ≤ reap + len.
    pub reap: u64,
    /// Absolute append budget (monotone domain). Recomputed by the vault from the last k spine entries: min(reap_i + len_i). None = unfenced (genesis era, fewer than k commits).
    pub fence_limit: Option<u64>,
    /// Appends awaiting the commit's single write (see [`Staging`]).
    pub staging: Staging,
}

impl Staging {
    /// Staging on: the vault's form.
    pub fn on() -> Self {
        Self { enabled: true, ..Self::default() }
    }
}

impl Tract {
    /// A tract with staging off: appends write through, as a bare tract always has.
    pub fn new(base: u64, len: u64, plow: u64, reap: u64, fence_limit: Option<u64>) -> Self {
        Self { base, len, plow, reap, fence_limit, staging: Staging::default() }
    }

    /// The staged block at tract position `pos`, if one is staged there. Staged blocks are plow-contiguous and never span more than a lap (an append past the clean space is refused), so at most one matches.
    fn staged_at(&self, pos: u64) -> Option<usize> {
        let n = self.staging.blocks.len() as u64;
        if n == 0 {
            return None;
        }
        let off = (pos + self.len - self.staging.start % self.len) % self.len;
        (off < n).then_some(off as usize)
    }

    /// Write every staged block to the devices — one contiguous run per device (two at a ring wrap), read back and verified — and clear the stage. The vault calls this between the index flush and the spine entry: data before the commit that names it.
    pub fn write_staged<A: BlockDev, B: BlockDev>(&mut self, mirror: &mut Mirror<A, B>) -> Result<()> {
        if self.staging.blocks.is_empty() {
            return Ok(());
        }
        let start = self.staging.start;
        let blocks = core::mem::take(&mut self.staging.blocks);
        let batch: Vec<(u64, &Block)> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (self.base + (start + i as u64) % self.len, b))
            .collect();
        mirror.write_verified_batch(&batch)
    }

    /// Drop the stage unwritten — for a barrier that resets the plow (its positions are about to be reused) or a commit that failed (nothing may point at them).
    pub fn discard_staged(&mut self) {
        self.staging.blocks.clear();
    }

    /// Blocks staged and not yet written.
    pub fn staged_blocks(&self) -> usize {
        self.staging.blocks.len()
    }

    pub fn position(&self) -> u64 {
        self.plow % self.len
    }

    pub fn lap(&self) -> u64 {
        self.plow / self.len
    }

    /// Blocks of clean space (no live content, appendable modulo the fence).
    pub fn clean_blocks(&self) -> u64 {
        self.len - (self.plow - self.reap)
    }

    /// Append `blocks` contiguously at the plow (already sealed by the layer above).
    /// Returns the tract-relative lbas, in order — consecutive positions, wrapping at most once. Checks space, fence AND liveness BEFORE writing a byte: a refused append has no side effects.
    pub fn append<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        live: &dyn Liveness,
        blocks: &[Block],
    ) -> Result<Vec<u64>> {
        let n = blocks.len() as u64;
        if n > self.clean_blocks() {
            return Err(Error::TractFull);
        }
        if let Some(limit) = self.fence_limit {
            if self.plow + n > limit {
                return Err(Error::Fenced(self.plow));
            }
        }
        // THE LAP GUARD (field 2026-09-03: Leviathan's 43 danglings, no bad byte anywhere — the pointers were wrong, and blind appends turned wrong pointers into destroyed values). The clean invariant says no live block sits in [plow, reap+len); every historical loss class (missed repoint, cursor desync, pre-fix tombstone reuse) ends with exactly that broken, and the append is the moment breakage becomes loss. One map lookup per block makes lapping physically impossible: refuse before writing, emit so the embedder's log names the averted lap, and surface TractFull — the caller's ladder grows, the grow barrier realigns cursors onto provably live-free space, and the referenced bytes survive untouched.
        for i in 0..n {
            let pos = (self.plow + i) % self.len;
            if live.is_referenced(pos) {
                mirror.emit(crate::events::StorageEvent::LiveLapAverted { lba: pos });
                return Err(Error::TractFull);
            }
        }
        if self.staging.enabled {
            if self.staging.blocks.is_empty() {
                self.staging.start = self.plow;
            }
            debug_assert_eq!(self.staging.start + self.staging.blocks.len() as u64, self.plow, "staged appends are plow-contiguous");
            self.staging.blocks.extend_from_slice(blocks);
        } else {
            let batch: Vec<(u64, &Block)> = blocks
                .iter()
                .enumerate()
                .map(|(i, b)| (self.base + (self.plow + i as u64) % self.len, b))
                .collect();
            mirror.write_verified_batch(&batch)?;
        }
        let placed = (0..n).map(|i| (self.plow + i) % self.len).collect();
        self.plow += n;
        if self.staging.blocks.len() >= STAGE_MAX_BLOCKS {
            self.write_staged(mirror)?;
        }
        Ok(placed)
    }

    /// O(1) delete: zero the block on both mirrors. The index entry goes stale and the slot is reaped later (per VAULT.md, "no tombstones needed" — flash erases to zero, zero IS the deleted state).
    pub fn zero_delete<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        lba: u64,
    ) -> Result<()> {
        if lba >= self.len {
            return Err(Error::Bounds(lba));
        }
        if let Some(i) = self.staged_at(lba) {
            self.staging.blocks[i] = crate::block::ZERO_BLOCK;
            return Ok(());
        }
        mirror.write_verified(self.base + lba, &crate::block::ZERO_BLOCK)
    }

    /// Plain read of a tract block (callers verify content at their own layer).
    pub fn read<A: BlockDev, B: BlockDev>(
        &self,
        mirror: &mut Mirror<A, B>,
        lba: u64,
        buf: &mut Block,
    ) -> Result<()> {
        if lba >= self.len {
            return Err(Error::Bounds(lba));
        }
        if let Some(i) = self.staged_at(lba) {
            buf.copy_from_slice(&self.staging.blocks[i]);
            return Ok(());
        }
        mirror.read(self.base + lba, buf)
    }
}
