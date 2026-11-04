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
}

impl Tract {
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
    /// Returns the tract-relative lbas, in order — consecutive positions, wrapping at most once. Checks space, fence AND liveness BEFORE staging a byte: a refused append has no side effects. The blocks are staged in the mirror and reach the devices, verified, before the next spine write.
    pub fn append<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        live: &dyn Liveness,
        blocks: &[Block],
    ) -> Result<Vec<u64>> {
        self.append_with(mirror, live, blocks.len() as u64, |i| blocks[i as usize])
    }

    /// [`Self::append`] without the caller's copy of the blocks: block `i` is made by `make(i)` and staged as it is made, after every check has passed (so a refused append makes and stages nothing). A large value is then held once, in the staging, instead of once in the caller's vector and again there (2026-10-26: a 2.78 MB put peaked at 3.3x the value in the heap, and ran the ferros kernel's out).
    pub fn append_with<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        live: &dyn Liveness,
        n: u64,
        mut make: impl FnMut(u64) -> Block,
    ) -> Result<Vec<u64>> {
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
        // Staged, not written: the commit that will reference these writes them out first (Mirror::stage / drain).
        mirror.reserve_staged(n as usize);
        for i in 0..n {
            let b = make(i);
            mirror.stage_one(self.base + (self.plow + i) % self.len, &b);
        }
        let placed = (0..n).map(|i| (self.plow + i) % self.len).collect();
        self.plow += n;
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
        mirror.write_verified(self.base + lba, &crate::block::ZERO_BLOCK)
    }

    /// [`Self::read`] thru the mirror's index cache — the index walk's reads (see [`Mirror::read_cached`]).
    pub fn read_cached<A: BlockDev, B: BlockDev>(&self, mirror: &mut Mirror<A, B>, lba: u64, buf: &mut Block) -> Result<()> {
        if lba >= self.len {
            return Err(Error::Bounds(lba));
        }
        mirror.read_cached(self.base + lba, buf)
    }

    /// Consecutive tract blocks from `lba` as one read (no ring wrap inside: callers cut their runs at consecutive positions, which a wrap breaks).
    pub fn read_run<A: BlockDev, B: BlockDev>(&self, mirror: &mut Mirror<A, B>, lba: u64, out: &mut [Block]) -> Result<()> {
        // WHY/PROOF: `lba` is a furrow position read off a leaf block; `lba + out.len()` wrapped for an lba near u64::MAX, passed the old compare, and `base + lba` then wrapped into the spine; the subtraction form checks lba first so `len - lba` is defined, and forms no sum.
        if lba >= self.len || out.len() as u64 > self.len - lba {
            return Err(Error::Bounds(lba));
        }
        mirror.read_run(self.base + lba, out)
    }

    /// Scattered tract blocks with reads in flight together ([`Mirror::read_many`]).
    pub fn read_many<A: BlockDev, B: BlockDev>(&self, mirror: &mut Mirror<A, B>, lbas: &[u64], out: &mut [Block]) -> Result<()> {
        let mut dev: Vec<u64> = Vec::with_capacity(lbas.len());
        for &lba in lbas {
            if lba >= self.len {
                return Err(Error::Bounds(lba));
            }
            dev.push(self.base + lba);
        }
        mirror.read_many(&dev, out)
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
        mirror.read(self.base + lba, buf)
    }
}
