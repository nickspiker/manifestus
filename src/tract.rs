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
    /// Returns the tract-relative lbas, in order — consecutive positions, wrapping at most once. Checks space and fence BEFORE writing a byte: a refused append has no side effects.
    pub fn append<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
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
        let batch: Vec<(u64, &Block)> = blocks
            .iter()
            .enumerate()
            .map(|(i, b)| (self.base + (self.plow + i as u64) % self.len, b))
            .collect();
        mirror.write_verified_batch(&batch)?;
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
