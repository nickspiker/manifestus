//! The tract — plow-managed log-structured region. VAULT.md mechanics, host profile.
//!
//! Single write head (the plow), advancing and wrapping. One pass per advance: scan positions ahead, classify each (zeroed → dead; sealed + oracle-live → live; anything else → trash, dead), compact live blocks back toward the write cursor, place new payload into the reclaimed slack. VAULT.md's "flush against live block → leave in place" falls out naturally: a live block whose compacted home equals its current position is skipped without I/O.
//!
//! The plow value is the MONOTONE total of blocks plowed since genesis — wrapped position is `plow % len`, and the rollback fence is a pure integer compare (`write cursor < fence_limit`). Wrapped positions are lap-ambiguous; totals are not.
//!
//! Killswitch posture: relocation copies are written BEFORE any commit references them; originals remain sealed at their old positions until physically overwritten, and the fence guarantees that cannot happen until the relocating commit is ≥ k generations deep. Crash at any byte: the committed HAMT points at originals, which are intact. Orphans (copies whose commit never landed) classify dead on the next pass and are trampled.
//!
//! The tract interprets NOTHING about block contents beyond sealedness (RÅ + hp). Liveness is the caller's knowledge (the HAMT), injected via [`Liveness`].

use crate::block::{Block, BlockDev, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::mirror::Mirror;
use crate::ring::MAGIC;
use vsf::decoding::parse::parse;
use vsf::types::VsfType;

/// Extract the sealing hp from a block if (and only if) the seal verifies. Schema-agnostic: spine entries, HAMT nodes, furrows, lone leaves all answer. One code path for the plow's liveness scan.
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

/// A live block that moved during compaction: the caller must update its index (batched into the next spine commit).
#[derive(Debug, Clone, PartialEq)]
pub struct Reloc {
    pub hp: [u8; 32],
    pub from: u64,
    pub to: u64,
}

/// Outcome of one advance pass.
#[derive(Debug, Default)]
pub struct Advance {
    /// Tract-relative lbas where the new payload blocks landed, in order.
    pub placed: Vec<u64>,
    /// Live blocks that moved (old position → new position). Empty when everything stayed put.
    pub relocations: Vec<Reloc>,
    /// Dead/trash blocks consumed by this pass.
    pub trampled: u64,
}

/// Plow state for one tract. Pure state — the mirror and oracle are borrowed per operation so the spine ring (which owns the mirror's lower blocks) and the tract can interleave.
pub struct Tract {
    /// Device lba where the tract begins (= N on host; G#C0000 on ferros).
    pub base: u64,
    /// Tract length in blocks. Arbitrary — never assumed power of two.
    pub len: u64,
    /// Monotone total blocks plowed since genesis. Wrapped position = plow % len.
    pub plow: u64,
    /// Absolute advance budget for the write cursor (monotone domain). Recomputed by the vault from the last k spine entries: min(recent plows) + len. None = unfenced (genesis era, fewer than k commits).
    pub fence_limit: Option<u64>,
}

impl Tract {
    pub fn position(&self) -> u64 {
        self.plow % self.len
    }

    pub fn lap(&self) -> u64 {
        self.plow / self.len
    }

    /// Write `payload` blocks (already sealed by the layer above) into the tract, compacting live blocks encountered along the way. `extra_scan` forces the pass to consume at least that many positions even when payload needs less — the spin primitive (`payload = &[], extra_scan = window`).
    pub fn advance<A: BlockDev, B: BlockDev, L: Liveness>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        oracle: &L,
        payload: &[Block],
        extra_scan: u64,
    ) -> Result<Advance> {
        let len = self.len;
        let mut out = Advance::default();

        // Scan cursor (classification frontier) and write cursor, both in the monotone domain. Invariant: write ≤ scan.
        let mut scan = self.plow;
        let mut write = self.plow;
        // Live blocks awaiting a compacted home: (original monotone position, hp, contents).
        let mut pending: Vec<(u64, [u8; 32], Block)> = Vec::new();
        // SAME-PASS KILLSWITCH GUARD: monotone positions of relocated originals. Their slots are reserved until the relocating commit lands — the write cursor skips them. (Cross-pass re-entry is the rollback fence's job in the monotone domain; this guards within one uncommitted pass.) Ascending by construction (scan order) — binary search.
        let mut reserved: Vec<u64> = Vec::new();
        let mut buf = ZERO_BLOCK;
        let mut dead_found = 0u64;

        // Every relocation already placed, every pending live, and every payload block consumes one dead slot.
        macro_rules! needs_met {
            () => {
                dead_found >= out.relocations.len() as u64 + pending.len() as u64 + payload.len() as u64
                    && scan - self.plow >= extra_scan
            };
        }
        macro_rules! skip_reserved {
            () => {
                while reserved.binary_search(&write).is_ok() {
                    write += 1;
                }
            };
        }

        while !needs_met!() {
            if scan - self.plow >= len {
                return Err(Error::TractFull);
            }
            let pos = scan % len;
            mirror.read(self.base + pos, &mut buf)?;
            let live_hp = sealed_hp(&buf).filter(|hp| oracle.is_live(pos, hp));
            match live_hp {
                Some(hp) => {
                    skip_reserved!();
                    if write == scan {
                        // Flush against a live block — already where it would be written. Zero I/O.
                        write += 1;
                    } else {
                        pending.push((scan, hp, buf));
                    }
                }
                None => {
                    if buf != ZERO_BLOCK {
                        out.trampled += 1;
                    }
                    dead_found += 1;
                }
            }
            scan += 1;

            // Drain pending into reclaimed slots; originals stay physically intact (reserved) until the relocating commit lands.
            loop {
                skip_reserved!();
                let Some(&(orig, _, _)) = pending.first() else { break };
                if write >= orig {
                    break;
                }
                let (orig, hp, block) = pending.remove(0);
                self.fenced_write(mirror, write, &block)?;
                out.relocations.push(Reloc { hp, from: orig % len, to: write % len });
                reserved.push(orig);
                write += 1;
            }
        }

        // Stragglers: enough dead slack exists by accounting; drain with the same reservation discipline.
        while !pending.is_empty() {
            skip_reserved!();
            let (orig, hp, block) = pending.remove(0);
            if write == orig {
                write += 1; // compacted home == current home
                continue;
            }
            debug_assert!(write < orig);
            self.fenced_write(mirror, write, &block)?;
            out.relocations.push(Reloc { hp, from: orig % len, to: write % len });
            reserved.push(orig);
            write += 1;
        }

        // Place the payload into the remaining slack — batched so both rings write concurrently. (Relocations above stay sequential: they're read-then-write interleaved.) Resolve each block's fenced lba up front, then one concurrent verified write.
        let mut batch: Vec<(u64, &Block)> = Vec::with_capacity(payload.len());
        for block in payload {
            skip_reserved!();
            debug_assert!(write < scan);
            if let Some(limit) = self.fence_limit {
                if write >= limit {
                    return Err(Error::Fenced(write));
                }
            }
            batch.push((self.base + (write % len), block));
            out.placed.push(write % len);
            write += 1;
        }
        mirror.write_verified_batch(&batch)?;
        skip_reserved!();

        // The new plow is the write cursor: everything in [write, scan) was classified dead and remains free-ahead; the next pass re-derives it with cheap reads. Persisting only the write cursor keeps crash recovery trivial.
        self.plow = write;
        Ok(out)
    }

    /// One spin window: relocate/compact `window` positions with no new payload. The vault loops this with a spine commit per window until a full lap is covered (dead > 25% trigger).
    pub fn spin_window<A: BlockDev, B: BlockDev, L: Liveness>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        oracle: &L,
        window: u64,
    ) -> Result<Advance> {
        self.advance(mirror, oracle, &[], window.min(self.len))
    }

    /// O(1) delete: zero the block on both mirrors. The index entry goes stale and is reaped by the plow (per VAULT.md, "no tombstones needed" — flash erases to zero, zero IS the deleted state).
    pub fn zero_delete<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        lba: u64,
    ) -> Result<()> {
        if lba >= self.len {
            return Err(Error::Bounds(lba));
        }
        mirror.write_verified(self.base + lba, &ZERO_BLOCK)
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

    fn fenced_write<A: BlockDev, B: BlockDev>(
        &self,
        mirror: &mut Mirror<A, B>,
        write: u64,
        block: &Block,
    ) -> Result<()> {
        if let Some(limit) = self.fence_limit {
            if write >= limit {
                return Err(Error::Fenced(write));
            }
        }
        mirror.write_verified(self.base + (write % self.len), block)
    }
}
