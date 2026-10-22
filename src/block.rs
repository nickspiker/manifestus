//! 4KB block device abstraction — the only I/O surface the engine sees.
//!
//! 4KB is the natural write unit for UFS (4KB logical block), SD (8 × 512B sectors, FTL-aligned), and every modern filesystem (ext4/f2fs/APFS default block size). One block = one read = one write, everywhere.

use crate::error::Result;

pub const BLOCK: usize = 1 << 12;

/// One 4KB block. Stack-friendly fixed array; the engine never does partial-block I/O.
pub type Block = [u8; BLOCK];

pub const ZERO_BLOCK: Block = [0u8; BLOCK];

/// The engine's entire I/O surface. Host backs this with files (see [`crate::host::FileDev`]); the ferros kernel backs it with UFS/SD HAL devices. Same engine code above, zero changes. `Send` so the two mirror rings can be written concurrently from separate threads (the hybrid write path treats each ring as its own disk).
pub trait BlockDev: Send {
    /// Device capacity in blocks. Engine-visible geometry comes from spine entries, never from here — this exists for bounds checks and the fs-as-witness cross-check.
    fn block_count(&self) -> u64;

    fn read(&mut self, lba: u64, buf: &mut Block) -> Result<()>;

    fn write(&mut self, lba: u64, buf: &Block) -> Result<()>;

    /// Write consecutive blocks starting at `lba`. A device that can move a run in one transfer overrides this (FileDev: one pwrite); the default is one write per block.
    fn write_run(&mut self, lba: u64, blocks: &[&Block]) -> Result<()> {
        for (i, b) in blocks.iter().enumerate() {
            self.write(lba + i as u64, b)?;
        }
        Ok(())
    }

    /// Read consecutive blocks starting at `lba` into `out`. Default: one read per block.
    fn read_run(&mut self, lba: u64, out: &mut [Block]) -> Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            self.read(lba + i as u64, b)?;
        }
        Ok(())
    }

    /// TRIM hint. No-op on host (filesystem's problem); kernel profile forwards to UFS/SD on tract wrap boundaries per RING.md.
    fn discard(&mut self, _lba: u64, _count: u64) -> Result<()> {
        Ok(())
    }

    /// Durability barrier — when this returns, prior writes survive power loss.
    fn flush(&mut self) -> Result<()>;

    /// Extend capacity to `new_blocks` (zeroed). Space-first discipline: the vault grows devices BEFORE committing the new geometry, so power loss between the two leaves unclaimed zeros. Default refuses — fixed-extent devices (kernel partitions) cannot grow.
    fn grow(&mut self, _new_blocks: u64) -> Result<()> {
        Err(crate::error::Error::Corrupt(
            "device does not support grow".into(),
        ))
    }
}

/// Split (lba, block) pairs into runs of consecutive lbas, in order: (first lba, index range into `blocks`). The commit, the follower and the read-backs move each run in one transfer.
pub fn runs_of(blocks: &[(u64, &Block)]) -> alloc::vec::Vec<(u64, core::ops::Range<usize>)> {
    let mut out: alloc::vec::Vec<(u64, core::ops::Range<usize>)> = alloc::vec::Vec::new();
    for (i, &(lba, _)) in blocks.iter().enumerate() {
        match out.last_mut() {
            Some((start, r)) if *start + (r.end - r.start) as u64 == lba => r.end = i + 1,
            _ => out.push((lba, i..i + 1)),
        }
    }
    out
}

/// Write every pair, a run per transfer.
pub fn write_pairs<D: BlockDev + ?Sized>(dev: &mut D, blocks: &[(u64, &Block)]) -> Result<()> {
    for (lba, r) in runs_of(blocks) {
        let run: alloc::vec::Vec<&Block> = blocks[r].iter().map(|&(_, b)| b).collect();
        dev.write_run(lba, &run)?;
    }
    Ok(())
}

/// Read every pair's lba back, a run per transfer, and return the indices whose bytes differ from what was written.
pub fn mismatches<D: BlockDev + ?Sized>(dev: &mut D, blocks: &[(u64, &Block)]) -> Result<alloc::vec::Vec<usize>> {
    let mut bad = alloc::vec::Vec::new();
    for (lba, r) in runs_of(blocks) {
        let mut got = alloc::vec![ZERO_BLOCK; r.end - r.start];
        dev.read_run(lba, &mut got)?;
        for (j, g) in got.iter().enumerate() {
            if g != blocks[r.start + j].1 {
                bad.push(r.start + j);
            }
        }
    }
    Ok(bad)
}

/// Forwarding impl so borrowed devices compose (verified_replicate wraps `&mut A` / `&mut B` in temporary solo Mirrors).
impl<D: BlockDev + ?Sized> BlockDev for &mut D {
    fn block_count(&self) -> u64 {
        (**self).block_count()
    }
    fn read(&mut self, lba: u64, buf: &mut Block) -> Result<()> {
        (**self).read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &Block) -> Result<()> {
        (**self).write(lba, buf)
    }
    fn write_run(&mut self, lba: u64, blocks: &[&Block]) -> Result<()> {
        (**self).write_run(lba, blocks)
    }
    fn read_run(&mut self, lba: u64, out: &mut [Block]) -> Result<()> {
        (**self).read_run(lba, out)
    }
    fn discard(&mut self, lba: u64, count: u64) -> Result<()> {
        (**self).discard(lba, count)
    }
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
    fn grow(&mut self, new_blocks: u64) -> Result<()> {
        (**self).grow(new_blocks)
    }
}
