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

    /// Consecutive blocks from `lba` as one I/O where the device can: a commit's appends are runs, and a block at a time they were a device round trip each (2026-10-25: a 40 KB put was 40 single-block O_DIRECT writes and as many reads across the two rings). Default: block by block.
    fn write_run(&mut self, lba: u64, blocks: &[&Block]) -> Result<()> {
        for (i, b) in blocks.iter().enumerate() {
            self.write(lba + i as u64, b)?;
        }
        Ok(())
    }

    /// Consecutive blocks from `lba` into `out`, as one I/O where the device can. Default: block by block.
    fn read_run(&mut self, lba: u64, out: &mut [Block]) -> Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            self.read(lba + i as u64, b)?;
        }
        Ok(())
    }

    /// Scattered blocks, `out[i]` from `lbas[i]`, with as many reads in flight as the device can take where it can (the open's index walk reads a level of the tree at a time). Default: one after another.
    fn read_many(&mut self, lbas: &[u64], out: &mut [Block]) -> Result<()> {
        for (&lba, b) in lbas.iter().zip(out.iter_mut()) {
            self.read(lba, b)?;
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

    /// `grow` told where the committed extent ended before: the blocks `old_blocks..new_blocks` are the new ones. A device whose space is larger than its extent (ferros's vault process: a window bigger than the tract) zeroes exactly those and nothing below; the default ignores `old_blocks` and grows as `grow` does. The engine calls this, never `grow` directly, when it grows a tract (2026-11-08: a device that guessed where the old extent ended zeroed a whole vault).
    fn grow_from(&mut self, old_blocks: u64, new_blocks: u64) -> Result<()> {
        let _ = old_blocks;
        self.grow(new_blocks)
    }
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
    fn read_many(&mut self, lbas: &[u64], out: &mut [Block]) -> Result<()> {
        (**self).read_many(lbas, out)
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
    fn grow_from(&mut self, old_blocks: u64, new_blocks: u64) -> Result<()> {
        (**self).grow_from(old_blocks, new_blocks)
    }
}
