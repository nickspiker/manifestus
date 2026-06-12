//! 4KB block device abstraction — the only I/O surface the engine sees.
//!
//! 4KB is the natural write unit for UFS (4KB logical block), SD (8 × 512B sectors, FTL-aligned), and every modern filesystem (ext4/f2fs/APFS default block size). One block = one read = one write, everywhere.

use crate::error::Result;

pub const BLOCK: usize = 4096;

/// One 4KB block. Stack-friendly fixed array; the engine never does partial-block I/O.
pub type Block = [u8; BLOCK];

pub const ZERO_BLOCK: Block = [0u8; BLOCK];

/// The engine's entire I/O surface. Host backs this with files (see [`crate::host::FileDev`]); the ferros kernel backs it with UFS/SD HAL devices. Same engine code above, zero changes.
pub trait BlockDev {
    /// Device capacity in blocks. Engine-visible geometry comes from spine entries, never from here — this exists for bounds checks and the fs-as-witness cross-check.
    fn block_count(&self) -> u64;

    fn read(&mut self, lba: u64, buf: &mut Block) -> Result<()>;

    fn write(&mut self, lba: u64, buf: &Block) -> Result<()>;

    /// TRIM hint. No-op on host (filesystem's problem); kernel profile forwards to UFS/SD on tract wrap boundaries per RING.md.
    fn discard(&mut self, _lba: u64, _count: u64) -> Result<()> {
        Ok(())
    }

    /// Durability barrier — when this returns, prior writes survive power loss.
    fn flush(&mut self) -> Result<()>;
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
    fn discard(&mut self, lba: u64, count: u64) -> Result<()> {
        (**self).discard(lba, count)
    }
    fn flush(&mut self) -> Result<()> {
        (**self).flush()
    }
}
