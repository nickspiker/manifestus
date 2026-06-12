//! Host file-backed block device.
//!
//! The file offset grid IS the block grid: `pwrite(4096, lba * 4096)` covers whole filesystem blocks on every modern fs, reaching the device as whole-sector writes — same property the kernel profile gets from raw LBAs.
//!
//! Page cache vs the verify discipline: a buffered read-back verifies RAM, not media — verification theater. FileDev therefore opens O_DIRECT on Linux/Android (4096-aligned scratch buffer satisfies the alignment contract), F_NOCACHE on macOS (Darwin has no O_DIRECT), and falls back to buffered + fdatasync where O_DIRECT is refused (tmpfs in CI). [`FileDev::direct`] reports which mode is live.
//!
//! Durability: `flush` is fdatasync on Linux/Android and F_FULLFSYNC on macOS — Darwin's plain fsync does not flush the drive cache.
//!
//! Torn writes: 4KB atomicity is never assumed. A torn block reads as Corrupt at the validation layer (BLAKE3 fails) and the killswitch theorems handle it.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::block::{Block, BlockDev, BLOCK};
use crate::error::{Error, Result};

/// O_DIRECT requires buffer alignment to the logical block size; 4096 satisfies every real device.
#[repr(C, align(4096))]
struct AlignedBlock([u8; BLOCK]);

pub struct FileDev {
    file: File,
    blocks: u64,
    direct: bool,
    scratch: Box<AlignedBlock>,
}

impl FileDev {
    /// Create the device file at `blocks` 4KB blocks (zeroed), or ADOPT an existing one (growing it to at least `blocks` if short, never truncating). The path is passless-derived — a 43-char blake3 name in our app dir is definitionally ours — so there is no foreign file to protect at this layer. Data-aware protection lives at the ring level: genesis only over zero-Valid rings, decided at mirror scope.
    pub fn create(path: &Path, blocks: u64) -> Result<Self> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)?;
        let len = f.metadata()?.len();
        let want = blocks * BLOCK as u64;
        if len < want {
            preallocate(&f, want)?;
        }
        f.sync_all()?;
        drop(f);
        Self::open(path)
    }

    /// Open an existing device file. Length must be block-aligned — anything else was not written by us.
    pub fn open(path: &Path) -> Result<Self> {
        let (file, direct) = open_rw(path)?;
        let len = file.metadata()?.len();
        if len % BLOCK as u64 != 0 {
            return Err(Error::Corrupt(format!(
                "file length {} is not 4KB-aligned — not a custodes device",
                len
            )));
        }
        Ok(Self {
            file,
            blocks: len / BLOCK as u64,
            direct,
            scratch: Box::new(AlignedBlock([0u8; BLOCK])),
        })
    }

    /// Extend the file to `new_blocks` (zeroed, preallocated). Tract growth: fallocate first, commit the new geometry in a spine entry second — power loss between the two leaves unclaimed zeros, which is harmless.
    pub fn grow(&mut self, new_blocks: u64) -> Result<()> {
        if new_blocks < self.blocks {
            return Err(Error::Corrupt(format!(
                "grow cannot shrink: {} -> {}",
                self.blocks, new_blocks
            )));
        }
        preallocate(&self.file, new_blocks * BLOCK as u64)?;
        self.file.sync_all()?;
        self.blocks = new_blocks;
        Ok(())
    }

    /// True when I/O bypasses the page cache (O_DIRECT / F_NOCACHE) — read-back verification reaches media. False = buffered fallback: verification still catches wrong-offset and short-write bugs, but reads may be served from cache.
    pub fn direct(&self) -> bool {
        self.direct
    }

    fn bounds(&self, lba: u64) -> Result<()> {
        if lba >= self.blocks {
            Err(Error::Bounds(lba))
        } else {
            Ok(())
        }
    }
}

impl BlockDev for FileDev {
    fn block_count(&self) -> u64 {
        self.blocks
    }

    fn read(&mut self, lba: u64, buf: &mut Block) -> Result<()> {
        self.bounds(lba)?;
        let off = lba * BLOCK as u64;
        if self.direct {
            // O_DIRECT contract: aligned buffer, aligned offset, aligned length. Caller's buf may be unaligned — bounce through the aligned scratch.
            self.file.read_exact_at(&mut self.scratch.0, off)?;
            buf.copy_from_slice(&self.scratch.0);
        } else {
            self.file.read_exact_at(buf, off)?;
        }
        Ok(())
    }

    fn write(&mut self, lba: u64, buf: &Block) -> Result<()> {
        self.bounds(lba)?;
        let off = lba * BLOCK as u64;
        if self.direct {
            self.scratch.0.copy_from_slice(buf);
            self.file.write_all_at(&self.scratch.0, off)?;
        } else {
            self.file.write_all_at(buf, off)?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            // Darwin's fsync does not flush the drive cache; F_FULLFSYNC does.
            let r = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_FULLFSYNC) };
            if r != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.file.sync_data()?;
            Ok(())
        }
    }
}

/// Open read-write, preferring cache-bypass: O_DIRECT on Linux/Android, F_NOCACHE on macOS, buffered fallback elsewhere or when the filesystem refuses (tmpfs).
fn open_rw(path: &Path) -> Result<(File, bool)> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::unix::fs::OpenOptionsExt;
        if let Ok(f) = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_DIRECT)
            .open(path)
        {
            return Ok((f, true));
        }
    }

    let f = OpenOptions::new().read(true).write(true).open(path)?;

    #[cfg(target_os = "macos")]
    {
        let direct = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_NOCACHE, 1) } == 0;
        return Ok((f, direct));
    }

    #[cfg(not(target_os = "macos"))]
    Ok((f, false))
}

/// Preallocate so ENOSPC fires at format/grow time, never mid-commit. fallocate where available; set_len (sparse) as the portable fallback.
fn preallocate(f: &File, len: u64) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let r = unsafe { libc::fallocate(f.as_raw_fd(), 0, 0, len as libc::off_t) };
        if r == 0 {
            return Ok(());
        }
        // Filesystem without fallocate support — fall through to sparse.
    }
    f.set_len(len)?;
    Ok(())
}
