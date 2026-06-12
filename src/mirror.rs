//! Write-verify-then-mirror, per RING.md verbatim.
//!
//! Never write to the second device until the first is verified. A block is "written" only after it has been read back and compared — an unverified byte is not a written byte. A generation is committed when at least one device holds a verified copy.
//!
//! Failure semantics:
//! - Primary write/verify fails → retry once → hard error, secondary untouched (RING.md: "do not proceed").
//! - Secondary fails → dropped for the session, `degraded` flips, the op succeeds — the primary has it.
//!
//! The comparison is byte equality against the just-written buffer — strictly stronger than the kernel's BLAKE3-against-expected-hash check (we hold both byte strings; the kernel holds only the hash).

use crate::block::{Block, BlockDev, ZERO_BLOCK};
use crate::error::{Error, Result};

pub struct Mirror<A: BlockDev, B: BlockDev> {
    a: Option<A>,
    b: Option<B>,
    degraded: bool,
    scratch: Block,
}

impl<A: BlockDev, B: BlockDev> Mirror<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self {
            a: Some(a),
            b: Some(b),
            degraded: false,
            scratch: ZERO_BLOCK,
        }
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
        })
    }

    /// Write `buf` at `lba` on every present device, verifying each by read-back before touching the next. See module docs for the failure matrix.
    pub fn write_verified(&mut self, lba: u64, buf: &Block) -> Result<()> {
        match (self.a.as_mut(), self.b.as_mut()) {
            (Some(a), b) => {
                // Primary must land or the op fails — secondary deliberately untouched on primary failure.
                write_one(a, lba, buf, &mut self.scratch)?;
                if let Some(b) = b {
                    if write_one(b, lba, buf, &mut self.scratch).is_err() {
                        self.b = None;
                        self.degraded = true;
                    }
                }
                Ok(())
            }
            (None, Some(b)) => write_one(b, lba, buf, &mut self.scratch),
            (None, None) => Err(Error::Corrupt("mirror has no devices".into())),
        }
    }

    /// Read from the first healthy device. Content validation (hp / Empty / Corrupt classification) is the layer above — the mirror only routes.
    pub fn read(&mut self, lba: u64, buf: &mut Block) -> Result<()> {
        if let Some(a) = self.a.as_mut() {
            return a.read(lba, buf);
        }
        if let Some(b) = self.b.as_mut() {
            return b.read(lba, buf);
        }
        Err(Error::Corrupt("mirror has no devices".into()))
    }

    pub fn flush(&mut self) -> Result<()> {
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

    pub fn has_a(&self) -> bool {
        self.a.is_some()
    }

    pub fn has_b(&self) -> bool {
        self.b.is_some()
    }

    /// Direct access for replication / per-device search (verified_replicate reads both sides independently).
    pub fn devices(&mut self) -> (Option<&mut A>, Option<&mut B>) {
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
