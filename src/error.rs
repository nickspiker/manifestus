//! Error type for the custodes engine.

use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    BadMagic,
    /// Seal verification failed — the block's hp does not match BLAKE3 of its body.
    Seal,
    /// Structural corruption: misplaced entry, foreign schema, missing fields, broken chain, or geometry violations. Classification paths map this to Corrupt-the-state and trust no byte of the block.
    Corrupt(String),
    /// Read-back verification failed after write — the bytes on the device do not match what was written, even after retry.
    Verify(u64),
    /// Block address beyond device bounds.
    Bounds(u64),
    /// Write cursor reached the rollback fence — the caller must commit generations before the plow may advance further.
    Fenced(u64),
    /// A full lap was scanned without finding enough dead space: the tract is full (grow or refuse).
    TractFull,
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O: {}", e),
            Error::BadMagic => write!(f, "not a custodes file (bad magic)"),
            Error::Seal => write!(f, "seal verification failed"),
            Error::Corrupt(s) => write!(f, "corrupt: {}", s),
            Error::Verify(lba) => write!(f, "write verification failed at block {}", lba),
            Error::Bounds(lba) => write!(f, "block {} out of device bounds", lba),
            Error::Fenced(w) => write!(f, "rollback fence reached at plow {}", w),
            Error::TractFull => write!(f, "tract full — no dead space in a full lap"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
