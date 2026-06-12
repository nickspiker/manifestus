//! Error type for custodes Layer 0.

use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    BadMagic,
    UnsupportedVersion(u32),
    /// HMAC verification failed for an individual record.
    Hmac,
    /// Length redundancy check failed, body truncated, or other structural corruption. Triggers silent truncate at the offending offset during open.
    Corrupt(String),
    /// Read-back verification failed after write — the bytes on the device do not match what was written, even after retry.
    Verify(u64),
    /// Block address beyond device bounds.
    Bounds(u64),
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
            Error::UnsupportedVersion(v) => write!(f, "unsupported format version: {}", v),
            Error::Hmac => write!(f, "HMAC verification failed"),
            Error::Corrupt(s) => write!(f, "corrupt: {}", s),
            Error::Verify(lba) => write!(f, "write verification failed at block {}", lba),
            Error::Bounds(lba) => write!(f, "block {} out of device bounds", lba),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
