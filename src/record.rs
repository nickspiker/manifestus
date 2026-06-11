//! On-disk record format. Self-validating: each record carries its own length-redundant header + BLAKE3 keyed-hash HMAC over the rest, so torn writes / corruption are detected at the per-record granularity.
//!
//! # Layout
//!
//! Fixed-size 104-byte header followed by `value_len = total_size - 104` opaque body bytes.
//!
//! | Offset | Size | Field             | Notes |
//! |---|---|---|---|
//! |  0     | 4    | magic             | `RECORD_MAGIC` little-endian |
//! |  4     | 4    | total_size        | header + body in bytes |
//! |  8     | 4    | total_size_chk    | `!total_size` — torn-write detector |
//! | 12     | 32   | entry_key         | content address (caller-supplied) |
//! | 44     | 1    | type_tag          | caller-defined |
//! | 45     | 1    | flags             | tombstone / pinned / expires bits |
//! | 46     | 2    | reserved          | zero |
//! | 48     | 8    | created_at        | i64 little-endian (caller's clock) |
//! | 56     | 8    | expires_at        | i64 little-endian (0 = never) |
//! | 64     | 8    | anchor_seq        | monotonic per-write counter |
//! | 72     | 32   | hmac              | BLAKE3 keyed_hash over offsets 0..72 + body |
//! | 104    | n    | body              | opaque value bytes (`value_len` bytes) |

use crate::error::{Error, Result};

/// 32-byte content address. Caller-supplied (typically a hash derived via passless-key or similar).
pub type EntryKey = [u8; 32];

pub const FILE_MAGIC: [u8; 4] = *b"PVDB";
pub const FORMAT_VERSION: u32 = 0;
pub const FILE_HEADER_LEN: usize = 8;

pub const RECORD_MAGIC: u32 = 0x5644_5244; // arbitrary, fixed
pub const RECORD_HEADER_LEN: usize = 104;
pub const HMAC_OFFSET: usize = 72;
pub const HMAC_LEN: usize = 32;

/// Record alive by default. Tombstone signals delete. Pinned exempts from GC. Expires means `expires_at` is meaningful (otherwise ignore the field).
pub const FLAG_TOMBSTONE: u8 = 0b0000_0001;
pub const FLAG_PINNED: u8 = 0b0000_0010;
pub const FLAG_EXPIRES: u8 = 0b0000_0100;

/// Decoded record header + body. Used when reading existing records back from disk.
pub struct Record {
    pub entry_key: EntryKey,
    pub type_tag: u8,
    pub flags: u8,
    pub created_at: i64,
    pub expires_at: i64,
    pub anchor_seq: u64,
    pub value: Vec<u8>,
}

impl Record {
    /// Encode this record under `anchor_key`. The returned bytes are ready to append to a file.
    pub fn encode(&self, anchor_key: &[u8; 32]) -> Vec<u8> {
        let total_size = (RECORD_HEADER_LEN + self.value.len()) as u32;
        let mut buf = Vec::with_capacity(total_size as usize);

        buf.extend_from_slice(&RECORD_MAGIC.to_le_bytes());
        buf.extend_from_slice(&total_size.to_le_bytes());
        buf.extend_from_slice(&(!total_size).to_le_bytes());
        buf.extend_from_slice(&self.entry_key);
        buf.push(self.type_tag);
        buf.push(self.flags);
        buf.extend_from_slice(&[0u8; 2]); // reserved
        buf.extend_from_slice(&self.created_at.to_le_bytes());
        buf.extend_from_slice(&self.expires_at.to_le_bytes());
        buf.extend_from_slice(&self.anchor_seq.to_le_bytes());

        debug_assert_eq!(buf.len(), HMAC_OFFSET);

        // HMAC slot: placeholder, filled in after we hash everything else.
        let hmac_slot = buf.len();
        buf.extend_from_slice(&[0u8; HMAC_LEN]);
        buf.extend_from_slice(&self.value);

        // HMAC = keyed_hash(anchor_key, header_pre_hmac || body)
        let mut hasher = blake3::Hasher::new_keyed(anchor_key);
        hasher.update(&buf[..hmac_slot]);
        hasher.update(&self.value);
        let mac = hasher.finalize();
        buf[hmac_slot..hmac_slot + HMAC_LEN].copy_from_slice(mac.as_bytes());

        debug_assert_eq!(buf.len(), total_size as usize);
        buf
    }

    /// Decode a record starting at `offset` in `buf`. Returns the record + the total bytes consumed so the scanner can advance.
    pub fn decode_at(buf: &[u8], offset: usize, anchor_key: &[u8; 32]) -> Result<(Self, usize)> {
        if offset + RECORD_HEADER_LEN > buf.len() {
            return Err(Error::Corrupt("record header truncated".into()));
        }

        let magic = u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap());
        if magic != RECORD_MAGIC {
            return Err(Error::Corrupt("bad record magic".into()));
        }

        let total_size = u32::from_le_bytes(buf[offset + 4..offset + 8].try_into().unwrap());
        let total_size_chk = u32::from_le_bytes(buf[offset + 8..offset + 12].try_into().unwrap());
        if !total_size != total_size_chk {
            return Err(Error::Corrupt("size redundancy check failed".into()));
        }
        let total = total_size as usize;
        if total < RECORD_HEADER_LEN {
            return Err(Error::Corrupt("record size smaller than header".into()));
        }
        if offset + total > buf.len() {
            return Err(Error::Corrupt("record body extends past file end".into()));
        }

        let mut entry_key = [0u8; 32];
        entry_key.copy_from_slice(&buf[offset + 12..offset + 44]);
        let type_tag = buf[offset + 44];
        let flags = buf[offset + 45];
        // 46..48 reserved
        let created_at = i64::from_le_bytes(buf[offset + 48..offset + 56].try_into().unwrap());
        let expires_at = i64::from_le_bytes(buf[offset + 56..offset + 64].try_into().unwrap());
        let anchor_seq = u64::from_le_bytes(buf[offset + 64..offset + 72].try_into().unwrap());

        let hmac_start = offset + HMAC_OFFSET;
        let stored_hmac = &buf[hmac_start..hmac_start + HMAC_LEN];

        let value_start = offset + RECORD_HEADER_LEN;
        let value_end = offset + total;
        let value = buf[value_start..value_end].to_vec();

        // HMAC verify: hash header bytes 0..72 + body
        let mut hasher = blake3::Hasher::new_keyed(anchor_key);
        hasher.update(&buf[offset..hmac_start]);
        hasher.update(&value);
        if hasher.finalize().as_bytes() != stored_hmac {
            return Err(Error::Hmac);
        }

        Ok((
            Self {
                entry_key,
                type_tag,
                flags,
                created_at,
                expires_at,
                anchor_seq,
                value,
            },
            total,
        ))
    }
}
