//! Append-only keyed store with crash-safe recovery.
//!
//! Each write appends a self-validating record (see [`crate::record`]) and fsyncs. Open scans the file front-to-back, builds an in-memory pointer table, and silently truncates at the first invalid record — the standard recovery path for any "power died mid-write" scenario.
//!
//! Latest-record-wins semantics: writing the same `entry_key` twice means the older record becomes waste (its bytes still occupy file space until a compaction). Tombstones are themselves records; they make the entry invisible to `get` and `iter` and add to waste.
//!
//! No in-place mutation. Ever. Append + tombstone + compact-into-fresh-file is the entire write surface.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::record::{
    EntryKey, Record, FILE_HEADER_LEN, FILE_MAGIC, FLAG_TOMBSTONE, FORMAT_VERSION,
};

/// What the pointer table tracks per live entry. Lookups go through this in RAM; the actual value bytes are re-read from disk on `get` and HMAC-reverified.
#[derive(Debug, Clone)]
pub struct EntryMeta {
    pub offset: u64,
    pub size: u32,
    pub type_tag: u8,
    pub flags: u8,
    pub created_at: i64,
    pub expires_at: i64,
    pub anchor_seq: u64,
}

pub struct Store {
    path: PathBuf,
    file: File,
    anchor_key: [u8; 32],
    /// Live entries only. Tombstoned and overwritten records are absent.
    index: HashMap<EntryKey, EntryMeta>,
    /// Next `anchor_seq` to assign on write.
    next_seq: u64,
    /// Sum of bytes occupied by tombstoned + superseded records. Drives compaction trigger.
    wasted_bytes: u64,
    /// Current logical EOF. New writes go here.
    file_size: u64,
}

impl Store {
    /// Open existing store at `path`, or create a new one if missing. Either way, returns a ready-to-use handle.
    ///
    /// Recovery: any tail bytes that fail to decode (torn header, body truncation, HMAC mismatch on the tail record) are silently truncated. This is the only response to corruption — no caller-visible signal, no `Recovered` variant. Atomicity all the way down.
    pub fn open_or_create(path: &Path, anchor_key: &[u8; 32]) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let existed_with_data = path.exists() && std::fs::metadata(path).map(|m| m.len() > 0).unwrap_or(false);

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;

        let mut store = Self {
            path: path.to_path_buf(),
            file,
            anchor_key: *anchor_key,
            index: HashMap::new(),
            next_seq: 1,
            wasted_bytes: 0,
            file_size: 0,
        };

        if existed_with_data {
            store.scan_and_rebuild()?;
        } else {
            store.write_file_header()?;
        }

        Ok(store)
    }

    fn write_file_header(&mut self) -> Result<()> {
        let mut header = [0u8; FILE_HEADER_LEN];
        header[..4].copy_from_slice(&FILE_MAGIC);
        header[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&header)?;
        self.file.sync_data()?;
        self.file_size = FILE_HEADER_LEN as u64;
        Ok(())
    }

    fn scan_and_rebuild(&mut self) -> Result<()> {
        let total_len = self.file.metadata()?.len();
        if total_len < FILE_HEADER_LEN as u64 {
            // Header itself missing → bad file, but treat as fresh: write header, ignore prior bytes.
            self.file.set_len(0)?;
            self.write_file_header()?;
            return Ok(());
        }

        // Load whole file. V0 vaults are sub-100 MB so this is fine.
        let mut buf = Vec::with_capacity(total_len as usize);
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_to_end(&mut buf)?;

        if &buf[..4] != FILE_MAGIC {
            return Err(Error::BadMagic);
        }
        let version = u32::from_le_bytes(buf[4..8].try_into().unwrap());
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let mut offset = FILE_HEADER_LEN;
        let mut valid_end = FILE_HEADER_LEN;
        let mut max_seq = 0u64;

        while offset < buf.len() {
            match Record::decode_at(&buf, offset, &self.anchor_key) {
                Ok((rec, consumed)) => {
                    self.apply_record(&rec, offset as u64, consumed as u32);
                    if rec.anchor_seq > max_seq {
                        max_seq = rec.anchor_seq;
                    }
                    offset += consumed;
                    valid_end = offset;
                }
                Err(_) => break, // Stop scanning at first corrupt record.
            }
        }

        if valid_end < buf.len() {
            self.file.set_len(valid_end as u64)?;
            self.file.sync_data()?;
        }

        self.file_size = valid_end as u64;
        self.next_seq = max_seq + 1;
        Ok(())
    }

    /// Update in-memory state to reflect a single decoded record. Handles both alive and tombstone records, accounting waste for any prior version that gets superseded.
    fn apply_record(&mut self, rec: &Record, offset: u64, size: u32) {
        // If we had a prior entry for this key, that entry's bytes are now waste.
        if let Some(prev) = self.index.remove(&rec.entry_key) {
            self.wasted_bytes = self.wasted_bytes.saturating_add(prev.size as u64);
        }
        if rec.flags & FLAG_TOMBSTONE != 0 {
            // Tombstones are themselves waste — they exist only to nullify a prior live record.
            self.wasted_bytes = self.wasted_bytes.saturating_add(size as u64);
            return;
        }
        self.index.insert(
            rec.entry_key,
            EntryMeta {
                offset,
                size,
                type_tag: rec.type_tag,
                flags: rec.flags,
                created_at: rec.created_at,
                expires_at: rec.expires_at,
                anchor_seq: rec.anchor_seq,
            },
        );
    }

    /// Look up a value by `entry_key`. Returns `Ok(None)` if the entry doesn't exist or was tombstoned. Re-reads the record from disk and re-verifies HMAC — paranoid but cheap.
    pub fn get(&mut self, entry_key: &EntryKey) -> Result<Option<Vec<u8>>> {
        let Some(meta) = self.index.get(entry_key).cloned() else {
            return Ok(None);
        };
        let mut buf = vec![0u8; meta.size as usize];
        self.file.seek(SeekFrom::Start(meta.offset))?;
        self.file.read_exact(&mut buf)?;
        let (rec, _) = Record::decode_at(&buf, 0, &self.anchor_key)?;
        Ok(Some(rec.value))
    }

    /// Insert or overwrite `entry_key` with `value`. The previous record (if any) becomes waste until compaction.
    ///
    /// `now` is the timestamp the caller wants written as `created_at` — caller's clock, caller's units. The store doesn't read it.
    pub fn put(
        &mut self,
        entry_key: EntryKey,
        value: &[u8],
        type_tag: u8,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;

        let mut flags = 0u8;
        if expires_at.is_some() {
            flags |= crate::record::FLAG_EXPIRES;
        }

        let record = Record {
            entry_key,
            type_tag,
            flags,
            created_at: now,
            expires_at: expires_at.unwrap_or(0),
            anchor_seq: seq,
            value: value.to_vec(),
        };
        let encoded = record.encode(&self.anchor_key);
        let offset = self.file_size;
        let size = encoded.len() as u32;

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.file_size += encoded.len() as u64;

        self.apply_record(&record, offset, size);
        Ok(())
    }

    /// Write a tombstone for `entry_key`. After this, `get` and `iter` ignore the key until a fresh `put` resurrects it.
    pub fn delete(&mut self, entry_key: &EntryKey, now: i64) -> Result<()> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let record = Record {
            entry_key: *entry_key,
            type_tag: 0,
            flags: FLAG_TOMBSTONE,
            created_at: now,
            expires_at: 0,
            anchor_seq: seq,
            value: Vec::new(),
        };
        let encoded = record.encode(&self.anchor_key);
        let offset = self.file_size;
        let size = encoded.len() as u32;
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(&encoded)?;
        self.file.sync_data()?;
        self.file_size += encoded.len() as u64;
        self.apply_record(&record, offset, size);
        Ok(())
    }

    /// Iterate live entries. Order is unspecified.
    pub fn iter(&self) -> impl Iterator<Item = (&EntryKey, &EntryMeta)> {
        self.index.iter()
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Highest `anchor_seq` written so far. Useful for dual-ring sync.
    pub fn anchor_seq(&self) -> u64 {
        self.next_seq.saturating_sub(1)
    }

    pub fn wasted_bytes(&self) -> u64 {
        self.wasted_bytes
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Fraction of `file_size` that's wasted (tombstones + superseded records). Inputs to compaction trigger.
    pub fn wasted_ratio(&self) -> f64 {
        if self.file_size == 0 {
            0.0
        } else {
            self.wasted_bytes as f64 / self.file_size as f64
        }
    }

    /// Rewrite live records to `target_path`. Caller is responsible for atomically renaming `target_path` over `self.path` (and reopening) — keeping that step at the caller layer lets the dual-ring orchestrator do its swap correctly.
    pub fn compact_to(&mut self, target_path: &Path) -> Result<()> {
        let mut metas: Vec<(EntryKey, EntryMeta)> = self
            .index
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect();
        metas.sort_by_key(|(_, m)| m.anchor_seq);

        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(target_path)?;

        let mut header = [0u8; FILE_HEADER_LEN];
        header[..4].copy_from_slice(&FILE_MAGIC);
        header[4..8].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.write_all(&header)?;

        let mut buf = Vec::new();
        for (_, meta) in &metas {
            buf.resize(meta.size as usize, 0);
            self.file.seek(SeekFrom::Start(meta.offset))?;
            self.file.read_exact(&mut buf)?;
            out.write_all(&buf)?;
        }
        out.sync_all()?;
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
