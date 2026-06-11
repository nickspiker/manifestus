//! Generic dual-ring resilience wrapper over two [`Store`]s.
//!
//! Two files hold the same logical state. Writes go to both; reads come from the first healthy ring. If one ring dies mid-session (I/O error on write) it's dropped for the session and `degraded` flips so a UI can surface it. On open, the rings self-heal:
//!
//! - Missing ring → `Store::open_or_create` makes a fresh empty one → it has `anchor_seq == 0` → seq-heal copies the survivor's file over it.
//! - Torn-tail ring → `Store`'s own open-time truncation already repaired it → it just has a lower `anchor_seq` → same seq-heal path.
//! - Hard-unopenable ring (bad magic, permission denied) → attempt file copy from the survivor; if that fails too, run single-ring with `degraded` set.
//! - Both unopenable → error; vault is genuinely unrecoverable on this device.
//!
//! Seq-heal is a whole-file copy, not record replay: `Store` fsyncs every write so the on-disk bytes of the higher-seq ring are always a complete, valid store. Close both handles, `fs::copy`, reopen.

use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::record::EntryKey;
use crate::store::Store;

pub struct DualStore {
    rings: [Option<Store>; 2],
    paths: [PathBuf; 2],
    anchor_key: [u8; 32],
    degraded: bool,
}

impl DualStore {
    /// Open or create both rings, healing divergence. See module docs for the failure matrix.
    pub fn open_or_create(paths: [PathBuf; 2], anchor_key: &[u8; 32]) -> Result<Self> {
        let r0 = Store::open_or_create(&paths[0], anchor_key);
        let r1 = Store::open_or_create(&paths[1], anchor_key);

        let (rings, degraded) = match (r0, r1) {
            (Ok(a), Ok(b)) => Self::heal_if_diverged(a, b, &paths, anchor_key),
            (Ok(a), Err(_)) => Self::repair_into(a, 0, &paths, anchor_key),
            (Err(_), Ok(b)) => Self::repair_into(b, 1, &paths, anchor_key),
            (Err(e), Err(_)) => return Err(e),
        };

        Ok(Self {
            rings,
            paths,
            anchor_key: *anchor_key,
            degraded,
        })
    }

    /// Both rings opened. If their seqs match we're healthy; otherwise copy the higher-seq file over the lower and reopen it.
    fn heal_if_diverged(
        a: Store,
        b: Store,
        paths: &[PathBuf; 2],
        anchor_key: &[u8; 32],
    ) -> ([Option<Store>; 2], bool) {
        let (seq_a, seq_b) = (a.anchor_seq(), b.anchor_seq());
        if seq_a == seq_b {
            return ([Some(a), Some(b)], false);
        }
        let (src_idx, dst_idx) = if seq_a > seq_b { (0, 1) } else { (1, 0) };
        // Close both handles before copying so the destination file isn't held open.
        drop(a);
        drop(b);
        let healed = copy_and_open(&paths[src_idx], &paths[dst_idx], anchor_key);
        let survivor = Store::open_or_create(&paths[src_idx], anchor_key).ok();
        let degraded = healed.is_none() || survivor.is_none();
        let mut rings: [Option<Store>; 2] = [None, None];
        rings[src_idx] = survivor;
        rings[dst_idx] = healed;
        (rings, degraded)
    }

    /// One ring opened (`survivor` at index `survivor_idx`), the other hard-failed. Copy the survivor's file over the failed path and try again.
    fn repair_into(
        survivor: Store,
        survivor_idx: usize,
        paths: &[PathBuf; 2],
        anchor_key: &[u8; 32],
    ) -> ([Option<Store>; 2], bool) {
        let dst_idx = 1 - survivor_idx;
        // Remove whatever is blocking the destination (bad-magic file etc.); ignore failure — copy will surface it.
        let _ = std::fs::remove_file(&paths[dst_idx]);
        let healed = copy_and_open(&paths[survivor_idx], &paths[dst_idx], anchor_key);
        let mut rings: [Option<Store>; 2] = [None, None];
        rings[survivor_idx] = Some(survivor);
        rings[dst_idx] = healed;
        // Repair was needed — degraded regardless of whether it succeeded, so the session surfaces that something was wrong.
        (rings, true)
    }

    /// Insert or overwrite in both rings. Succeeds if at least one ring landed it; a ring that errors is dropped for the session and flips `degraded`.
    pub fn put(
        &mut self,
        entry_key: EntryKey,
        value: &[u8],
        type_tag: u8,
        expires_at: Option<i64>,
        now: i64,
    ) -> Result<()> {
        let mut any_ok = false;
        for i in 0..2 {
            let Some(store) = self.rings[i].as_mut() else {
                continue;
            };
            match store.put(entry_key, value, type_tag, expires_at, now) {
                Ok(()) => any_ok = true,
                Err(_) => {
                    self.rings[i] = None;
                    self.degraded = true;
                }
            }
        }
        if any_ok {
            Ok(())
        } else {
            Err(Error::Corrupt("both rings failed to accept write".into()))
        }
    }

    /// Read from the first healthy ring.
    pub fn get(&mut self, entry_key: &EntryKey) -> Result<Option<Vec<u8>>> {
        for i in 0..2 {
            if let Some(store) = self.rings[i].as_mut() {
                return store.get(entry_key);
            }
        }
        Err(Error::Corrupt("no readable ring".into()))
    }

    /// Tombstone in both rings. Same at-least-one semantics as `put`.
    pub fn delete(&mut self, entry_key: &EntryKey, now: i64) -> Result<()> {
        let mut any_ok = false;
        for i in 0..2 {
            let Some(store) = self.rings[i].as_mut() else {
                continue;
            };
            match store.delete(entry_key, now) {
                Ok(()) => any_ok = true,
                Err(_) => {
                    self.rings[i] = None;
                    self.degraded = true;
                }
            }
        }
        if any_ok {
            Ok(())
        } else {
            Err(Error::Corrupt("both rings failed to accept delete".into()))
        }
    }

    /// True if a ring needed repair on open or died mid-session. Sticky for the session.
    pub fn degraded(&self) -> bool {
        self.degraded
    }

    /// Live entry count from the first healthy ring.
    pub fn len(&self) -> usize {
        self.rings
            .iter()
            .flatten()
            .next()
            .map(|s| s.len())
            .unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Highest anchor_seq across healthy rings.
    pub fn anchor_seq(&self) -> u64 {
        self.rings
            .iter()
            .flatten()
            .map(|s| s.anchor_seq())
            .max()
            .unwrap_or(0)
    }

    pub fn paths(&self) -> &[PathBuf; 2] {
        &self.paths
    }

    /// Anchor key this store was opened with. Needed by callers that re-open or compact.
    pub fn anchor_key(&self) -> &[u8; 32] {
        &self.anchor_key
    }
}

fn copy_and_open(src: &Path, dst: &Path, anchor_key: &[u8; 32]) -> Option<Store> {
    if let Some(parent) = dst.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).ok();
        }
    }
    std::fs::copy(src, dst).ok()?;
    Store::open_or_create(dst, anchor_key).ok()
}
