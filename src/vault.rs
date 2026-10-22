//! The vault — spine + tract + HAMT composed into a crash-proof keyed object store. VAULT.md write path; host-profile resolutions in the README.
//!
//! Commit-per-write by default: `put`/`delete` return durable (a spine entry references the new state on at least one verified mirror). Everything between spine commits is provisional — orphans are reaped as garbage when their window retires.
//!
//! Open ladder (the genesis rule — README "Security posture"):
//! 1. Bootstrap: ring exponent from slot 0 (walks past killswitch damage).
//! 2. Found → head search → geometry/index/live-set from the committed head.
//! 3. Nothing → WHOLE-FILE scan, both mirrors. Any sealed block anywhere = real vault → refuse to format (recovery ladder, v0 refuses loudly). Zero sealed blocks = trash or fresh → zero the ring, genesis.

use crate::block::{BlockDev, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::hamt::{DanglingPointer, Delta, Hamt, StalePointer};
use crate::mirror::Mirror;
use crate::ring::{any_sealed_block, append_root, read_root, zero_ring, zero_ring_at, MapRef, Ring, RootEntry, SpineEntry, Tail, FENCE_K, ROOT_SLOTS};
use crate::tract::{Liveness, Staging, Tract};
use alloc::{format, vec::Vec};
use hashbrown::HashMap;

/// The vault's knowledge of what is referenced — the reap's liveness oracle and the append lap guard's.
///
/// A BITMAP (2026-10-22), one bit per tract position, set where the committed index references a block: nodes, leaves, furrows. It replaced a map of lba → hash, rebuilt at every open by walking every node and leaf; the bits are persisted as the live map (see [`crate::livemap`]) and an open reads a few pages of them instead. Position alone is the whole answer: a committed block's position is referenced at most once (appends never land on a referenced position — the lap guard), which the tree-only open already relied on for furrows.
/// `own` holds the positions of the committed live map's own pages and tables: live, never recorded in the bits (a map recording its own pages would never settle).
#[derive(Default)]
pub struct LiveSet {
    bits: Vec<u64>,
    count: u64,
    own: hashbrown::HashSet<u64>,
    /// Pages whose bits changed since the live map was last written.
    dirty: hashbrown::HashSet<usize>,
}

impl LiveSet {
    /// An empty set for a tract of `len` positions.
    pub fn with_len(len: u64) -> Self {
        Self { bits: alloc::vec![0; len.div_ceil(64) as usize], ..Self::default() }
    }

    fn ensure(&mut self, pos: u64) {
        let w = (pos / 64) as usize;
        if w >= self.bits.len() {
            self.bits.resize(w + 1, 0);
        }
    }

    pub fn get(&self, pos: u64) -> bool {
        self.bits.get((pos / 64) as usize).is_some_and(|w| w >> (pos % 64) & 1 == 1)
    }

    fn set(&mut self, pos: u64) {
        self.ensure(pos);
        let w = &mut self.bits[(pos / 64) as usize];
        if *w >> (pos % 64) & 1 == 0 {
            *w |= 1 << (pos % 64);
            self.count += 1;
            self.dirty.insert((pos / crate::livemap::PAGE_BITS) as usize);
        }
    }

    fn clear(&mut self, pos: u64) {
        if let Some(w) = self.bits.get_mut((pos / 64) as usize) {
            if *w >> (pos % 64) & 1 == 1 {
                *w &= !(1 << (pos % 64));
                self.count -= 1;
                self.dirty.insert((pos / crate::livemap::PAGE_BITS) as usize);
            }
        }
    }

    /// ADDED FIRST, THEN REMOVED — the order is load-bearing (field 2026-09-08, photon: "relocation repointed nothing for block at 2078" ×3 on a fresh phone vault mid history-restore). A block can be added AND retired inside ONE delta: a key written twice in the same batch appends leaf L1, then the rewrite retires L1 and appends L2. The tract is append-only within a delta: an lba is added at most once per commit and any removal of it comes after its add, so a block that is both ends removed.
    pub fn apply(&mut self, delta: Delta) {
        for (lba, _) in delta.added {
            self.set(lba);
        }
        for (lba, _) in delta.removed {
            self.clear(lba);
        }
    }

    /// The page words `delta` would leave in each page it touches — what the commit writes before the delta itself is applied (RAM moves only once the commit lands). Pages already dirty are included as they stand.
    fn preview(&self, delta: &Delta, len: u64, all: bool) -> alloc::collections::BTreeMap<usize, Vec<u64>> {
        let words = crate::livemap::PAGE_WORDS;
        let mut out: alloc::collections::BTreeMap<usize, Vec<u64>> = alloc::collections::BTreeMap::new();
        let mut page = |p: usize, out: &mut alloc::collections::BTreeMap<usize, Vec<u64>>| -> () {
            out.entry(p).or_insert_with(|| {
                let lo = p * words;
                let mut v = alloc::vec![0u64; words];
                for (i, w) in v.iter_mut().enumerate() {
                    *w = self.bits.get(lo + i).copied().unwrap_or(0);
                }
                v
            });
        };
        for &p in &self.dirty {
            page(p, &mut out);
        }
        if all {
            for p in 0..crate::livemap::pages_for(len) {
                page(p, &mut out);
            }
        }
        let set = |out: &mut alloc::collections::BTreeMap<usize, Vec<u64>>, pos: u64, on: bool| {
            let p = (pos / crate::livemap::PAGE_BITS) as usize;
            let i = ((pos % crate::livemap::PAGE_BITS) / 64) as usize;
            let w = &mut out.get_mut(&p).unwrap()[i];
            if on {
                *w |= 1 << (pos % 64);
            } else {
                *w &= !(1 << (pos % 64));
            }
        };
        for &(lba, _) in &delta.added {
            page((lba / crate::livemap::PAGE_BITS) as usize, &mut out);
            set(&mut out, lba, true);
        }
        for &(lba, _) in &delta.removed {
            page((lba / crate::livemap::PAGE_BITS) as usize, &mut out);
            set(&mut out, lba, false);
        }
        out.retain(|&p, _| p < crate::livemap::pages_for(len));
        out
    }

    /// The whole bitmap `delta` would leave, as bytes (bit i = byte i/8, bit i%8) — the inline map of a small tract.
    fn inline_after(&self, delta: &Delta, len: u64) -> Vec<u8> {
        let mut words: Vec<u64> = (0..len.div_ceil(64) as usize).map(|i| self.bits.get(i).copied().unwrap_or(0)).collect();
        for &(lba, _) in &delta.added {
            if let Some(w) = words.get_mut((lba / 64) as usize) {
                *w |= 1 << (lba % 64);
            }
        }
        for &(lba, _) in &delta.removed {
            if let Some(w) = words.get_mut((lba / 64) as usize) {
                *w &= !(1 << (lba % 64));
            }
        }
        let mut bytes: Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        bytes.truncate(len.div_ceil(8) as usize);
        bytes
    }

    /// A set from an inline map.
    fn from_inline(bytes: &[u8], len: u64) -> Result<Self> {
        if bytes.len() as u64 != len.div_ceil(8) {
            return Err(Error::Corrupt("inline live map length".into()));
        }
        let mut live = Self::with_len(len);
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut w = [0u8; 8];
            w[..chunk.len()].copy_from_slice(chunk);
            live.bits[i] = u64::from_le_bytes(w);
        }
        live.count = live.bits.iter().map(|w| w.count_ones() as u64).sum();
        Ok(live)
    }

    /// Mark a block live by position (open's walk; the reap's furrows).
    pub fn mark_referenced(&mut self, lba: u64) {
        self.set(lba);
    }

    /// Live positions: the bits plus the live map's own blocks.
    pub fn len(&self) -> usize {
        self.count as usize + self.own.len()
    }

    /// Blocks the live entries occupy. Display-grade, not accounting-grade.
    pub fn live_blocks(&self) -> u64 {
        self.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Every live position, bits and own.
    pub fn positions(&self) -> impl Iterator<Item = u64> + '_ {
        self.bits
            .iter()
            .enumerate()
            .flat_map(|(i, &w)| (0..64u64).filter(move |b| w >> b & 1 == 1).map(move |b| i as u64 * 64 + b))
            .chain(self.own.iter().copied())
    }

    /// Positions the bits hold (the index's blocks), without the map's own.
    pub fn indexed(&self) -> impl Iterator<Item = u64> + '_ {
        self.bits.iter().enumerate().flat_map(|(i, &w)| (0..64u64).filter(move |b| w >> b & 1 == 1).map(move |b| i as u64 * 64 + b))
    }

    /// Distance from tract position `from` to the nearest live position at or after it, wrapping; `len` when nothing is live.
    fn clean_run_from(&self, from: u64, len: u64) -> u64 {
        let mut best = len;
        for &o in &self.own {
            best = best.min((o + len - from) % len);
        }
        // Word scan from `from` to the end, then from 0 back to `from`.
        let scan = |lo: u64, hi: u64| -> Option<u64> {
            let mut p = lo;
            while p < hi {
                let w = self.bits.get((p / 64) as usize).copied().unwrap_or(0) >> (p % 64);
                if w != 0 {
                    let q = p + w.trailing_zeros() as u64;
                    return (q < hi).then_some(q);
                }
                p = (p / 64 + 1) * 64;
            }
            None
        };
        if let Some(q) = scan(from, len) {
            best = best.min(q - from);
        } else if let Some(q) = scan(0, from) {
            best = best.min(q + len - from);
        }
        best
    }
}

impl Liveness for LiveSet {
    fn is_live(&self, lba: u64, _hp: &[u8; 32]) -> bool {
        self.get(lba) || self.own.contains(&lba)
    }
    fn is_referenced(&self, lba: u64) -> bool {
        self.get(lba) || self.own.contains(&lba)
    }
    fn is_foreign(&self, lba: u64) -> bool {
        self.own.contains(&lba)
    }
}

/// What `Vault::open_repairing` pruned: stale pointers (target zeroed — the deleted-but-never-unlinked legal state, no data behind them) and dangling pointers (target reused/corrupt — the referenced value is LOST).
#[derive(Debug, Default)]
pub struct RepairReport {
    pub stale: Vec<StalePointer>,
    pub dangling: Vec<DanglingPointer>,
}

/// The vault's tracts stage their appends for the commit's single write (see [`Staging`]).
fn staged() -> Staging {
    Staging::on()
}

/// The longest run a commit writes under the same flush as its entry (256 KiB): longer runs are flushed ahead of the entry, so the torn-commit check at open never reads more than this.
const TAIL_MAX_BLOCKS: usize = 1 << 6;

/// Clean blocks a reap holds back for its retiring commit's own appends: the index path the relocations rewrote, and the live map's page and table.
const COMMIT_RESERVE: u64 = 8;

/// Proactive reap trigger: dead > 25% of the tract → one window after the commit.
/// Window size scales with the tract (len/64, floor 16) so huge values fragment into at most ~64 runs crossing a full lap — far under the extent leaf's capacity.
const REAP_WINDOW_MIN: u64 = 1 << 4;

/// The idle-edge reclaim's window ceiling (1 MiB of blocks): small enough that an op arriving mid-step barely waits, large enough that a lap is a few hundred steps.
const RECLAIM_WINDOW_MAX: u64 = 1 << 8;

/// What one [`Vault::reclaim_ahead`] step found or did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reclaim {
    /// Clean space is at target and dead space under the inline trigger: nothing to do.
    Comfortable,
    /// One window reaped and committed; call again while still idle.
    Reaped,
    /// Short of clean space with more than three quarters live — reaping cannot pay its way, growth is the honest fix, and the choice is the embedder's.
    LiveHeavy,
    /// Short, but no window can stage right now (clean or fence too tight); the next commit changes that.
    Stuck,
}

/// The engine's physique for a stats page: block-denominated, display-grade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultStats {
    /// Spine generation at the committed head — how many commits this vault has lived.
    pub generation: u64,
    /// Tract capacity in blocks.
    pub tract_blocks: u64,
    /// Absolute append position (monotonic, wraps modulo the tract for the physical block).
    pub plow: u64,
    /// Absolute reap position — plow − reap = occupied blocks.
    pub reap: u64,
    /// Live logical entries (keys the HAMT answers for).
    pub live_entries: u64,
    /// Blocks those entries pin (coarse for tree-only referenced runs).
    pub live_blocks: u64,
    /// Bytes per block.
    pub block_bytes: u64,
}

pub struct Vault<A: BlockDev, B: BlockDev> {
    ring: Ring<A, B>,
    tract: Tract,
    hamt: Hamt,
    live: LiveSet,
    /// Migrating profile (RING.md "Migrating Rings"): the newest root entry. None on the legacy/host layout (spine fixed at block 0, R = ∞).
    root: Option<RootEntry>,
    /// What delete physically does (see [`crate::DeletePolicy`]) — a required open parameter, stored for the life of the handle.
    policy: crate::DeletePolicy,
    /// A reaped window awaiting its retiring commit: the cursor value the reap reached, held back from `tract.reap` until that commit's flush has landed.
    /// The window's originals are what the COMMITTED head still references, so counting them as clean before the retiring entry exists let the flush plow straight into them whenever the fence was waived (rescue) — the lap guard caught it, which is the confession Emma's phone logged as "LIVE-LAP AVERTED at lba 19" inside a 3.3 s commit, and the TractFull it raised sent the put into a full grow barrier (fuzz repro 2026-10-21).
    pending_reap: Option<u64>,
    /// Where the committed live map's blocks are, and whether the next commit must write it whole.
    lmap: MapLayout,
    /// The next commit writes no live map: grow's, the spine-only move no fence may refuse — appending a whole map into the fresh space would be fenced by the generations before it. Its entry names no map; the commit after it writes one whole.
    map_off: bool,
    /// Whether this handle's open read the live map (rather than walking the index).
    from_map: bool,
    /// Where the idle scrub resumes: the next tract position it checks.
    scrub_at: u64,
}

/// What one [`Vault::scrub_step`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Scrubbed {
    /// Live positions checked on both devices.
    pub checked: u64,
    /// Blocks rewritten from the other device.
    pub repaired: u64,
    /// Blocks bad on both devices — nothing to heal them from.
    pub lost: u64,
    /// The step reached the end of the tract; the next starts over.
    pub lap_done: bool,
}

/// Where the committed live map's blocks are (see [`crate::livemap`]).
#[derive(Default, Clone)]
struct MapLayout {
    root: Option<crate::livemap::Ptr>,
    /// Page pointers by page index.
    pages: Vec<Option<crate::livemap::Ptr>>,
    /// Level-1 tables, when the map has two levels (more than one table's worth of pages).
    tables: Vec<crate::livemap::Ptr>,
    /// Write every page and table at the next commit: no map yet (an older vault, a repair), a grow, or a reap window crossed the map's own blocks.
    rewrite: bool,
}

impl MapLayout {
    fn whole() -> Self {
        Self { rewrite: true, ..Self::default() }
    }
}

/// Read a block and check it against the hash its parent recorded.
fn read_sealed<A: BlockDev, B: BlockDev>(mirror: &mut Mirror<A, B>, tract: &Tract, ptr: crate::livemap::Ptr) -> Result<crate::block::Block> {
    let mut buf = ZERO_BLOCK;
    tract.read(mirror, ptr.1, &mut buf)?;
    if crate::tract::sealed_hp(&buf) != Some(ptr.0) {
        return Err(Error::Seal);
    }
    Ok(buf)
}

/// Load the committed live map named by `root`: the tables, then every page in one run of reads, each checked against its parent's hash. The map's own block positions come back in the set's `own`.
fn load_livemap<A: BlockDev, B: BlockDev>(mirror: &mut Mirror<A, B>, tract: &Tract, root: crate::livemap::Ptr) -> Result<(LiveSet, MapLayout)> {
    use crate::livemap::{decode, pages_for, Doc, PAGE_WORDS};
    let Doc::Table { level, len, children } = decode(&read_sealed(mirror, tract, root)?)? else {
        return Err(Error::Corrupt("live map root is not a table".into()));
    };
    if len != tract.len {
        return Err(Error::Corrupt(format!("live map for a tract of {len}, tract is {}", tract.len)));
    }
    let mut layout = MapLayout { root: Some(root), ..MapLayout::default() };
    let mut page_ptrs = Vec::new();
    match level {
        1 => page_ptrs = children,
        2 => {
            for t in children {
                let Doc::Table { level: 1, children, .. } = decode(&read_sealed(mirror, tract, t)?)? else {
                    return Err(Error::Corrupt("live map sub-table is not level 1".into()));
                };
                layout.tables.push(t);
                page_ptrs.extend(children);
            }
        }
        _ => return Err(Error::Corrupt("live map table level".into())),
    }
    if page_ptrs.len() != pages_for(len) {
        return Err(Error::Corrupt("live map page count".into()));
    }
    let positions: Vec<u64> = page_ptrs.iter().map(|p| p.1).collect();
    let blocks = tract.read_positions(mirror, &positions)?;
    let mut live = LiveSet::with_len(len);
    for (i, (b, ptr)) in blocks.iter().zip(&page_ptrs).enumerate() {
        if crate::tract::sealed_hp(b) != Some(ptr.0) {
            return Err(Error::Seal);
        }
        let Doc::Page { index, words } = decode(b)? else {
            return Err(Error::Corrupt("live map page".into()));
        };
        if index as usize != i || words.len() != PAGE_WORDS {
            return Err(Error::Corrupt("live map page index".into()));
        }
        let lo = i * PAGE_WORDS;
        for (j, w) in words.into_iter().enumerate() {
            if lo + j < live.bits.len() {
                live.bits[lo + j] = w;
            } else if w != 0 {
                return Err(Error::Corrupt("live map bit past the tract".into()));
            }
        }
    }
    live.count = live.bits.iter().map(|w| w.count_ones() as u64).sum();
    live.own.insert(root.1);
    live.own.extend(layout.tables.iter().map(|t| t.1));
    live.own.extend(positions);
    layout.pages = page_ptrs.into_iter().map(Some).collect();
    Ok((live, layout))
}

impl<A: BlockDev, B: BlockDev> Vault<A, B> {
    /// Open an existing vault or genesis a fresh one, per the open ladder above. `default_tract_blocks` sizes genesis only — an existing vault's geometry comes from its head entry, never from arguments.
    pub fn open(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64, policy: crate::DeletePolicy) -> Result<Self> {
        // Migrating layout first: a root entry at blocks [0, 4) names the spine's residence.
        {
            let (a, b) = mirror.devices();
            let root = match (a, b) {
                (Some(a), _) => read_root(a)?,
                (None, Some(b)) => read_root(b)?,
                (None, None) => None,
            };
            if let Some(root) = root {
                return Self::resume_migrating(mirror, root, policy);
            }
        }
        match Ring::bootstrap_n(&mut mirror)? {
            Some(r) => Self::resume(mirror, r, policy),
            None => {
                // Nothing bootstrappable: trash-vs-real decided by the WHOLE file, both sides — a valid block is its own proof (2^-256 false positive).
                let (a, b) = mirror.devices();
                let mut found = false;
                if let Some(a) = a {
                    found |= any_sealed_block(a)?;
                }
                if let Some(b) = b {
                    found |= any_sealed_block(b)?;
                }
                if found {
                    return Err(Error::Corrupt(
                        "sealed blocks exist but no spine bootstraps: real vault needing recovery — refusing to format".into(),
                    ));
                }
                Self::genesis(mirror, ring_log2, now, policy)
            }
        }
    }

    fn genesis(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64, policy: crate::DeletePolicy) -> Result<Self> {
        let n = 1u64 << ring_log2;
        let total = mirror.block_count();
        if total <= n {
            return Err(Error::Corrupt(format!(
                "device too small: {total} blocks ≤ ring {n}"
            )));
        }
        zero_ring(&mut mirror, ring_log2)?;
        let mut ring = Ring::open(mirror, ring_log2)?;
        let tract_blocks = total - n;
        let entry = SpineEntry {
            gen: 0,
            prev_hash: [0u8; 32],
            ring_log2,
            tract_blocks,
            hamt_hash: [0u8; 32],
            hamt_lba: 0,
            plow: 0,
            reap: Some(0),
            live: 0,
            eagle_time: now,
            tail: None,
            livemap: None,
        };
        ring.append(&entry)?;
        let tract = Tract {
            base: n,
            len: tract_blocks,
            plow: 0,
            reap: 0,
            fence_limit: None,
            staging: staged(),
        };
        Ok(Self {
            ring,
            tract,
            hamt: Hamt::empty(),
            live: LiveSet::default(),
            root: None,
            policy,
            pending_reap: None,
            lmap: MapLayout::whole(),
            map_off: false,
            from_map: false,
            scrub_at: 0,
        })
    }

    /// Genesis a MIGRATING vault (RING.md "Migrating Rings"): root ring at block 0, a band of `residences` spine residences after it, tract beyond the band. The spine hops to the next residence every `residency` rotations. Resuming an existing vault ignores these parameters — the layout is self-describing.
    pub fn open_migrating(
        mut mirror: Mirror<A, B>,
        ring_log2: u8,
        residences: u64,
        residency: u64,
        now: i64,
        policy: crate::DeletePolicy,
    ) -> Result<Self> {
        {
            let (a, b) = mirror.devices();
            let root = match (a, b) {
                (Some(a), _) => read_root(a)?,
                (None, Some(b)) => read_root(b)?,
                (None, None) => None,
            };
            if let Some(root) = root {
                return Self::resume_migrating(mirror, root, policy);
            }
        }
        if Ring::bootstrap_n(&mut mirror)?.is_some() {
            return Err(Error::Corrupt(
                "legacy fixed-ring vault: cannot adopt the migrating layout in place".into(),
            ));
        }
        {
            let (a, b) = mirror.devices();
            let mut found = false;
            if let Some(a) = a {
                found |= any_sealed_block(a)?;
            }
            if let Some(b) = b {
                found |= any_sealed_block(b)?;
            }
            if found {
                return Err(Error::Corrupt(
                    "sealed blocks exist but nothing bootstraps: real vault needing recovery — refusing to format".into(),
                ));
            }
        }
        if residences < 2 || residency == 0 {
            return Err(Error::Corrupt("migrating layout needs ≥2 residences and residency ≥1".into()));
        }
        let n = 1u64 << ring_log2;
        let tract_base = ROOT_SLOTS + residences * n;
        let total = mirror.block_count();
        if total <= tract_base {
            return Err(Error::Corrupt(format!(
                "device too small: {total} blocks ≤ root + band {tract_base}"
            )));
        }
        // Root slots + first residence, then the root entry naming it, then spine genesis.
        for slot in 0..ROOT_SLOTS {
            mirror.write_verified(slot, &ZERO_BLOCK)?;
        }
        zero_ring_at(&mut mirror, ring_log2, ROOT_SLOTS)?;
        let root = RootEntry {
            gen: 0,
            prev_hash: [0u8; 32],
            ring_log2,
            at: ROOT_SLOTS,
            was: ROOT_SLOTS,
            since: 0,
            residences,
            residency,
            eagle_time: now,
        };
        append_root(&mut mirror, &root)?;
        let mut ring = Ring::open_at(mirror, ring_log2, ROOT_SLOTS)?;
        let tract_blocks = total - tract_base;
        let entry = SpineEntry {
            gen: 0,
            prev_hash: [0u8; 32],
            ring_log2,
            tract_blocks,
            hamt_hash: [0u8; 32],
            hamt_lba: 0,
            plow: 0,
            reap: Some(0),
            live: 0,
            eagle_time: now,
            tail: None,
            livemap: None,
        };
        ring.append(&entry)?;
        let tract = Tract {
            base: tract_base,
            len: tract_blocks,
            plow: 0,
            reap: 0,
            fence_limit: None,
            staging: staged(),
        };
        Ok(Self {
            ring,
            tract,
            hamt: Hamt::empty(),
            live: LiveSet::default(),
            root: Some(root),
            policy,
            pending_reap: None,
            lmap: MapLayout::whole(),
            map_off: false,
            from_map: false,
            scrub_at: 0,
        })
    }

    /// Open with DANGLING-POINTER REPAIR — the recovery entry point for vaults bricked by the pre-fix tombstone bug (a fast-deleted key's pointer surviving into a reused slot). Walks the committed index tolerantly, prunes every pointer whose target is stale (zeroed) or dangling (reused/corrupt), COMMITS the pruned index, and reports exactly what was dropped. The values behind dangling pointers are unrecoverable by construction (their blocks were overwritten); everything else is preserved byte-for-byte. NEVER the default open: a strict open must keep refusing damage loudly — this is the explicitly-invoked salvage.
    pub fn open_repairing(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64, policy: crate::DeletePolicy) -> Result<(Self, RepairReport)> {
        let mut report = RepairReport::default();
        {
            let (a, b) = mirror.devices();
            let root = match (a, b) {
                (Some(a), _) => read_root(a)?,
                (None, Some(b)) => read_root(b)?,
                (None, None) => None,
            };
            if let Some(root) = root {
                let mut ring = Ring::open_at(mirror, root.ring_log2, root.at)?;
                if ring.head().is_none() && root.was != root.at {
                    let mirror = ring.into_mirror();
                    ring = Ring::open_at(mirror, root.ring_log2, root.was)?;
                }
                let tract_base = ROOT_SLOTS + root.residences * (1u64 << root.ring_log2);
                let mut vault = Self::resume_common_with(ring, tract_base, Some(root), Some(&mut report), policy)?;
                vault.commit(now)?;
                return Ok((vault, report));
            }
        }
        let Some(r) = Ring::bootstrap_n(&mut mirror)? else {
            return Err(Error::Corrupt("nothing bootstraps: not a vault (repair needs an existing spine)".into()));
        };
        let ring = Ring::open(mirror, r)?;
        let n = 1u64 << r;
        let _ = ring_log2;
        let mut vault = Self::resume_common_with(ring, n, None, Some(&mut report), policy)?;
        vault.commit(now)?;
        Ok((vault, report))
    }

    /// Resume a migrating vault: spine at the root's current residence, falling back to the previous residence when the current one is empty (crash between the root update and the first commit at the new base — the A/B pattern).
    fn resume_migrating(mirror: Mirror<A, B>, root: RootEntry, policy: crate::DeletePolicy) -> Result<Self> {
        let mut ring = Ring::open_at(mirror, root.ring_log2, root.at)?;
        if ring.head().is_none() && root.was != root.at {
            let mirror = ring.into_mirror();
            ring = Ring::open_at(mirror, root.ring_log2, root.was)?;
        }
        let tract_base = ROOT_SLOTS + root.residences * (1u64 << root.ring_log2);
        Self::resume_common(ring, tract_base, Some(root), policy)
    }

    fn resume(mirror: Mirror<A, B>, ring_log2: u8, policy: crate::DeletePolicy) -> Result<Self> {
        let ring = Ring::open(mirror, ring_log2)?;
        let n = 1u64 << ring_log2;
        Self::resume_common(ring, n, None, policy)
    }

    fn resume_common(ring: Ring<A, B>, tract_base: u64, root: Option<RootEntry>, policy: crate::DeletePolicy) -> Result<Self> {
        Self::resume_common_with(ring, tract_base, root, None, policy)
    }

    fn resume_common_with(mut ring: Ring<A, B>, tract_base: u64, root: Option<RootEntry>, repair: Option<&mut RepairReport>, policy: crate::DeletePolicy) -> Result<Self> {
        let mut head = ring
            .head()
            .ok_or_else(|| Error::Corrupt("bootstrap found entries but head search found none".into()))?
            .clone();
        // A torn commit: its entry landed, some of its run did not. The generation before it is whole (its own commit finished flushed and verified before this one began, and this one's appends stayed inside the fence), so the vault opens there; the next commit takes the torn entry's slot.
        while let Some(t) = head.tail {
            let (a, b) = ring.mirror().devices();
            let intact = match (a, b) {
                (Some(a), _) => tail_intact(a, tract_base, head.tract_blocks, &t)?,
                (None, Some(b)) => tail_intact(b, tract_base, head.tract_blocks, &t)?,
                (None, None) => true,
            };
            if intact {
                break;
            }
            ring.rewind_head()?;
            ring.mirror().emit(crate::events::StorageEvent::TornCommit { gen: head.gen });
            head = ring.head().ok_or_else(|| Error::Corrupt("rewind left no head".into()))?.clone();
        }
        let mut tract = Tract {
            base: tract_base,
            len: head.tract_blocks,
            plow: head.plow,
            reap: 0, // derived below, once the live set is known
            fence_limit: None,
            staging: staged(),
        };
        // Host-only truncation guard: the device must hold the committed geometry. The fs is a witness, never the authority.
        let need = tract_base + head.tract_blocks;
        if ring.mirror().block_count() < need {
            return Err(Error::Corrupt(format!(
                "device truncated: committed geometry needs {need} blocks"
            )));
        }
        let mut hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        // THE LIVE MAP (2026-10-22): a head that names one opens by reading it — a few blocks — and never walks the index. A missing or unreadable map (an older vault, damage) falls back to the walk below, and the next commit writes the map whole.
        if repair.is_none() {
            let loaded = match &head.livemap {
                Some(MapRef::Inline(bytes)) => LiveSet::from_inline(bytes, tract.len).ok().map(|l| (l, MapLayout::whole())),
                Some(MapRef::Root(h, at)) => load_livemap(ring.mirror(), &tract, (*h, *at)).ok(),
                None => None,
            };
            if loaded.is_none() && head.livemap.is_some() {
                ring.mirror().emit(crate::events::StorageEvent::LiveMapFallback);
            }
            {
                if let Some((live, lmap)) = loaded {
                    tract.reap = derive_reap(tract.plow, tract.len, &live);
                    let fences = ring.recent_fences(FENCE_K)?;
                    tract.fence_limit = fence_from(&fences);
                    let mut v = Self { ring, tract, hamt, live, root, policy, pending_reap: None, lmap, map_off: false, from_map: true, scrub_at: 0 };
                    v.live.dirty.clear();
                    v.probe_wedge(head.eagle_time + 1, true);
                    return Ok(v);
                }
            }
        }
        let mut live_blocks = Vec::new();
        let mut stale = Vec::new();
        let mut dangling = Vec::new();
        // TREE-ONLY OPEN (2026-09-12): the ordinary open reads the INDEX — nodes and leaves — and marks each leaf's furrows and extent runs live by position without reading them. It used to read every data block of every value to take its seal hash (a full read of the vault: 6 s on a phone with a season of kept waves, growing with each one). A repair open still walks everything: that one exists to find what is broken.
        let mut referenced: Vec<u64> = Vec::new();
        match repair {
            None => hamt.walk_tree_collect(ring.mirror(), &tract, &mut live_blocks, &mut referenced, &mut stale)?,
            Some(_) => hamt.walk_live_repair(ring.mirror(), &tract, &mut live_blocks, &mut stale, &mut dangling)?,
        }
        // Pre-fix vaults (and a crash between a delete's zero and its retiring commit) leave stale pointers at zeroed slots. They are time bombs: the reap retires the slot, the plow reuses it, and the pointer flips from "reads as deleted" to Seal-on-open. Unlink them now, in RAM — the next commit persists the pruned index; a session that never commits changes nothing.
        for s in &stale {
            hamt.prune(ring.mirror(), &tract, &s.route, (s.hash, s.lba))?;
        }
        for d in &dangling {
            hamt.prune(ring.mirror(), &tract, &d.route, (d.hash, d.lba))?;
        }
        let pruned_any = !stale.is_empty() || !dangling.is_empty();
        let mut live = LiveSet::with_len(tract.len);
        for (lba, _) in live_blocks {
            live.mark_referenced(lba);
        }
        for lba in referenced {
            live.mark_referenced(lba);
        }
        // The reap is DERIVED, not trusted: the maximal monotone value whose clean region [plow, reap + len) is verifiably live-free right now. Works identically for legacy (pre-reap) vaults, whose mixed layout simply derives near-zero clean space — ordinary cleaning then migrates them, no format break.
        tract.reap = derive_reap(tract.plow, tract.len, &live);
        let fences = ring.recent_fences(FENCE_K)?;
        tract.fence_limit = fence_from(&fences);
        // Rescue commits stamp head-time+1 — resume has no wall clock, and monotonicity over the head is all the spine asks of a generation's eagle_time.
        let rescue_now = ring.head().map(|h| h.eagle_time + 1).unwrap_or(1);
        let migrating = root.is_some();
        let mut v = Self {
            ring,
            tract,
            hamt,
            live,
            root,
            policy,
            pending_reap: None,
            lmap: MapLayout::whole(),
            map_off: false,
            from_map: false,
            scrub_at: 0,
        };
        // REPAIR COMMIT FIRST (field 2026-08-25, the boot that re-pruned the same 84 danglings forever): every rescue's opening move is rolling the index back to the COMMITTED head (the survivor law), so prunes still in RAM evaporate the moment the wedge probe below fires — and a broken vault is USUALLY wedge-shaped, which is why the repair open kept "succeeding" while the disk never changed. Commit the pruned index NOW so the pruned head is the one every later rollback restores. A refused commit (a broken vault is usually FULL-shaped too) gets one grow — and because grow is a barrier that reloads the committed (unpruned) head, the recorded routes are re-pruned before the retry. If even that fails, skip the probe: the prunes then survive in RAM until the session's first successful commit lands them.
        let mut probe_allowed = true;
        if pruned_any {
            // FENCE WAIVER (rescue's own privilege, same reasoning): the fence preserves rollback to older generations — but the generations a repairing vault would roll back TO are the broken ones being replaced, and the commit's heartbeat ladder can't raise a fence whose head still carries the pre-repair geometry. Waive, land, recompute from the ring.
            v.tract.fence_limit = None;
            let mut committed = v.commit(rescue_now).is_ok();
            if !committed {
                // A broken vault is usually FULL-shaped too — grow WITHOUT the barrier reload (the reload would resurrect the danglings and then fail Seal on them); the pruned index rides across and the grow's own commit lands it.
                committed = v.grow_preserving(v.tract.len * 2, rescue_now + 1).is_ok();
            }
            let fences = v.ring.recent_fences(FENCE_K)?;
            v.tract.fence_limit = fence_from(&fences);
            if !committed {
                probe_allowed = false;
            }
        }
        if let Some(report) = repair {
            report.stale = stale;
            report.dangling = dangling;
        }
        let _ = migrating;
        v.probe_wedge(rescue_now, probe_allowed);
        Ok(v)
    }

    /// WEDGE PROBE (field 2026-08-21/23/24): a head restored with less budget than one reap window + reserve is the fence deadlock arriving — nothing the ladders do can slide it. Rescue NOW, before any caller writes; best-effort, because a genuinely live-full tract must still open readable (the wedged field boxes served every boot load). NEVER on a migrating-era vault (root present): its legacy mixed layout derives near-zero clean space and looks wedge-shaped by definition — the migration sweep owns that state.
    fn probe_wedge(&mut self, rescue_now: i64, allowed: bool) {
        let wedged = allowed
            && self.root.is_none()
            && self.tract.fence_limit.map_or(false, |l| {
                l.saturating_sub(self.tract.plow) < self.reap_window() + 8
            });
        if wedged {
            // Dead-heavy → the rescue reaps its way out; live-full (rescue says TractFull) → grow, the spine-only move no fence refuses. Best-effort both ways: a vault that can't heal still opens readable.
            if let Err(Error::TractFull) = self.rescue(rescue_now) {
                let _ = self.grow(self.tract.len * 2, rescue_now);
            }
        }
    }

    // ======================================================================== KV API =================================================================

    /// Every live entry key — the enumeration a full-fidelity migration walks (`for k in live_keys { dest.put(k, src.get(k)) }`). Committed state only.
    pub fn live_keys(&mut self) -> Result<Vec<[u8; 32]>> {
        let Self { ring, tract, hamt, .. } = self;
        let mut out = Vec::new();
        hamt.walk_keys(ring.mirror(), tract, &mut out)?;
        Ok(out)
    }

    pub fn get(&mut self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let Self { ring, tract, hamt, .. } = self;
        hamt.lookup(ring.mirror(), tract, key)
    }

    /// Insert/overwrite, durable on return (commit-per-write). A refused append has no side effects, so the ladder simply makes room and retries: Fenced → commit generations to slide the K-window (heartbeats inside commit if the flush itself is fenced); TractFull → reap windows until space exists. Only a tract that stays full after a complete reap lap surfaces TractFull to the caller — grow or refuse.
    /// True iff `value` is already the COMMITTED value at `key` — the identical-overwrite skip's gate. Committed matters: matching a provisional copy and skipping would claim durability a crash could revoke. One index read against ~1s of flushes; same-value churn (fstate ping-pong, phonebook re-adoption) was pure plow pressure toward the fence cliff (field 2026-08-24/25).
    fn holds_committed(&mut self, key: &[u8; 32], value: &[u8]) -> Result<bool> {
        let leaf = {
            let Self { ring, tract, hamt, .. } = self;
            hamt.find_leaf(ring.mirror(), tract, key)?
        };
        let Some((lba, hash)) = leaf else {
            return Ok(false);
        };
        let _ = hash;
        if !self.live.get(lba) {
            return Ok(false);
        }
        // A committed value that can no longer be READ is a value the vault does not hold — full stop. Field 2026-08-25: a reused furrow passes the repair walk (its own seal is valid, just someone else's content), then this get propagated the Seal and killed every subsequent put of that key BEFORE its write — the one operation that would have healed the key by overwriting it. Unreadable = not held = let the put proceed.
        match self.get(key) {
            Ok(stored) => Ok(stored.as_deref() == Some(value)),
            Err(Error::Seal) | Err(Error::Corrupt(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    pub fn put(&mut self, key: &[u8; 32], value: &[u8], now: i64) -> Result<()> {
        // A one-entry batch: the identical-overwrite skip, the ladder, and the grow-and-replay law (a commit whose FLUSH finds no room surfaces TractFull raw; we still hold the item, so the barrier grows and the item replays from pristine) all live in apply_batch.
        self.apply_batch(&[(key, Some(value))], now)
    }

    /// The put ladder WITHOUT the final commit — the entry sits provisional in the arena until the next [`commit`](Self::commit) (which [`put`](Self::put) and [`put_batch`](Self::put_batch) supply). A Fenced retry still commits mid-ladder (that IS how the fence rises), so a tight window degrades toward commit-per-write, never past it.
    fn put_no_commit(&mut self, key: &[u8; 32], value: &[u8], now: i64) -> Result<()> {
        // One growth per call: repeated doubling inside the retry loop would balloon the device on a vault whose real ailment is something else. The growth verdict is BOUND EXHAUSTION, not any single error: a ladder that reaped and rescued a full lap and still never landed the put is a working set that has outgrown its tract (field-shaped test, 2026-08-25: a 64-block tract thrashed at budget≈0 forever because every rescue helped a little and nothing ever concluded "too small").
        let mut grew = false;
        loop {
        // Bound: cleaning advances the reap every iteration, so a full lap of windows plus the fence ladder is guaranteed to terminate.
        for _ in 0..(FENCE_K + 3 + (self.tract.len / self.reap_window()) + 8) {
            let attempt = {
                let Self { ring, tract, hamt, live, .. } = self;
                hamt.put(ring.mirror(), tract, live, key, value)
            };
            match attempt {
                Ok(()) => return Ok(()),                Err(Error::Fenced(_)) => {
                    // Slides old entries out of the K-window → fence rises. A commit that is ITSELF fenced past the heartbeat ladder is the terminal deadlock — the rescue is the exit, but ONLY against a pristine index: the field's 214 lost blocks (2026-08-24) were relocations whose repoint descents hunted pointers thru THIS put's own half-mutated arena and missed silently. Roll the in-flight put back to the committed root (its provisional appends become orphans a later window reaps), rescue clean, and let the loop retry the put from scratch.
                    if let Err(Error::Fenced(_)) = self.commit(now) {
                        self.rollback_to_head(now, true)?;
                        match self.rescue(now) {
                            Ok(_) => {}
                            Err(Error::TractFull) if !grew => {
                                self.grow_in_ladder(now)?;
                                grew = true;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                Err(Error::TractFull) => {
                    // The ordinary reap first; when IT can't move (fence-clamped or airlocked), the same rescue ladder as the Fenced arm — physical fullness and fence exhaustion are one disease at the terminal stage, and this arm returning bare TractFull was the last way churn could still die (the new-law test caught it).
                    if !self.reap_one_window(now)? {
                        self.rollback_to_head(now, false)?;
                        match self.rescue(now) {
                            Ok(_) => {}
                            Err(Error::TractFull) if !grew => {
                                self.grow_in_ladder(now)?;
                                grew = true;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                Err(e) => return Err(e),
            }
        }
        if grew {
            return Err(Error::TractFull);
        }
        self.grow_in_ladder(now)?;
        grew = true;
        }
    }

    /// GROUP COMMIT: insert/overwrite MANY entries, durable on return, under ONE spine commit instead of one per write. The commit's flush is the dominant per-op cost in the field (~900ms per put on a busy BTRFS desktop, SIZE-INDEPENDENT — 53 bytes cost the same as 22KB, 2026-08-21), and callers arrive in bursts (kete's librarian drains a queue): N puts under one commit turn N flushes into one. Failure is all-or-nothing from the caller's view — no batch entry is spine-referenced until the single commit lands (a mid-batch Fenced heartbeat-commit can land earlier entries early, which is harmless: durability sooner, never later).
    pub fn put_batch(&mut self, items: &[(&[u8; 32], &[u8])], now: i64) -> Result<()> {
        // apply_batch IS this with every op a put: one item pass, one ladder, one replay law.
        // The old upfront identical-overwrite filter checked every entry against the committed index before any landed, so a key written twice whose LATER value matched the committed one dropped that write and left the earlier value in place.
        let ops: Vec<(&[u8; 32], Option<&[u8]>)> = items.iter().map(|&(key, value)| (key, Some(value))).collect();
        self.apply_batch(&ops, now)
    }

    /// The put ladder's own grow — a barrier that reloads the committed head and discards the arena, so it may run only while the arena holds nothing but this put's failed attempts.
    /// With earlier batch entries still uncommitted it surfaces TractFull instead: the batch callers grow and replay every entry they hold, where this grow would have dropped them while the batch reported success.
    fn grow_in_ladder(&mut self, now: i64) -> Result<()> {
        if self.hamt.has_uncommitted() {
            return Err(Error::TractFull);
        }
        self.grow(self.tract.len * 2, now)
    }

    /// Roll the in-flight index back to the committed head so the rescue works against a pristine index — but NEVER over uncommitted batch work.
    /// Earlier entries of the same batch live only in the arena: discarding them here while apply_batch went on to report success was silent loss (fuzz repro 2026-10-21: an entry the batch acknowledged read back absent).
    /// Land them first; when that commit cannot land (or `commit_failed` says one just didn't), surface TractFull, whose caller law (put_batch/apply_batch replay, kete's apply_growing) is grow-and-replay with every item still in hand.
    fn rollback_to_head(&mut self, now: i64, commit_failed: bool) -> Result<()> {
        if self.hamt.has_uncommitted() {
            if commit_failed {
                return Err(Error::TractFull);
            }
            match self.commit(now) {
                Ok(()) => {}
                Err(Error::TractFull) | Err(Error::Fenced(_)) => return Err(Error::TractFull),
                Err(e) => return Err(e),
            }
        }
        let (h, l) = {
            let head = self
                .ring
                .head()
                .ok_or_else(|| Error::Corrupt("rescue on pre-genesis vault".into()))?;
            (head.hamt_hash, head.hamt_lba)
        };
        self.hamt.reset_to(h, l);
        self.pending_reap = None;
        Ok(())
    }

    /// The fence deadlock's exit for a BATCH: reload the committed head (discarding the provisional arena — the caller still holds every item and replays), then the same rescue ladder as put()'s Fenced arm, growing once if the rescue itself finds the tract genuinely full.
    fn rescue_from_committed_head(&mut self, now: i64) -> Result<()> {
        let (h, l) = {
            let head = self
                .ring
                .head()
                .ok_or_else(|| Error::Corrupt("rescue on pre-genesis vault".into()))?;
            (head.hamt_hash, head.hamt_lba)
        };
        self.hamt.reset_to(h, l);
        // A staged reap belongs to the arena just discarded: its relocations are gone, so its window must stay occupied.
        self.pending_reap = None;
        match self.rescue(now) {
            Ok(_) => Ok(()),
            Err(Error::TractFull) => self.grow(self.tract.len * 2, now),
            Err(e) => Err(e),
        }
    }

    /// GROUP COMMIT with deletes: apply MANY put-or-delete ops IN ORDER, durable on return, under ONE spine commit (put_batch's law extended to mixed ops — a rarangi transaction's apply phase is [row puts + catalog put + superroot put + WAL retire-delete], and each riding its own commit was the 4-5x amplification behind the field's 40s message sends, 2026-09-02). `Some(value)` = put (identical-overwrite skipped), `None` = delete (absent key skipped). Order is preserved, which is load-bearing for callers whose LAST op is their visibility/cleanup edge (rarangi puts the WAL retire last): a mid-ladder Fenced heartbeat commit can land a PREFIX of the batch early — durability sooner, never out of order — so an op only ever lands after everything before it. NOT atomic under that heartbeat window: a caller needing all-or-nothing must anchor on its own journal (rarangi's WAL put precedes this and replays the full set on crash).
    pub fn apply_batch(&mut self, items: &[(&[u8; 32], Option<&[u8]>)], now: i64) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        // An entry's ladder that cannot land without discarding earlier entries says TractFull: grow (the barrier drops the arena) and replay the whole batch — the same law as the commit arm below.
        let dirty = match self.apply_items(items, now) {
            Ok(d) => d,
            Err(Error::TractFull) => {
                self.grow(self.tract.len * 2, now)?;
                self.apply_items(items, now)?;
                true
            }
            Err(e) => return Err(e),
        };
        if !dirty {
            return Ok(());
        }
        // The replay law: commit's TractFull means grow-the-barrier (reloads the committed head, arena pristine) and re-run the whole batch — holds_committed skips whatever a mid-ladder commit already landed; a FENCED commit takes the rescue exit and replays the same way.
        let replay = match self.commit(now) {
            Ok(()) => false,
            Err(Error::TractFull) => {
                self.grow(self.tract.len * 2, now)?;
                true
            }
            Err(Error::Fenced(_)) => {
                self.rescue_from_committed_head(now)?;
                true
            }
            Err(e) => return Err(e),
        };
        if replay {
            self.apply_items(items, now)?;
            self.commit(now)?;
        }
        self.maybe_reap(now)?;
        Ok(())
    }

    /// apply_batch's item pass, provisional (no final commit): every op in order, puts skipped when already committed, deletes skipped when absent — so a replay after a barrier re-lands exactly what the barrier dropped.
    /// Returns whether anything changed.
    fn apply_items(&mut self, items: &[(&[u8; 32], Option<&[u8]>)], now: i64) -> Result<bool> {
        let mut dirty = false;
        for &(key, value) in items {
            match value {
                Some(v) => {
                    if self.holds_committed(key, v)? {
                        continue;
                    }
                    self.put_no_commit(key, v, now)?;
                    dirty = true;
                }
                None => {
                    // The delete ladder: deletion mutates index nodes (arena appends), so it can be Fenced like a put — commit to slide the fence and retry. A commit Fenced past its own heartbeat ladder propagates, same as vault::delete today.
                    let existed = loop {
                        let attempt = {
                            let Self { ring, tract, hamt, policy, .. } = self;
                            hamt.delete(ring.mirror(), tract, key, *policy)
                        };
                        match attempt {
                            Ok(e) => break e,
                            Err(Error::Fenced(_)) => self.commit(now)?,
                            Err(e) => return Err(e),
                        }
                    };
                    dirty |= existed;
                }
            }
        }
        Ok(dirty)
    }

    /// Delete, durable on return. Returns false if the key was absent.
    pub fn delete(&mut self, key: &[u8; 32], now: i64) -> Result<bool> {
        let existed = {
            let Self { ring, tract, hamt, policy, .. } = self;
            hamt.delete(ring.mirror(), tract, key, *policy)?
        };
        if existed {
            self.commit(now)?;
            self.maybe_reap(now)?;
        }
        Ok(existed)
    }

    /// Grow the tract to `new_tract_blocks` (never shrinks; equal length is a no-op). Space first, geometry second: devices are extended (zeroed, preallocated) BEFORE the spine entry carrying the new length lands — power loss between the two leaves unclaimed zeros, which is harmless.
    ///
    /// The plow is re-aligned to the smallest monotone value ≥ the current plow whose wrapped position under the NEW length equals the current wrapped position, so the sweep continues from the same physical block. With that continuity, any position's revisit gap stays ≥ the tract length at its previous visit, and the per-generation fence (min of plow_i + tract_blocks_i) keeps every pre-grow generation in the K-window fully restorable. The alignment jump only burns fence budget, never adds any — strictly conservative; the put/commit heartbeat ladders absorb a tight window.
    pub fn grow(&mut self, new_tract_blocks: u64, now: i64) -> Result<()> {
        let old_len = self.tract.len;
        // A target at or below the current length is a NO-OP, never an error (field 2026-08-27): callers compute their target from a tract_blocks() read, and between that read and this call other queued work may have grown the tract past it — the request isn't wrong, it's already satisfied. Erroring here failed every chains persist on the Mac with "grow cannot shrink 35072 -> 18752" while the vault was perfectly healthy at 35072.
        if new_tract_blocks <= old_len {
            return Ok(());
        }
        let need = self.tract.base + new_tract_blocks;
        self.ring.mirror().grow(need)?;

        // Grow is a barrier: the usual caller just hit TractFull/Fenced mid-put, leaving a dirty arena and half-applied liveness. Discard all provisional state by reloading the committed head — exactly resume's path. Orphaned blocks the wedged op placed classify dead and are reclaimed by the sweep.
        let head = self
            .ring
            .head()
            .ok_or_else(|| Error::Corrupt("grow on pre-genesis vault".into()))?
            .clone();
        self.hamt.reset_to(head.hamt_hash, head.hamt_lba);
        // The plow goes back to the head's: staged appends sit at positions about to be reused, and nothing committed names them.
        self.tract.discard_staged();
        self.tract.plow = head.plow;
        self.pending_reap = None;
        // TREE-ONLY rewalk, the open's own (2026-09-12): nodes and leaves read and verified, furrows and extent runs marked live by position unread.
        // The full walk read and hashed every data block of the vault — most likely the bulk of the field's 3.3 s and 5.7 s single-chunk commits on a phone holding hundreds of MB of attachments (2026-10-21), a grow the put ladder ran inside the caller's commit.
        let mut live_blocks = Vec::new();
        let mut referenced = Vec::new();
        let mut stale = Vec::new();
        {
            let Self { ring, tract, hamt, .. } = self;
            hamt.walk_tree_collect(ring.mirror(), tract, &mut live_blocks, &mut referenced, &mut stale)?;
        }
        self.live = LiveSet::with_len(self.tract.len);
        for (lba, _) in live_blocks {
            self.live.mark_referenced(lba);
        }
        for lba in referenced {
            self.live.mark_referenced(lba);
        }
        // The old map's blocks sit in the old region, which the realign below hands to the reap; the grow's own commit writes the map whole in the new space.
        self.lmap = MapLayout::whole();

        // Re-align the cursors so the CLEAN region is exactly the appended zeros and the OCCUPIED region is exactly the old tract: plow' ≡ old_len (appends start at the first new block), reap' = plow' − old_len (≡ 0 — the whole old region awaits the reap, which migrates its live blocks and retires its dead ones window by window).
        // Monotone order is preserved (plow' ≥ plow), so fence comparisons stay sound; pre-grow entries keep their smaller budgets until they age out of the K-window.
        let plow = self.tract.plow;
        let delta = (old_len + new_tract_blocks - plow % new_tract_blocks) % new_tract_blocks;
        self.tract.plow = plow + delta;
        self.tract.reap = self.tract.plow - old_len;
        self.tract.len = new_tract_blocks;
        self.map_off = true;
        let r = self.commit(now);
        self.map_off = false;
        r
    }

    /// Grow WITHOUT the barrier reload — for the one caller whose in-RAM index is MORE authoritative than the committed head: the repair open, whose prunes exist only in RAM. The normal grow discards RAM state and re-walks the committed head STRICTLY, which on a vault mid-repair (a) resurrects the pruned danglings and (b) fails Seal on them — the 2026-08-25 loop where the "repaired" vault re-pruned the same 84 pointers every boot while the disk never changed. Here the pruned hamt + its live set ride across the grow untouched; the trailing commit flushes them into the fresh clean region, landing the repair durably. Sound ONLY when the caller guarantees the RAM state is clean-by-construction (no half-applied put) — the repair open is exactly that.
    pub(crate) fn grow_preserving(&mut self, new_tract_blocks: u64, now: i64) -> Result<()> {
        let old_len = self.tract.len;
        if new_tract_blocks <= old_len {
            return Ok(());
        }
        let need = self.tract.base + new_tract_blocks;
        // The repaired index rides across this grow, so whatever it staged must reach the devices at the positions it was given — before the realign moves the plow.
        self.tract.write_staged(self.ring.mirror())?;
        self.ring.mirror().grow(need)?;
        // The realign below re-derives the reap from scratch; a staged window's cursor would overwrite it at the commit.
        self.pending_reap = None;
        self.lmap.rewrite = true;
        let plow = self.tract.plow;
        let delta = (old_len + new_tract_blocks - plow % new_tract_blocks) % new_tract_blocks;
        self.tract.plow = plow + delta;
        self.tract.reap = self.tract.plow - old_len;
        self.tract.len = new_tract_blocks;
        self.map_off = true;
        let r = self.commit(now);
        self.map_off = false;
        r
    }

    /// Flush the index, append the next generation, recompute the fence. The transaction commit point — everything before this is provisional.
    ///
    /// Fence deadlock escape: flushing needs tract appends; appends can be fenced; raising the fence needs generations. HEARTBEAT generations break the cycle — spine entries re-asserting the committed head, written into the (unfenced) ring region, sliding old entries out of the K-window.
    pub fn commit(&mut self, now: i64) -> Result<()> {
        let mut attempts = 0u64;
        let ((root_hash, root_lba), (map_root, map_layout, map_own)) = loop {
            let r = {
                let Self { ring, tract, hamt, live, .. } = self;
                hamt.flush(ring.mirror(), tract, live)
            };
            // The live map rides the same run: the pages this commit's delta touches, and their table, appended after the index.
            // A tract that fits rides its whole bitmap inside the entry: no tract block. A larger one appends pages — except under a grow, whose commit appends nothing.
            let r = r.and_then(|x| {
                let len = self.tract.len;
                if len <= crate::livemap::INLINE_MAX_BITS {
                    let bytes = self.live.inline_after(self.hamt.delta(), len);
                    Ok((x, (Some(MapRef::Inline(bytes)), MapLayout::whole(), hashbrown::HashSet::new())))
                } else if self.map_off {
                    Ok((x, (None, MapLayout::whole(), hashbrown::HashSet::new())))
                } else {
                    self.append_livemap().map(|(root, layout, own)| (x, (Some(MapRef::Root(root.0, root.1)), layout, own)))
                }
            });
            match r {
                Ok(x) => break x,
                Err(Error::Fenced(_)) if attempts <= FENCE_K + 2 => {
                    attempts += 1;
                    self.append_heartbeat(now)?;
                }
                // TractFull exits RAW on purpose: grow is a barrier that reloads the committed head, which would silently discard the very state this commit is flushing. The too-small verdict belongs to callers still holding their items — put/put_batch grow and REPLAY (2026-08-25).
                Err(e) => return Err(e),
            }
        };
        // Everything this commit appended goes down WITH its entry, under one flush per device, and the entry carries the run's hash (the verified head): an entry that lands without all of its run is a torn commit, which open detects and steps back from.
        // RAM moves only once that write has landed. A failure sends the index back to the committed head; the reap cursor, the live set and the delta have not changed yet, and the caller's batch still holds its items.
        let (start, run) = self.tract.take_staged();
        // A large run goes down first under its own flush and the entry carries no tail: open checks a head's run by reading it, and that read must stay a few blocks however big the last commit was. A large commit's cost is its transfer, not its second flush.
        let split = run.len() > TAIL_MAX_BLOCKS;
        let tail = (!run.is_empty() && !split).then(|| {
            let mut h = blake3::Hasher::new();
            for b in &run {
                h.update(b);
            }
            Tail { start, count: run.len() as u64, hash: *h.finalize().as_bytes() }
        });
        let data: Vec<(u64, &crate::block::Block)> = run.iter().enumerate().map(|(i, b)| (self.tract.device_lba(start + i as u64), b)).collect();
        // The staged reap retires its window with this entry: the run above landed in clean space that still excluded the window's originals.
        let reap = self.pending_reap.unwrap_or(self.tract.reap);
        let (added, removed) = self.hamt.delta_counts();
        let head = self
            .ring
            .head()
            .ok_or_else(|| Error::Corrupt("commit on pre-genesis vault".into()))?;
        let entry = SpineEntry {
            gen: head.gen + 1,
            prev_hash: head.body_hash(),
            ring_log2: self.ring.ring_log2(),
            tract_blocks: self.tract.len,
            hamt_hash: root_hash,
            hamt_lba: root_lba,
            plow: self.tract.plow,
            reap: Some(reap),
            live: (self.live.count as usize + added).saturating_sub(removed) as u64 + map_own.len() as u64,
            eagle_time: now,
            tail,
            livemap: map_root,
        };
        let landed = if split {
            self.ring.mirror().write_verified_batch(&data).and_then(|_| self.ring.append(&entry))
        } else {
            self.ring.append_commit(&entry, &data)
        };
        if let Err(e) = landed {
            let head = self.ring.head().ok_or_else(|| Error::Corrupt("commit on pre-genesis vault".into()))?;
            self.hamt.reset_to(head.hamt_hash, head.hamt_lba);
            self.pending_reap = None;
            return Err(e);
        }
        {
            let Self { hamt, live, .. } = self;
            live.apply(hamt.take_delta());
        }
        self.live.dirty.clear();
        self.live.own = map_own;
        self.lmap = map_layout;
        self.map_off = false;
        self.pending_reap = None;
        self.tract.reap = reap;

        // Fence: the last K generations stay fully restorable.
        let fences = self.ring.recent_fences(FENCE_K)?;
        self.tract.fence_limit = fence_from(&fences);

        // Migrating profile: hop to the next residence after `residency` rotations here.
        if let Some(root) = &self.root {
            let n_gens = root.residency << self.ring.ring_log2();
            if entry.gen.saturating_sub(root.since) >= n_gens {
                self.migrate_ring(now)?;
            }
        }
        Ok(())
    }

    /// Append the live map this commit leaves: every page its delta (or an earlier unwritten change) touches, then the tables over them — or the whole map when [`MapLayout::rewrite`] says so. Nothing in RAM moves here; the commit installs the returned layout and own-block set once its write lands.
    fn append_livemap(&mut self) -> Result<(crate::livemap::Ptr, MapLayout, hashbrown::HashSet<u64>)> {
        use crate::livemap::{encode_page, encode_table, pages_for, TABLE_FANOUT};
        let len = self.tract.len;
        let n = pages_for(len);
        let mut layout = self.lmap.clone();
        let rewrite = layout.rewrite || layout.pages.len() != n || layout.root.is_none();
        let pages = self.live.preview(self.hamt.delta(), len, rewrite);
        if !rewrite && pages.is_empty() {
            let root = layout.root.unwrap();
            return Ok((root, layout, self.live.own.clone()));
        }
        layout.pages.resize(n, None);
        let encoded: Vec<(usize, crate::block::Block)> = pages.iter().map(|(&p, w)| encode_page(p as u64, w).map(|b| (p, b))).collect::<Result<_>>()?;
        let blocks: Vec<crate::block::Block> = encoded.iter().map(|(_, b)| *b).collect();
        let placed = {
            let Self { ring, tract, live, .. } = self;
            tract.append(ring.mirror(), live, &blocks)?
        };
        for ((p, b), pos) in encoded.iter().zip(&placed) {
            layout.pages[*p] = Some((crate::tract::sealed_hp(b).unwrap(), *pos));
        }
        let page_ptrs: Vec<crate::livemap::Ptr> = layout.pages.iter().map(|p| p.ok_or_else(|| Error::Corrupt("live map page never written".into()))).collect::<Result<_>>()?;
        let dirty_pages: hashbrown::HashSet<usize> = pages.keys().copied().collect();
        let mut append_one = |v: &mut Self, block: crate::block::Block| -> Result<crate::livemap::Ptr> {
            let Self { ring, tract, live, .. } = v;
            let pos = tract.append(ring.mirror(), live, core::slice::from_ref(&block))?[0];
            Ok((crate::tract::sealed_hp(&block).unwrap(), pos))
        };
        let root = if n <= TABLE_FANOUT {
            layout.tables.clear();
            append_one(self, encode_table(1, len, &page_ptrs)?)?
        } else {
            let groups = n.div_ceil(TABLE_FANOUT);
            if rewrite || layout.tables.len() != groups {
                layout.tables.clear();
            }
            let mut tables = Vec::with_capacity(groups);
            for g in 0..groups {
                let lo = g * TABLE_FANOUT;
                let hi = (lo + TABLE_FANOUT).min(n);
                let keep = layout.tables.get(g).copied().filter(|_| !(lo..hi).any(|p| dirty_pages.contains(&p)));
                let t = match keep {
                    Some(t) => t,
                    None => append_one(self, encode_table(1, len, &page_ptrs[lo..hi])?)?,
                };
                tables.push(t);
            }
            layout.tables = tables;
            append_one(self, encode_table(2, len, &layout.tables)?)?
        };
        layout.root = Some(root);
        layout.rewrite = false;
        let mut own: hashbrown::HashSet<u64> = page_ptrs.iter().map(|p| p.1).collect();
        own.extend(layout.tables.iter().map(|t| t.1));
        own.insert(root.1);
        Ok((root, layout, own))
    }

    /// Move the spine to the next residence in the band (RING.md "Migrating Rings").
    /// Ordering is the A/B pattern: zero the next residence, record the move in the root ring (current + previous), then let commits land at the new base — the generation chain rides across via prev_hash. Crash anywhere: boot scans `at`, falls back to `was`, and finds exactly one committed head.
    fn migrate_ring(&mut self, now: i64) -> Result<()> {
        let Some(root) = self.root.clone() else {
            return Ok(());
        };
        let n = 1u64 << root.ring_log2;
        // Compute from where the ring ACTUALLY is (a crash-fallback session may still be at `was`), so the new entry's fallback pointer is always truthful.
        let cur = self.ring.base();
        let idx = (cur - ROOT_SLOTS) / n;
        let next = ROOT_SLOTS + ((idx + 1) % root.residences) * n;
        zero_ring_at(self.ring.mirror(), root.ring_log2, next)?;
        let head_gen = self.ring.head().map(|h| h.gen).unwrap_or(0);
        let new_root = RootEntry {
            gen: root.gen + 1,
            prev_hash: root.body_hash(),
            ring_log2: root.ring_log2,
            at: next,
            was: cur,
            since: head_gen + 1,
            residences: root.residences,
            residency: root.residency,
            eagle_time: now,
        };
        append_root(self.ring.mirror(), &new_root)?;
        self.ring.set_base(next);
        self.root = Some(new_root);
        Ok(())
    }

    /// One reap window per commit while dead space exceeds 25% of the tract — incremental, bounded amplification, never stop-the-world. Skipped when the fence or clean headroom cannot host the window's survivors; ordinary commits raise both.
    fn maybe_reap(&mut self, now: i64) -> Result<()> {
        let used = (self.tract.plow - self.tract.reap).min(self.tract.len);
        let dead = used.saturating_sub(self.live.len() as u64);
        if dead << 2 > self.tract.len {
            self.reap_one_window(now)?;
        }
        Ok(())
    }

    fn reap_window(&self) -> u64 {
        (self.tract.len >> 6).max(REAP_WINDOW_MIN)
    }

    /// A display-grade snapshot of the engine's physique — the Settings vault page reads this thru kete's librarian (one message, no I/O beyond what RAM already holds).
    pub fn engine_stats(&self) -> VaultStats {
        let head = self.ring.head();
        VaultStats {
            generation: head.map_or(0, |h| h.gen),
            tract_blocks: self.tract.len,
            plow: self.tract.plow,
            reap: self.tract.reap,
            live_entries: self.live.len() as u64,
            live_blocks: self.live.live_blocks(),
            block_bytes: crate::BLOCK as u64,
        }
    }

    /// EMERGENCY UN-WEDGE — the fence deadlock's exit (field 2026-08-21/23/24: plows 422745, 307312, 1110637 across three vaults). The terminal state: a committed head whose budget cannot stage even one reap window — cleaning needs budget, budget needs cleaning, and the head faithfully restores the wedge at every reopen. Two waivers break the cycle, both safe by the tract's clean-invariant (reap targets only verifiably live-free space, originals stay sealed until their retiring commit):
    /// 1. The FENCE is waived per window (fence_limit = None) — what that sacrifices is rollback to OLDER generations, never the current committed state; after a wedge that trade is the whole point.
    /// 2. The all-survive worst-case sizing is replaced by ACTUAL survivor counts from the LiveSet (no device I/O) — a dead-heavy window stages nearly nothing, so even clean ≈ 0 makes progress.
    /// Returns the windows reaped. Err(TractFull) = a live block sits hard against the reap with no staging room — genuinely full of live data: grow or refuse (the rescue only ever helps dead-heavy occupancy). Each retiring commit re-fences honestly, so the loop's comfort check reads the true post-rescue budget.
    pub fn rescue(&mut self, now: i64) -> Result<u64> {
        const RESERVE: u64 = COMMIT_RESERVE;
        let mut windows = 0u64;
        let mut airlock_grown = false;
        let bound = (self.tract.len / REAP_WINDOW_MIN).max(8);
        for _ in 0..bound {
            let occupied = self.tract.plow - self.tract.reap;
            if occupied == 0 {
                break;
            }
            let comfortable = self.tract.fence_limit.map_or(true, |l| {
                l.saturating_sub(self.tract.plow) >= self.reap_window() + RESERVE * 2
            });
            if comfortable && windows > 0 {
                break;
            }
            let clean = self.tract.clean_blocks();
            let max_w = self.reap_window().min(occupied);
            let mut w = 0u64;
            let mut surv = 0u64;
            for i in 0..max_w {
                let pos = (self.tract.reap + i) % self.tract.len;
                // Any referenced position is a survivor, hashed or tree-only: counting the map alone sized windows full of a tree-only open's furrows as pure-dead, whose relocations then ran out of room mid-window.
                surv += self.live.is_referenced(pos) as u64;
                // The reserve is charged only when something actually stages: a pure-dead window appends NOTHING, so even clean-of-zero reaps it whole — without this guard the field vault (91% dead, clean 3) was refused at its very first block and ground forward in 4-block bites (2026-08-24).
                if surv > 0 && surv + RESERVE > clean {
                    break;
                }
                w = i + 1;
            }
            if w == 0 {
                // THE AIRLOCK (field geometry, 2026-08-24): the clean boundary is BY DEFINITION where live blocks start, so a wedge parks the reap head ON the live index cluster — survivors to move, no room to stage them (clean=3 on the Mac). A modest grow is the key that fits: spine-only, no fence consent needed, and the fresh lap of clean space lets the reap run normally from here. Once per rescue; a second stall is genuinely full.
                if airlock_grown {
                    return Err(Error::TractFull);
                }
                // Size the key to the disease (field 2026-09-03, Leviathan: 7.5 HOURS of failing writes). A dead-heavy wedge needs only staging room — the modest 4-window grow. But a LIVE-heavy tract (>50% live) has genuinely outgrown itself, and the modest grow is a token: its fresh lap is consumed at once and the vault re-enters the wedge, looping grow→wedge→grow for hours while every put fails. Every other grow site doubles; when the working set is the problem, double here too — disk is cheap, hours of refused writes are not.
                let target = if self.live.len() as u64 * 2 > self.tract.len {
                    self.tract.len * 2
                } else {
                    self.tract.len + self.reap_window() * 4
                };
                self.grow(target, now)?;
                airlock_grown = true;
                continue;
            }
            self.tract.fence_limit = None;
            self.reap_staged(w)?;
            self.commit(now)?;
            windows += 1;
        }
        let fences = self.ring.recent_fences(FENCE_K)?;
        self.tract.fence_limit = fence_from(&fences);
        Ok(windows)
    }

    /// RECLAIM AHEAD — the reap an embedder runs at its own idle edge, so callers' commits stop paying for it.
    /// The inline ladders (put's TractFull arm, maybe_reap after each commit) reclaim INSIDE whichever caller's commit meets the shortage: field 2026-10-21, a phone taking in 256 KiB attachment chunks saw single-chunk commits of 3.3 s and 5.7 s while the ladder reaped, rescued and grew under them.
    /// One bounded window per call (at most RECLAIM_WINDOW_MAX blocks, and at most half the clean space so the retiring flush always has room), so an op arriving mid-step waits for one small window; the embedder calls again only while it stays idle.
    /// Wants clean space of at least an eighth of the tract, and dead space under the quarter that maybe_reap acts on inline.
    pub fn reclaim_ahead(&mut self, now: i64) -> Result<Reclaim> {
        let len = self.tract.len;
        let clean = self.tract.clean_blocks();
        let occupied = self.tract.plow - self.tract.reap;
        let dead = occupied.saturating_sub(self.live.len() as u64);
        let target = len >> 3;
        let short = clean < target;
        if !short && dead << 2 <= len {
            return Ok(Reclaim::Comfortable);
        }
        // Short with more than three quarters live: reaping cannot pay its way — each relocated survivor rewrites its index path, so a live-dense window makes about as much new garbage as it frees (fuzz 2026-10-21: two thousand windows at 78% live never restored the eighth).
        // The working set has outgrown the tract; growth is the honest fix.
        if short && (self.live.len() as u64) * 4 > len * 3 {
            return Ok(Reclaim::LiveHeavy);
        }
        let cap = RECLAIM_WINDOW_MAX.min(clean >> 1);
        if cap == 0 {
            return Ok(Reclaim::Stuck);
        }
        Ok(if self.reap_one_window_capped(now, cap)? { Reclaim::Reaped } else { Reclaim::Stuck })
    }

    /// Clean one window at the reap and commit the retiring generation. Returns false when no progress is possible right now (nothing occupied, or not even a one-block window can stage its survivors — the caller's ladder commits/grows and comes back).
    pub fn reap_one_window(&mut self, now: i64) -> Result<bool> {
        self.reap_one_window_capped(now, u64::MAX)
    }

    /// [`reap_one_window`](Self::reap_one_window) with the window held to at most `cap` blocks — the idle-edge reclaim's bounded step.
    fn reap_one_window_capped(&mut self, now: i64, cap: u64) -> Result<bool> {
        // One staged window at a time: a window whose retiring commit failed is still in the arena, and re-scanning it before it lands would relocate its survivors twice.
        if self.pending_reap.is_some() {
            self.commit(now)?;
        }
        let occupied = self.tract.plow - self.tract.reap;
        if occupied == 0 {
            return Ok(false);
        }
        // Reserve a few clean blocks for the retiring commit's index rewrite; size the window to what the clean region can stage (worst case: every block survives).
        const RESERVE: u64 = COMMIT_RESERVE;
        let mut w = self
            .reap_window()
            .min(cap)
            .min(occupied)
            .min(self.tract.clean_blocks().saturating_sub(RESERVE));
        if w == 0 {
            return Ok(false);
        }
        // Fence room for the survivor appends; slide the window first if it is tight.
        let budget = |t: &Tract| t.fence_limit.map(|l| l.saturating_sub(t.plow));
        if let Some(b) = budget(&self.tract) {
            if b < w + RESERVE {
                self.commit(now)?;
            }
        }
        if let Some(b) = budget(&self.tract) {
            w = w.min(b.saturating_sub(RESERVE));
            if w == 0 {
                return Ok(false);
            }
        }
        self.reap_staged(w)?;
        self.commit(now).map(|_| true)
    }

    /// Run one reap window and STAGE its retirement: survivors are copied and repointed in the arena, but the reap cursor moves only inside the retiring commit (see `pending_reap`).
    /// Until then the window's originals are what the committed head references, so they must not count as clean space for the commit's own flush.
    fn reap_staged(&mut self, w: u64) -> Result<()> {
        let start = self.tract.reap;
        // The reap leaves the live map's own blocks to the map: a window that holds any of them has the retiring commit write the map whole, elsewhere.
        let len = self.tract.len;
        if self.live.own.iter().any(|&p| (p + len - start % len) % len < w) {
            self.lmap.rewrite = true;
        }
        {
            let Self { ring, tract, hamt, live, .. } = self;
            hamt.reap_window(ring.mirror(), tract, live, w)?;
        }
        self.pending_reap = Some(self.tract.reap);
        self.tract.reap = start;
        Ok(())
    }

    /// A generation that changes nothing    /// A generation that changes nothing    /// A generation that changes nothing: the head's root, geometry, and plow under a new generation number. Exists to slide OLDER entries out of the fence window when the tract is too tight to flush — budget rises to one lap past the last real commit, never further. Recording the tract's in-flight plow here would be a lie: the head's root still references originals the in-flight passes swept past, and a fence raised past them lets the retrying flush tramp blocks the committed index needs (Seal on resume). A tract still wedged at the head's own lap is genuinely full — grow or refuse.
    fn append_heartbeat(&mut self, now: i64) -> Result<()> {
        let head = self
            .ring
            .head()
            .ok_or_else(|| Error::Corrupt("heartbeat on pre-genesis vault".into()))?
            .clone();
        let entry = SpineEntry {
            gen: head.gen + 1,
            prev_hash: head.body_hash(),
            ring_log2: self.ring.ring_log2(),
            tract_blocks: head.tract_blocks,
            hamt_hash: head.hamt_hash,
            hamt_lba: head.hamt_lba,
            plow: head.plow,
            reap: head.reap,
            live: self.live.len() as u64,
            eagle_time: now,
            tail: None,
            livemap: head.livemap.clone(),
        };
        self.ring.append(&entry)?;
        let fences = self.ring.recent_fences(FENCE_K)?;
        self.tract.fence_limit = fence_from(&fences);
        Ok(())
    }

    /// TEST/MIGRATION AID — write a value in the LEGACY per-lba direct format and commit it, exactly as pre-extent engines did. Exists so migration tests can build old-format state inside a modern vault.
    #[doc(hidden)]
    pub fn put_legacy_direct_for_tests(&mut self, key: &[u8; 32], value: &[u8], now: i64) -> Result<()> {
        {
            let Self { ring, tract, hamt, live, .. } = self;
            hamt.put_legacy_direct_for_tests(ring.mirror(), tract, live, key, value)?;
        }
        self.commit(now)
    }

    // ======================================================================== introspection ==========================================================

    pub fn generation(&self) -> Option<u64> {
        self.ring.head().map(|h| h.gen)
    }

    pub fn live_blocks(&self) -> usize {
        self.live.len()
    }

    /// TEST AID — the live map against the index, block for block: (in the map but unreachable from the root, reachable but not in the map). Both empty = the two agree, which is the invariant every commit must keep and the plow's classification depends on. Walks the whole index; test scale only.
    #[doc(hidden)]
    pub fn live_map_divergence(&mut self) -> Result<(Vec<u64>, Vec<u64>)> {
        let mut walked: Vec<(u64, [u8; 32])> = Vec::new();
        {
            let Self { ring, tract, hamt, .. } = self;
            hamt.walk_live(ring.mirror(), tract, &mut walked)?;
        }
        let index: HashMap<u64, [u8; 32]> = walked.into_iter().collect();
        let mut unrouted: Vec<u64> = self.live.indexed().filter(|lba| !index.contains_key(lba)).collect();
        let mut missing: Vec<u64> = index.keys().filter(|lba| !self.live.get(**lba)).copied().collect();
        unrouted.sort_unstable();
        missing.sort_unstable();
        Ok((unrouted, missing))
    }

    /// THE IDLE SCRUB (2026-10-22): check up to `budget` live blocks on BOTH devices, resuming where the last step stopped, and heal whichever side is bad from the side that is good — a block failing its own seal is the bad one; when both are sealed but differ, the primary wins (it is the copy commits are acknowledged on). Reads heal the primary as they go; this is what finds a quietly rotting second copy before it is needed, and the primary's cold blocks nothing reads.
    /// An embedder runs it at its idle edge, a step at a time. Without a second device it only reports.
    pub fn scrub_step(&mut self, budget: u64) -> Result<Scrubbed> {
        #[cfg(feature = "std")]
        self.ring.mirror().sync_follower();
        let mut out = Scrubbed::default();
        let len = self.tract.len;
        let mut pos = self.scrub_at;
        while out.checked < budget {
            if pos >= len {
                out.lap_done = true;
                pos = 0;
                break;
            }
            if !self.live.is_referenced(pos) {
                pos += 1;
                continue;
            }
            let (mut a, mut b) = (ZERO_BLOCK, ZERO_BLOCK);
            self.tract.read(self.ring.mirror(), pos, &mut a)?;
            let has_b = self.tract.read_alt(self.ring.mirror(), pos, &mut b)?;
            out.checked += 1;
            if has_b && a != b {
                let a_ok = crate::tract::sealed_hp(&a).is_some();
                let b_ok = crate::tract::sealed_hp(&b).is_some();
                let lba = self.tract.base + pos;
                if a_ok {
                    self.ring.mirror().repair_secondary(lba, &a)?;
                    self.ring.mirror().emit(crate::events::StorageEvent::ScrubRepaired { lba: pos, primary: false });
                    out.repaired += 1;
                } else if b_ok {
                    self.ring.mirror().repair_primary(lba, &b)?;
                    self.ring.mirror().emit(crate::events::StorageEvent::ScrubRepaired { lba: pos, primary: true });
                    out.repaired += 1;
                } else {
                    out.lost += 1;
                }
            } else if crate::tract::sealed_hp(&a).is_none() {
                out.lost += 1;
            }
            pos += 1;
        }
        self.scrub_at = pos;
        Ok(out)
    }

    /// TEST AID — whether this handle opened from the live map rather than by walking the index.
    #[doc(hidden)]
    pub fn opened_from_map(&self) -> bool {
        self.from_map
    }

    pub fn tract_blocks(&self) -> u64 {
        self.tract.len
    }

    /// Monotone append total — laps = plowed / tract_blocks.
    pub fn tract_blocks_plowed(&self) -> u64 {
        self.tract.plow
    }

    /// Monotone cleaning total.
    pub fn tract_blocks_reaped(&self) -> u64 {
        self.tract.reap
    }

    pub fn degraded(&mut self) -> bool {
        self.ring.mirror().degraded()
    }
}

#[cfg(feature = "std")]
impl<A: BlockDev, B: BlockDev + 'static> Vault<A, B> {
    /// Acknowledge writes on the primary alone and copy them to the second device behind it, in order (see [`Mirror::follow`]): a commit then waits for one device's flushes, not two. Call once the vault is open.
    pub fn follow(&mut self) {
        self.ring.mirror().follow();
    }

    /// Wait until the second device has caught up — for a caller about to read the files directly, or to measure.
    pub fn sync_follower(&mut self) {
        self.ring.mirror().sync_follower();
    }
}

/// min over the window of each generation's fence budget (reap_i + tract_blocks_i):
/// appends stay inside space that was already clean at every windowed generation, and clean space contains nothing those generations reference (Vault_CleanInvariant) — so the last K generations are fully restorable. Legacy entries without a reap contribute plow_i (zero budget) and age out over K generations.
fn fence_from(budgets_newest_first: &[u64]) -> Option<u64> {
    if budgets_newest_first.len() < FENCE_K as usize {
        return None; // genesis era: fewer than K generations exist
    }
    budgets_newest_first.iter().copied().min()
}

/// The maximal monotone reap whose clean region [plow, reap + len) holds no live block:
/// walk the live set for the nearest live position downstream of the plow. Sound for any layout — a legacy mixed tract simply derives little or no clean space.
fn derive_reap(plow: u64, len: u64, live: &LiveSet) -> u64 {
    let clean = live.clean_run_from(plow % len, len);
    (plow + clean).saturating_sub(len)
}

// ============================================================================ verified replication ===================================================

/// Outcome of a replication pass.
#[derive(Debug, Default, PartialEq)]
pub struct Replicated {
    pub spine_copied: u64,
    pub tract_copied: u64,
    /// The loser only lagged: just the tail between the two heads was copied.
    pub tail_only: bool,
}

/// A device's resolved layout: where its spine lives and where its tract begins.
struct DeviceLayout {
    spine_base: u64,
    tract_base: u64,
    has_root: bool,
}

/// Resolve a single device's layout: root entry (migrating profile, active residence decided by which base actually holds the higher committed generation) or legacy fixed ring at block 0.
fn resolve_layout<D: BlockDev>(dev: &mut D, ring_log2: u8) -> Result<(DeviceLayout, Option<u64>, u64)> {
    let n = 1u64 << ring_log2;
    if let Some(root) = read_root(dev)? {
        let band = ROOT_SLOTS + root.residences * (1u64 << root.ring_log2);
        let (gen_at, slot_at) = best_gen(dev, n, ring_log2, root.at)?;
        let (gen_was, slot_was) = best_gen(dev, n, ring_log2, root.was)?;
        let (gen, slot, base) = if gen_at >= gen_was {
            (gen_at, slot_at, root.at)
        } else {
            (gen_was, slot_was, root.was)
        };
        return Ok((
            DeviceLayout { spine_base: base, tract_base: band, has_root: true },
            gen,
            slot,
        ));
    }
    let (mut gen, mut slot) = best_gen(dev, n, ring_log2, 0)?;
    // A torn head on this device is not its generation: the one before it is (see resume).
    if let Some(g) = gen {
        let mut buf = ZERO_BLOCK;
        dev.read(slot, &mut buf)?;
        if let crate::ring::Classified::Valid(e) = crate::ring::classify(&buf, slot, Some(ring_log2)) {
            if let Some(t) = e.tail {
                if !tail_intact(dev, n, e.tract_blocks, &t)? && g > 0 {
                    gen = Some(g - 1);
                    slot = (g - 1) & (n - 1);
                }
            }
        }
    }
    Ok((DeviceLayout { spine_base: 0, tract_base: n, has_root: false }, gen, slot))
}

/// Whether a commit's run is on `dev` as its entry recorded it: the blocks at the run's positions hash to the entry's tail hash.
fn tail_intact<D: BlockDev>(dev: &mut D, tract_base: u64, tract_len: u64, t: &Tail) -> Result<bool> {
    if tract_len == 0 || t.count > tract_len {
        return Ok(false);
    }
    let mut h = blake3::Hasher::new();
    let mut buf = ZERO_BLOCK;
    for i in 0..t.count {
        dev.read(tract_base + (t.start + i) % tract_len, &mut buf)?;
        h.update(&buf);
    }
    Ok(h.finalize().as_bytes() == &t.hash)
}

/// Mirror resync — NEVER a file copy. Block-level, hash-compare-skip, write-verified, idempotent; I/O proportional to live + diverged data. Decides the winner by the highest valid generation found in either spine (each device resolved thru its OWN root, so a crash mid-migration on one mirror converges correctly), then converges the loser: root slots, spine slots, then the winner's committed live set.
pub fn verified_replicate<A: BlockDev, B: BlockDev>(
    a: &mut A,
    b: &mut B,
    ring_log2: u8,
) -> Result<Replicated> {
    let (la, gen_a, slot_a) = resolve_layout(a, ring_log2)?;
    let (lb, gen_b, slot_b) = resolve_layout(b, ring_log2)?;

    // CONVERGED FAST PATH (2026-09-10, photon on Android: the live walk below read every live block of BOTH mirrors at every open — 72 MB a side, five seconds on the screen thread, Android's ANR threshold to the second). Same generation in the same slot of the same residence, byte-identical head block (it carries the Merkle root, so a same-gen split brain reads as different) and equal extents ⇒ the committed state is the same on both sides, and every live block reached both devices before that head was committed (a secondary that failed a data write is dropped for the session and never receives the commit, so its generation lags and the walk runs). Nothing to reconcile.
    if gen_a.is_some() && gen_a == gen_b && slot_a == slot_b && la.spine_base == lb.spine_base && a.block_count() == b.block_count() {
        let (mut ha, mut hb) = (ZERO_BLOCK, ZERO_BLOCK);
        a.read(la.spine_base + slot_a, &mut ha)?;
        b.read(lb.spine_base + slot_b, &mut hb)?;
        if ha == hb {
            return Ok(Replicated::default());
        }
    }

    if gen_a >= gen_b {
        if let Some(r) = copy_tail(a, b, ring_log2, &la, gen_a, slot_a, &lb, gen_b, slot_b)? {
            return Ok(r);
        }
        replicate_into(a, b, ring_log2)
    } else {
        if let Some(r) = copy_tail(b, a, ring_log2, &lb, gen_b, slot_b, &la, gen_a, slot_a)? {
            return Ok(r);
        }
        replicate_into(b, a, ring_log2)
    }
}

/// THE TAIL COPY (2026-10-22): a loser that only LAGS — the lazy second copy after a kill, the usual case — differs from the winner by exactly what the winner appended since the loser's head: tract positions between the two plows, and the spine slots of the generations since. Everything is an append, so nothing else moved.
/// It applies when the two heads share history (the winner's slot for the loser's generation holds the loser's head entry byte for byte), the geometry is the same, and the gap is under a lap; anything else — a split brain, a grow, the migrating layout — returns None and the full replicate runs. Data first, flushed and verified, then the spine slots: the loser is a whole vault at every step.
#[allow(clippy::too_many_arguments)]
fn copy_tail<S: BlockDev, D: BlockDev>(
    src: &mut S,
    dst: &mut D,
    ring_log2: u8,
    ls: &DeviceLayout,
    gen_s: Option<u64>,
    slot_s: u64,
    ld: &DeviceLayout,
    gen_d: Option<u64>,
    slot_d: u64,
) -> Result<Option<Replicated>> {
    use crate::ring::{classify, Classified};
    let n = 1u64 << ring_log2;
    let (Some(gs), Some(gd)) = (gen_s, gen_d) else { return Ok(None) };
    if ls.has_root || ld.has_root || ls.spine_base != ld.spine_base || gs < gd || gs - gd >= n || src.block_count() != dst.block_count() {
        return Ok(None);
    }
    let read_entry = |dev: &mut dyn FnMut(u64, &mut crate::block::Block) -> Result<()>, slot: u64| -> Result<Option<(crate::block::Block, SpineEntry)>> {
        let mut buf = ZERO_BLOCK;
        dev(slot, &mut buf)?;
        Ok(match classify(&buf, slot, Some(ring_log2)) {
            Classified::Valid(e) => Some((buf, e)),
            _ => None,
        })
    };
    let Some((head_s_block, head_s)) = read_entry(&mut |l, b| src.read(ls.spine_base + l, b), slot_s)? else { return Ok(None) };
    let Some((head_d_block, head_d)) = read_entry(&mut |l, b| dst.read(ld.spine_base + l, b), slot_d)? else { return Ok(None) };
    // Shared history: the winner still holds the loser's head, unchanged, in its slot.
    let mut shared = ZERO_BLOCK;
    src.read(ls.spine_base + (gd & (n - 1)), &mut shared)?;
    if shared != head_d_block || head_s.tract_blocks != head_d.tract_blocks || head_s.plow < head_d.plow || head_s.plow - head_d.plow >= head_s.tract_blocks {
        return Ok(None);
    }
    let _ = head_s_block;
    let len = head_s.tract_blocks;
    let mut out = Replicated { tail_only: true, ..Replicated::default() };
    // The tract tail, in runs.
    let positions: Vec<u64> = (head_d.plow..head_s.plow).map(|m| ls.tract_base + m % len).collect();
    let mut blocks = alloc::vec![ZERO_BLOCK; positions.len()];
    for (i, &lba) in positions.iter().enumerate() {
        src.read(lba, &mut blocks[i])?;
    }
    let pairs: Vec<(u64, &crate::block::Block)> = positions.iter().copied().zip(blocks.iter()).collect();
    crate::block::write_pairs(dst, &pairs)?;
    dst.flush()?;
    for i in crate::block::mismatches(dst, &pairs)? {
        write_verified_one(dst, pairs[i].0, pairs[i].1)?;
    }
    out.tract_copied = pairs.len() as u64;
    // Then the generations since, oldest first.
    for g in gd + 1..=gs {
        let slot = g & (n - 1);
        let mut buf = ZERO_BLOCK;
        src.read(ls.spine_base + slot, &mut buf)?;
        write_verified_one(dst, ld.spine_base + slot, &buf)?;
        out.spine_copied += 1;
    }
    Ok(Some(out))
}

/// Highest valid generation in one spine residence (full N-read scan — cheaper and simpler than a solo bisect, and replication is rare).
fn best_gen<D: BlockDev>(dev: &mut D, n: u64, ring_log2: u8, base: u64) -> Result<(Option<u64>, u64)> {
    use crate::ring::{classify, Classified};
    let mut best: Option<u64> = None;
    let mut slot_of_best = 0u64;
    let mut buf = ZERO_BLOCK;
    let count = dev.block_count().saturating_sub(base).min(n);
    for slot in 0..count {
        dev.read(base + slot, &mut buf)?;
        if let Classified::Valid(e) = classify(&buf, slot, Some(ring_log2)) {
            if best.is_none() || Some(e.gen) > best {
                best = Some(e.gen);
                slot_of_best = slot;
            }
        }
    }
    Ok((best, slot_of_best))
}

fn replicate_into<S: BlockDev, D: BlockDev>(
    src: &mut S,
    dst: &mut D,
    ring_log2: u8,
) -> Result<Replicated> {
    let mut out = Replicated::default();
    let n = 1u64 << ring_log2;
    let mut sbuf = ZERO_BLOCK;
    let mut dbuf = ZERO_BLOCK;

    // Geometry first: a winner that grew while the loser was absent (crash between device grows, or a mid-session drop) is larger — extend the loser before comparing blocks. Zeros beyond the loser's old end are unclaimed space, harmless if we crash after this.
    if dst.block_count() < src.block_count() {
        dst.grow(src.block_count())?;
    }

    let (layout, _, _) = resolve_layout(src, ring_log2)?;

    // Root slots (migrating profile): every slot where the bytes differ, write-verified.
    if layout.has_root {
        for slot in 0..ROOT_SLOTS {
            src.read(slot, &mut sbuf)?;
            dst.read(slot, &mut dbuf)?;
            if sbuf != dbuf {
                write_verified_one(dst, slot, &sbuf)?;
                out.spine_copied += 1;
            }
        }
    }

    // Spine: every slot of the ACTIVE residence where the bytes differ, write-verified.
    for slot in 0..n {
        let addr = layout.spine_base + slot;
        src.read(addr, &mut sbuf)?;
        dst.read(addr, &mut dbuf)?;
        if sbuf != dbuf {
            write_verified_one(dst, addr, &sbuf)?;
            out.spine_copied += 1;
        }
    }

    // Tract: the winner's committed live set, via its head entry. A solo Mirror over a reborrowed device reuses the existing machinery; the borrow ends with the scope.
    let (live, tract_base) = {
        let solo: Mirror<&mut S, &mut S> = Mirror::from_parts(Some(&mut *src), None)?;
        let mut ring = Ring::open_at(solo, ring_log2, layout.spine_base)?;
        let Some(head) = ring.head().cloned() else {
            return Ok(out);
        };
        let tract = Tract::new(layout.tract_base, head.tract_blocks, head.plow, head.reap.unwrap_or(head.plow), None);
        let mut hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        let mut live = Vec::new();
        hamt.walk_live(ring.mirror(), &tract, &mut live)?;
        // The live map's own blocks are live too, and the index does not reach them.
        if let Some(MapRef::Root(h, at)) = head.livemap {
            if let Ok((map, _)) = load_livemap(ring.mirror(), &tract, (h, at)) {
                live.extend(map.own.iter().map(|&p| (p, [0u8; 32])));
            }
        }
        (live, layout.tract_base)
    };

    for (lba, _hp) in live {
        let dev_lba = tract_base + lba;
        src.read(dev_lba, &mut sbuf)?;
        dst.read(dev_lba, &mut dbuf)?;
        if sbuf != dbuf {
            write_verified_one(dst, dev_lba, &sbuf)?;
            out.tract_copied += 1;
        }
    }
    Ok(out)
}

/// write → flush → read back → compare → retry once. The file-discipline rule: an unverified byte is not a written byte.
fn write_verified_one<D: BlockDev>(dev: &mut D, lba: u64, buf: &crate::block::Block) -> Result<()> {
    let mut check = ZERO_BLOCK;
    for attempt in 0..2 {
        dev.write(lba, buf)?;
        dev.flush()?;
        dev.read(lba, &mut check)?;
        if &check == buf {
            return Ok(());
        }
        if attempt == 0 {
            continue;
        }
    }
    Err(Error::Verify(lba))
}
