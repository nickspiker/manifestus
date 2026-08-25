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
use crate::ring::{any_sealed_block, append_root, read_root, zero_ring, zero_ring_at, Ring, RootEntry, SpineEntry, FENCE_K, ROOT_SLOTS};
use crate::tract::{Liveness, Tract};
use alloc::{format, vec::Vec};
use hashbrown::HashMap;

/// The vault's knowledge of what is referenced: tract lba → sealing hash. Rebuilt from the committed HAMT at open; maintained by deltas afterward. This IS the reap's liveness oracle.
///
/// HashMap PROOF (AGENT.md consent: Nick, 2026-06-12): `is_live` is called once per scanned position in every reap window, and the map holds one entry per live tract block. A linear scan would make one window O(scanned × live); O(1) point lookup matches the access pattern exactly.
///
/// TODO(scale): this map (RAM ∝ live blocks) and the open-time walk_live that rebuilds it are the two caches standing between the on-disk format (petabyte-ready: EWE fields, constant-fragment extents, size-independent spine) and a petabyte-practical implementation. Both are retirable: blocks self-address, so `is_live` can be answered by walking the index for the block's own key (O(log) reads, zero RAM) and resume can skip the walk entirely. Not pressing at photon/cairn scale — do this with the kernel-profile port.
#[derive(Default)]
pub struct LiveSet {
    map: HashMap<u64, [u8; 32]>,
}

impl LiveSet {
    pub fn apply(&mut self, delta: Delta) {
        for (lba, hp) in delta.removed {
            if self.map.get(&lba) == Some(&hp) {
                self.map.remove(&lba);
            }
        }
        for (lba, hp) in delta.added {
            self.map.insert(lba, hp);
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

impl Liveness for LiveSet {
    fn is_live(&self, lba: u64, hp: &[u8; 32]) -> bool {
        self.map.get(&lba) == Some(hp)
    }
}

/// What `Vault::open_repairing` pruned: stale pointers (target zeroed — the deleted-but-never-unlinked legal state, no data behind them) and dangling pointers (target reused/corrupt — the referenced value is LOST).
#[derive(Debug, Default)]
pub struct RepairReport {
    pub stale: Vec<StalePointer>,
    pub dangling: Vec<DanglingPointer>,
}

/// Proactive reap trigger: dead > 25% of the tract → one window after the commit.
/// Window size scales with the tract (len/64, floor 16) so huge values fragment into at most ~64 runs crossing a full lap — far under the extent leaf's capacity.
const REAP_WINDOW_MIN: u64 = 1 << 4;

pub struct Vault<A: BlockDev, B: BlockDev> {
    ring: Ring<A, B>,
    tract: Tract,
    hamt: Hamt,
    live: LiveSet,
    /// Migrating profile (RING.md "Migrating Rings"): the newest root entry. None on the legacy/host layout (spine fixed at block 0, R = ∞).
    root: Option<RootEntry>,
}

impl<A: BlockDev, B: BlockDev> Vault<A, B> {
    /// Open an existing vault or genesis a fresh one, per the open ladder above. `default_tract_blocks` sizes genesis only — an existing vault's geometry comes from its head entry, never from arguments.
    pub fn open(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64) -> Result<Self> {
        // Migrating layout first: a root entry at blocks [0, 4) names the spine's residence.
        {
            let (a, b) = mirror.devices();
            let root = match (a, b) {
                (Some(a), _) => read_root(a)?,
                (None, Some(b)) => read_root(b)?,
                (None, None) => None,
            };
            if let Some(root) = root {
                return Self::resume_migrating(mirror, root);
            }
        }
        match Ring::bootstrap_n(&mut mirror)? {
            Some(r) => Self::resume(mirror, r),
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
                Self::genesis(mirror, ring_log2, now)
            }
        }
    }

    fn genesis(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64) -> Result<Self> {
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
        };
        ring.append(&entry)?;
        let tract = Tract {
            base: n,
            len: tract_blocks,
            plow: 0,
            reap: 0,
            fence_limit: None,
        };
        Ok(Self {
            ring,
            tract,
            hamt: Hamt::empty(),
            live: LiveSet::default(),
            root: None,
        })
    }

    /// Genesis a MIGRATING vault (RING.md "Migrating Rings"): root ring at block 0, a band of `residences` spine residences after it, tract beyond the band. The spine hops to the next residence every `residency` rotations. Resuming an existing vault ignores these parameters — the layout is self-describing.
    pub fn open_migrating(
        mut mirror: Mirror<A, B>,
        ring_log2: u8,
        residences: u64,
        residency: u64,
        now: i64,
    ) -> Result<Self> {
        {
            let (a, b) = mirror.devices();
            let root = match (a, b) {
                (Some(a), _) => read_root(a)?,
                (None, Some(b)) => read_root(b)?,
                (None, None) => None,
            };
            if let Some(root) = root {
                return Self::resume_migrating(mirror, root);
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
        };
        ring.append(&entry)?;
        let tract = Tract {
            base: tract_base,
            len: tract_blocks,
            plow: 0,
            reap: 0,
            fence_limit: None,
        };
        Ok(Self {
            ring,
            tract,
            hamt: Hamt::empty(),
            live: LiveSet::default(),
            root: Some(root),
        })
    }

    /// Open with DANGLING-POINTER REPAIR — the recovery entry point for vaults bricked by the pre-fix tombstone bug (a fast-deleted key's pointer surviving into a reused slot). Walks the committed index tolerantly, prunes every pointer whose target is stale (zeroed) or dangling (reused/corrupt), COMMITS the pruned index, and reports exactly what was dropped. The values behind dangling pointers are unrecoverable by construction (their blocks were overwritten); everything else is preserved byte-for-byte. NEVER the default open: a strict open must keep refusing damage loudly — this is the explicitly-invoked salvage.
    pub fn open_repairing(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64) -> Result<(Self, RepairReport)> {
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
                let mut vault = Self::resume_common_with(ring, tract_base, Some(root), Some(&mut report))?;
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
        let mut vault = Self::resume_common_with(ring, n, None, Some(&mut report))?;
        vault.commit(now)?;
        Ok((vault, report))
    }

    /// Resume a migrating vault: spine at the root's current residence, falling back to the previous residence when the current one is empty (crash between the root update and the first commit at the new base — the A/B pattern).
    fn resume_migrating(mirror: Mirror<A, B>, root: RootEntry) -> Result<Self> {
        let mut ring = Ring::open_at(mirror, root.ring_log2, root.at)?;
        if ring.head().is_none() && root.was != root.at {
            let mirror = ring.into_mirror();
            ring = Ring::open_at(mirror, root.ring_log2, root.was)?;
        }
        let tract_base = ROOT_SLOTS + root.residences * (1u64 << root.ring_log2);
        Self::resume_common(ring, tract_base, Some(root))
    }

    fn resume(mirror: Mirror<A, B>, ring_log2: u8) -> Result<Self> {
        let ring = Ring::open(mirror, ring_log2)?;
        let n = 1u64 << ring_log2;
        Self::resume_common(ring, n, None)
    }

    fn resume_common(ring: Ring<A, B>, tract_base: u64, root: Option<RootEntry>) -> Result<Self> {
        Self::resume_common_with(ring, tract_base, root, None)
    }

    fn resume_common_with(mut ring: Ring<A, B>, tract_base: u64, root: Option<RootEntry>, repair: Option<&mut RepairReport>) -> Result<Self> {
        let head = ring
            .head()
            .ok_or_else(|| Error::Corrupt("bootstrap found entries but head search found none".into()))?
            .clone();
        let mut tract = Tract {
            base: tract_base,
            len: head.tract_blocks,
            plow: head.plow,
            reap: 0, // derived below, once the live set is known
            fence_limit: None,
        };
        // Host-only truncation guard: the device must hold the committed geometry. The fs is a witness, never the authority.
        let need = tract_base + head.tract_blocks;
        if ring.mirror().block_count() < need {
            return Err(Error::Corrupt(format!(
                "device truncated: committed geometry needs {need} blocks"
            )));
        }
        let mut hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        let mut live_blocks = Vec::new();
        let mut stale = Vec::new();
        let mut dangling = Vec::new();
        match repair {
            None => hamt.walk_live_collect(ring.mirror(), &tract, &mut live_blocks, &mut stale)?,
            Some(_) => hamt.walk_live_repair(ring.mirror(), &tract, &mut live_blocks, &mut stale, &mut dangling)?,
        }
        // Pre-fix vaults (and a crash between a delete's zero and its retiring commit) leave stale pointers at zeroed slots. They are time bombs: the reap retires the slot, the plow reuses it, and the pointer flips from "reads as deleted" to Seal-on-open. Unlink them now, in RAM — the next commit persists the pruned index; a session that never commits changes nothing.
        for s in &stale {
            hamt.prune(ring.mirror(), &tract, &s.route, (s.hash, s.lba))?;
        }
        for d in &dangling {
            hamt.prune(ring.mirror(), &tract, &d.route, (d.hash, d.lba))?;
        }
        if let Some(report) = repair {
            report.stale = stale;
            report.dangling = dangling;
        }
        let mut live = LiveSet::default();
        for (lba, hp) in live_blocks {
            live.map.insert(lba, hp);
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
        };
        // WEDGE PROBE (field 2026-08-21/23/24): a head restored with less budget than one reap window + reserve is the fence deadlock arriving — nothing the ladders do can slide it. Rescue NOW, before any caller writes; best-effort, because a genuinely live-full tract must still open readable (the wedged field boxes served every boot load). NEVER on a migrating-era vault (root present): its legacy mixed layout derives near-zero clean space and looks wedge-shaped by definition — the migration sweep owns that state.
        let wedged = !migrating
            && v.tract.fence_limit.map_or(false, |l| {
                l.saturating_sub(v.tract.plow) < v.reap_window() + 8
            });
        if wedged {
            // Dead-heavy → the rescue reaps its way out; live-full (rescue says TractFull) → grow, the spine-only move no fence refuses. Best-effort both ways: a vault that can't heal still opens readable.
            if let Err(Error::TractFull) = v.rescue(rescue_now) {
                let _ = v.grow(v.tract.len * 2, rescue_now);
            }
        }
        Ok(v)
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
        if self.live.map.get(&lba) != Some(&hash) {
            return Ok(false);
        }
        Ok(self.get(key)?.as_deref() == Some(value))
    }

    pub fn put(&mut self, key: &[u8; 32], value: &[u8], now: i64) -> Result<()> {
        if self.holds_committed(key, value)? {
            return Ok(());
        }
        self.put_no_commit(key, value, now)?;
        // A commit whose FLUSH finds no room surfaces TractFull raw (grow inside commit would discard the very state being flushed). We still hold the item, so the verdict is ours: grow — a barrier that reloads the committed head — and replay from pristine.
        if let Err(Error::TractFull) = self.commit(now) {
            self.grow(self.tract.len * 2, now)?;
            self.put_no_commit(key, value, now)?;
            self.commit(now)?;
        }
        self.maybe_reap(now)?;
        Ok(())
    }

    /// The put ladder WITHOUT the final commit — the entry sits provisional in the arena until the next [`commit`](Self::commit) (which [`put`](Self::put) and [`put_batch`](Self::put_batch) supply). A Fenced retry still commits mid-ladder (that IS how the fence rises), so a tight window degrades toward commit-per-write, never past it.
    fn put_no_commit(&mut self, key: &[u8; 32], value: &[u8], now: i64) -> Result<()> {
        // One growth per call: repeated doubling inside the retry loop would balloon the device on a vault whose real ailment is something else. The growth verdict is BOUND EXHAUSTION, not any single error: a ladder that reaped and rescued a full lap and still never landed the put is a working set that has outgrown its tract (field-shaped test, 2026-08-25: a 64-block tract thrashed at budget≈0 forever because every rescue helped a little and nothing ever concluded "too small").
        let mut grew = false;
        loop {
        // Bound: cleaning advances the reap every iteration, so a full lap of windows plus the fence ladder is guaranteed to terminate.
        for _ in 0..(FENCE_K + 3 + (self.tract.len / self.reap_window()) + 8) {
            let attempt = {
                let Self { ring, tract, hamt, .. } = self;
                hamt.put(ring.mirror(), tract, key, value)
            };
            match attempt {
                Ok(()) => return Ok(()),                Err(Error::Fenced(_)) => {
                    // Slides old entries out of the K-window → fence rises. A commit that is ITSELF fenced past the heartbeat ladder is the terminal deadlock — the rescue is the exit, but ONLY against a pristine index: the field's 214 lost blocks (2026-08-24) were relocations whose repoint descents hunted pointers thru THIS put's own half-mutated arena and missed silently. Roll the in-flight put back to the committed root (its provisional appends become orphans a later window reaps), rescue clean, and let the loop retry the put from scratch.
                    if let Err(Error::Fenced(_)) = self.commit(now) {
                        let (h, l) = {
                            let head = self.ring.head().ok_or_else(|| {
                                Error::Corrupt("rescue on pre-genesis vault".into())
                            })?;
                            (head.hamt_hash, head.hamt_lba)
                        };
                        self.hamt = Hamt::from_root(h, l);
                        match self.rescue(now) {
                            Ok(_) => {}
                            Err(Error::TractFull) if !grew => {
                                self.grow(self.tract.len * 2, now)?;
                                grew = true;
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }
                Err(Error::TractFull) => {
                    // The ordinary reap first; when IT can't move (fence-clamped or airlocked), the same rescue ladder as the Fenced arm — physical fullness and fence exhaustion are one disease at the terminal stage, and this arm returning bare TractFull was the last way churn could still die (the new-law test caught it).
                    if !self.reap_one_window(now)? {
                        let (h, l) = {
                            let head = self.ring.head().ok_or_else(|| {
                                Error::Corrupt("rescue on pre-genesis vault".into())
                            })?;
                            (head.hamt_hash, head.hamt_lba)
                        };
                        self.hamt = Hamt::from_root(h, l);
                        match self.rescue(now) {
                            Ok(_) => {}
                            Err(Error::TractFull) if !grew => {
                                self.grow(self.tract.len * 2, now)?;
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
        self.grow(self.tract.len * 2, now)?;
        grew = true;
        }
    }

    /// GROUP COMMIT: insert/overwrite MANY entries, durable on return, under ONE spine commit instead of one per write. The commit's flush is the dominant per-op cost in the field (~900ms per put on a busy BTRFS desktop, SIZE-INDEPENDENT — 53 bytes cost the same as 22KB, 2026-08-21), and callers arrive in bursts (kete's librarian drains a queue): N puts under one commit turn N flushes into one. Failure is all-or-nothing from the caller's view — no batch entry is spine-referenced until the single commit lands (a mid-batch Fenced heartbeat-commit can land earlier entries early, which is harmless: durability sooner, never later).
    pub fn put_batch(&mut self, items: &[(&[u8; 32], &[u8])], now: i64) -> Result<()> {
        if items.is_empty() {
            return Ok(());
        }
        // The identical-overwrite skip, batch form: an all-skipped batch commits nothing at all.
        let mut fresh: Vec<(&[u8; 32], &[u8])> = Vec::with_capacity(items.len());
        for &(key, value) in items {
            if !self.holds_committed(key, value)? {
                fresh.push((key, value));
            }
        }
        if fresh.is_empty() {
            return Ok(());
        }
        let items = &fresh[..];
        for (key, value) in items {
            self.put_no_commit(key, value, now)?;
        }
        // Same replay law as put(): commit's TractFull means grow-the-barrier and re-run the whole batch — we still hold every item, and the barrier reset makes the replay start pristine.
        if let Err(Error::TractFull) = self.commit(now) {
            self.grow(self.tract.len * 2, now)?;
            for (key, value) in items {
                self.put_no_commit(key, value, now)?;
            }
            self.commit(now)?;
        }
        self.maybe_reap(now)?;
        Ok(())
    }

    /// Delete, durable on return. Returns false if the key was absent.
    pub fn delete(&mut self, key: &[u8; 32], now: i64) -> Result<bool> {
        let existed = {
            let Self { ring, tract, hamt, .. } = self;
            hamt.delete(ring.mirror(), tract, key)?
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
        if new_tract_blocks < old_len {
            return Err(Error::Corrupt(format!(
                "grow cannot shrink tract: {old_len} -> {new_tract_blocks}"
            )));
        }
        if new_tract_blocks == old_len {
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
        self.hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        self.tract.plow = head.plow;
        let mut live_blocks = Vec::new();
        {
            let Self { ring, tract, hamt, .. } = self;
            hamt.walk_live(ring.mirror(), tract, &mut live_blocks)?;
        }
        self.live = LiveSet::default();
        for (lba, hp) in live_blocks {
            self.live.map.insert(lba, hp);
        }

        // Re-align the cursors so the CLEAN region is exactly the appended zeros and the OCCUPIED region is exactly the old tract: plow' ≡ old_len (appends start at the first new block), reap' = plow' − old_len (≡ 0 — the whole old region awaits the reap, which migrates its live blocks and retires its dead ones window by window).
        // Monotone order is preserved (plow' ≥ plow), so fence comparisons stay sound; pre-grow entries keep their smaller budgets until they age out of the K-window.
        let plow = self.tract.plow;
        let delta = (old_len + new_tract_blocks - plow % new_tract_blocks) % new_tract_blocks;
        self.tract.plow = plow + delta;
        self.tract.reap = self.tract.plow - old_len;
        self.tract.len = new_tract_blocks;
        self.commit(now)
    }

    /// Flush the index, append the next generation, recompute the fence. The transaction commit point — everything before this is provisional.
    ///
    /// Fence deadlock escape: flushing needs tract appends; appends can be fenced; raising the fence needs generations. HEARTBEAT generations break the cycle — spine entries re-asserting the committed head, written into the (unfenced) ring region, sliding old entries out of the K-window.
    pub fn commit(&mut self, now: i64) -> Result<()> {
        let mut attempts = 0u64;
        let (root_hash, root_lba) = loop {
            let r = {
                let Self { ring, tract, hamt, .. } = self;
                hamt.flush(ring.mirror(), tract)
            };
            match r {
                Ok(x) => {
                    let Self { hamt, live, .. } = self;
                    live.apply(hamt.take_delta());
                    break x;
                }
                Err(Error::Fenced(_)) if attempts <= FENCE_K + 2 => {
                    attempts += 1;
                    self.append_heartbeat(now)?;
                }
                // TractFull exits RAW on purpose: grow is a barrier that reloads the committed head, which would silently discard the very state this commit is flushing. The too-small verdict belongs to callers still holding their items — put/put_batch grow and REPLAY (2026-08-25).
                Err(e) => return Err(e),
            }
        };
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
            reap: Some(self.tract.reap),
            live: self.live.len() as u64,
            eagle_time: now,
        };
        self.ring.append(&entry)?;

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

    /// EMERGENCY UN-WEDGE — the fence deadlock's exit (field 2026-08-21/23/24: plows 422745, 307312, 1110637 across three vaults). The terminal state: a committed head whose budget cannot stage even one reap window — cleaning needs budget, budget needs cleaning, and the head faithfully restores the wedge at every reopen. Two waivers break the cycle, both safe by the tract's clean-invariant (reap targets only verifiably live-free space, originals stay sealed until their retiring commit):
    /// 1. The FENCE is waived per window (fence_limit = None) — what that sacrifices is rollback to OLDER generations, never the current committed state; after a wedge that trade is the whole point.
    /// 2. The all-survive worst-case sizing is replaced by ACTUAL survivor counts from the LiveSet (no device I/O) — a dead-heavy window stages nearly nothing, so even clean ≈ 0 makes progress.
    /// Returns the windows reaped. Err(TractFull) = a live block sits hard against the reap with no staging room — genuinely full of live data: grow or refuse (the rescue only ever helps dead-heavy occupancy). Each retiring commit re-fences honestly, so the loop's comfort check reads the true post-rescue budget.
    pub fn rescue(&mut self, now: i64) -> Result<u64> {
        const RESERVE: u64 = 4;
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
                surv += self.live.map.contains_key(&pos) as u64;
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
                self.grow(self.tract.len + self.reap_window() * 4, now)?;
                airlock_grown = true;
                continue;
            }
            self.tract.fence_limit = None;
            {
                let Self { ring, tract, hamt, live, .. } = self;
                hamt.reap_window(ring.mirror(), tract, live, w)?;
            }
            self.commit(now)?;
            windows += 1;
        }
        let fences = self.ring.recent_fences(FENCE_K)?;
        self.tract.fence_limit = fence_from(&fences);
        Ok(windows)
    }

    /// Clean one window at the reap and commit the retiring generation. Returns false when no progress is possible right now (nothing occupied, or not even a one-block window can stage its survivors — the caller's ladder commits/grows and comes back).
    pub fn reap_one_window(&mut self, now: i64) -> Result<bool> {
        let occupied = self.tract.plow - self.tract.reap;
        if occupied == 0 {
            return Ok(false);
        }
        // Reserve a few clean blocks for the retiring commit's index rewrite; size the window to what the clean region can stage (worst case: every block survives).
        const RESERVE: u64 = 4;
        let mut w = self
            .reap_window()
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
        {
            let Self { ring, tract, hamt, live, .. } = self;
            hamt.reap_window(ring.mirror(), tract, live, w)?;
        }
        self.commit(now).map(|_| true)
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
            let Self { ring, tract, hamt, .. } = self;
            hamt.put_legacy_direct_for_tests(ring.mirror(), tract, key, value)?;
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
    let pos = plow % len;
    let mut clean = len;
    for &lba in live.map.keys() {
        let d = (lba + len - pos) % len;
        clean = clean.min(d);
    }
    (plow + clean).saturating_sub(len)
}

// ============================================================================ verified replication ===================================================

/// Outcome of a replication pass.
#[derive(Debug, Default, PartialEq)]
pub struct Replicated {
    pub spine_copied: u64,
    pub tract_copied: u64,
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
    let (gen, slot) = best_gen(dev, n, ring_log2, 0)?;
    Ok((DeviceLayout { spine_base: 0, tract_base: n, has_root: false }, gen, slot))
}

/// Mirror resync — NEVER a file copy. Block-level, hash-compare-skip, write-verified, idempotent; I/O proportional to live + diverged data. Decides the winner by the highest valid generation found in either spine (each device resolved thru its OWN root, so a crash mid-migration on one mirror converges correctly), then converges the loser: root slots, spine slots, then the winner's committed live set.
pub fn verified_replicate<A: BlockDev, B: BlockDev>(
    a: &mut A,
    b: &mut B,
    ring_log2: u8,
) -> Result<Replicated> {
    let (_, gen_a, _) = resolve_layout(a, ring_log2)?;
    let (_, gen_b, _) = resolve_layout(b, ring_log2)?;

    if gen_a >= gen_b {
        replicate_into(a, b, ring_log2)
    } else {
        replicate_into(b, a, ring_log2)
    }
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
        let tract = Tract {
            base: layout.tract_base,
            len: head.tract_blocks,
            plow: head.plow,
            reap: head.reap.unwrap_or(head.plow),
            fence_limit: None,
        };
        let mut hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        let mut live = Vec::new();
        hamt.walk_live(ring.mirror(), &tract, &mut live)?;
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
