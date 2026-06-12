//! The vault — spine + tract + HAMT composed into a crash-proof keyed object store. VAULT.md write path, CUSTODES.md host resolutions.
//!
//! Commit-per-write by default: `put`/`delete` return durable (a spine entry references the new state on at least one verified mirror). Everything between spine commits is provisional — orphans trample on the next plow pass.
//!
//! Open ladder (CUSTODES.md genesis rule):
//! 1. Bootstrap: ring exponent from slot 0 (walks past killswitch damage).
//! 2. Found → head search → geometry/index/live-set from the committed head.
//! 3. Nothing → WHOLE-FILE scan, both mirrors. Any sealed block anywhere = real vault → refuse to format (recovery ladder, v0 refuses loudly). Zero sealed blocks = trash or fresh → zero the ring, genesis.

use crate::block::{BlockDev, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::hamt::{Delta, Hamt};
use crate::mirror::Mirror;
use crate::ring::{any_sealed_block, zero_ring, Ring, SpineEntry, FENCE_K};
use crate::tract::{Liveness, Reloc, Tract};
use std::collections::HashMap;

/// The vault's knowledge of what is referenced: tract lba → sealing hash. Rebuilt from the committed HAMT at open; maintained by deltas and relocations afterward. This IS the plow's liveness oracle.
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

    pub fn apply_relocs(&mut self, relocs: &[Reloc]) {
        for r in relocs {
            if self.map.get(&r.from) == Some(&r.hp) {
                self.map.remove(&r.from);
            }
            self.map.insert(r.to, r.hp);
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

/// Spin trigger: dead > 25% of the tract (CUSTODES.md). One window per commit keeps amplification incremental.
const SPIN_WINDOW: u64 = 1 << 6;

pub struct Vault<A: BlockDev, B: BlockDev> {
    ring: Ring<A, B>,
    tract: Tract,
    hamt: Hamt,
    live: LiveSet,
}

impl<A: BlockDev, B: BlockDev> Vault<A, B> {
    /// Open an existing vault or genesis a fresh one, per the open ladder above. `default_tract_blocks` sizes genesis only — an existing vault's geometry comes from its head entry, never from arguments.
    pub fn open(mut mirror: Mirror<A, B>, ring_log2: u8, now: i64) -> Result<Self> {
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
            live: 0,
            eagle_time: now,
        };
        ring.append(&entry)?;
        let tract = Tract {
            base: n,
            len: tract_blocks,
            plow: 0,
            fence_limit: None,
        };
        Ok(Self {
            ring,
            tract,
            hamt: Hamt::empty(),
            live: LiveSet::default(),
        })
    }

    fn resume(mirror: Mirror<A, B>, ring_log2: u8) -> Result<Self> {
        let mut ring = Ring::open(mirror, ring_log2)?;
        let head = ring
            .head()
            .ok_or_else(|| Error::Corrupt("bootstrap found entries but head search found none".into()))?
            .clone();
        let n = 1u64 << ring_log2;
        let mut tract = Tract {
            base: n,
            len: head.tract_blocks,
            plow: head.plow,
            fence_limit: None,
        };
        // Host-only truncation guard: the device must hold the committed geometry. The fs is a witness, never the authority.
        let need = n + head.tract_blocks;
        if ring.mirror().block_count() < need {
            return Err(Error::Corrupt(format!(
                "device truncated: committed geometry needs {need} blocks"
            )));
        }
        let mut hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        let mut live_blocks = Vec::new();
        hamt.walk_live(ring.mirror(), &tract, &mut live_blocks)?;
        let mut live = LiveSet::default();
        for (lba, hp) in live_blocks {
            live.map.insert(lba, hp);
        }
        let plows = ring.recent_plows(FENCE_K)?;
        tract.fence_limit = fence_from(&plows, tract.len);
        Ok(Self {
            ring,
            tract,
            hamt,
            live,
        })
    }

    // ======================================================================== KV API =================================================================

    pub fn get(&mut self, key: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        let Self { ring, tract, hamt, .. } = self;
        hamt.lookup(ring.mirror(), tract, key)
    }

    /// Insert/overwrite, durable on return (commit-per-write). A Fenced error is the rollback fence demanding interleaved commits on a tight tract (spec: "correct anyway") — commit no-op generations to slide the fence window forward and retry, bounded by the window depth.
    pub fn put(&mut self, key: &[u8; 32], value: &[u8], now: i64) -> Result<()> {
        for _ in 0..(FENCE_K + 3) {
            let attempt = {
                let Self { ring, tract, hamt, live } = self;
                hamt.put(ring.mirror(), tract, live, key, value)
            };
            match attempt {
                Ok(()) => return self.commit(now),
                Err(Error::Fenced(_)) => {
                    self.commit(now)?; // slides old plows out of the K-window → fence rises
                }
                Err(e) => return Err(e),
            }
        }
        Err(Error::TractFull)
    }

    /// Delete, durable on return. Returns false if the key was absent.
    pub fn delete(&mut self, key: &[u8; 32], now: i64) -> Result<bool> {
        let existed = {
            let Self { ring, tract, hamt, .. } = self;
            hamt.delete(ring.mirror(), tract, key)?
        };
        if existed {
            self.commit(now)?;
        }
        Ok(existed)
    }

    /// Flush the index, append the next generation, recompute the fence, maybe spin. The transaction commit point — everything before this is provisional.
    ///
    /// Fence deadlock escape: flushing needs tract writes; tract writes can be fenced; raising the fence needs generations. HEARTBEAT generations break the cycle — spine entries pointing at the current committed root, written into the (unfenced) ring region, sliding old plows out of the K-window.
    pub fn commit(&mut self, now: i64) -> Result<()> {
        let mut attempts = 0u64;
        let (root_hash, root_lba) = loop {
            let r = {
                let Self { ring, tract, hamt, live } = self;
                hamt.flush(ring.mirror(), tract, live)
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
            live: self.live.len() as u64,
            eagle_time: now,
        };
        self.ring.append(&entry)?;

        // Fence: the last K generations stay fully restorable.
        let plows = self.ring.recent_plows(FENCE_K)?;
        self.tract.fence_limit = fence_from(&plows, self.tract.len);

        // Spin trigger: dead > 25% of tract → one window per commit (incremental, bounded amplification).
        let used = self.tract.plow.min(self.tract.len);
        // live ≤ used: every live-map key is a distinct tract position the plow has already written.
        let dead = used - self.live.len() as u64;
        if dead << 2 > self.tract.len {
            let spin = {
                let Self { ring, tract, live, .. } = self;
                tract.spin_window(ring.mirror(), live, SPIN_WINDOW)
            };
            let relocs = match spin {
                Ok(r) => r,
                Err(Error::Fenced(_)) => return Ok(()), // fence says not yet — future commits raise it
                Err(e) => return Err(e),
            };
            if !relocs.relocations.is_empty() {
                {
                    let Self { ring, tract, hamt, .. } = self;
                    hamt.repair_relocs(ring.mirror(), tract, &relocs.relocations)?;
                }
                self.live.apply_relocs(&relocs.relocations);
                // The repaired index commits with the NEXT generation; spin progress itself is provisional and crash-safe (originals intact behind the fence).
            }
        }
        Ok(())
    }

    /// A generation that changes nothing: same root, same geometry, current plow. Exists to advance the fence window when the tract is too tight to flush.
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
            tract_blocks: self.tract.len,
            hamt_hash: head.hamt_hash,
            hamt_lba: head.hamt_lba,
            plow: self.tract.plow,
            live: self.live.len() as u64,
            eagle_time: now,
        };
        self.ring.append(&entry)?;
        let plows = self.ring.recent_plows(FENCE_K)?;
        self.tract.fence_limit = fence_from(&plows, self.tract.len);
        Ok(())
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

    pub fn degraded(&mut self) -> bool {
        self.ring.mirror().degraded()
    }
}

fn fence_from(plows_newest_first: &[u64], len: u64) -> Option<u64> {
    if plows_newest_first.len() < FENCE_K as usize {
        return None; // genesis era: fewer than K generations exist
    }
    plows_newest_first.iter().min().map(|m| m + len)
}

// ============================================================================ verified replication ===================================================

/// Outcome of a replication pass.
#[derive(Debug, Default, PartialEq)]
pub struct Replicated {
    pub spine_copied: u64,
    pub tract_copied: u64,
}

/// CUSTODES.md mirror resync — NEVER a file copy. Block-level, hash-compare-skip, write-verified, idempotent; I/O proportional to live + diverged data. Decides the winner by the highest valid generation found in either spine, then converges the loser: spine slots first, then the winner's committed live set.
pub fn verified_replicate<A: BlockDev, B: BlockDev>(
    a: &mut A,
    b: &mut B,
    ring_log2: u8,
) -> Result<Replicated> {
    let n = 1u64 << ring_log2;
    let (gen_a, _) = best_gen(a, n, ring_log2)?;
    let (gen_b, _) = best_gen(b, n, ring_log2)?;
    if gen_a == gen_b && gen_a.is_none() {
        return Ok(Replicated::default()); // both pre-genesis
    }

    if gen_a >= gen_b {
        replicate_into(a, b, ring_log2)
    } else {
        replicate_into(b, a, ring_log2)
    }
}

/// Highest valid generation in a single device's spine (full 256-read scan — cheaper and simpler than a solo bisect, and replication is rare).
fn best_gen<D: BlockDev>(dev: &mut D, n: u64, ring_log2: u8) -> Result<(Option<u64>, u64)> {
    use crate::ring::{classify, Classified};
    let mut best: Option<u64> = None;
    let mut slot_of_best = 0u64;
    let mut buf = ZERO_BLOCK;
    for slot in 0..n.min(dev.block_count()) {
        dev.read(slot, &mut buf)?;
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

    // Spine: every slot where the bytes differ, write-verified.
    for slot in 0..n {
        src.read(slot, &mut sbuf)?;
        dst.read(slot, &mut dbuf)?;
        if sbuf != dbuf {
            write_verified_one(dst, slot, &sbuf)?;
            out.spine_copied += 1;
        }
    }

    // Tract: the winner's committed live set, via its head entry. A solo Mirror over a reborrowed device reuses the existing machinery; the borrow ends with the scope.
    let live = {
        let solo: Mirror<&mut S, &mut S> = Mirror::from_parts(Some(&mut *src), None)?;
        let mut ring = Ring::open(solo, ring_log2)?;
        let Some(head) = ring.head().cloned() else {
            return Ok(out);
        };
        let tract = Tract {
            base: n,
            len: head.tract_blocks,
            plow: head.plow,
            fence_limit: None,
        };
        let mut hamt = Hamt::from_root(head.hamt_hash, head.hamt_lba);
        let mut live = Vec::new();
        hamt.walk_live(ring.mirror(), &tract, &mut live)?;
        live
    };

    for (lba, _hp) in live {
        let dev_lba = n + lba;
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
