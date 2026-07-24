//! COW Hash Array Mapped Trie — HAMT.md mechanics. The object index; it lives inside the tract and is plowed like everything else.
//!
//! 32-way branching, 5 bits of the key per level. Every edit copies the touched path (2-4 nodes) and produces a new root; old roots remain intact and readable — the HAMT root in a spine entry IS the version identifier.
//!
//! Engine deviation from HAMT.md's leaf header (this doc is the flag, per the README's Specs section): every block is sealed by hp = BLAKE3(body) — the crate's ONE verification rule (plow scan, whole-file scan, ring entries, here). The provenance key lives as a FIELD inside the leaf rather than as the header hash, so lookup compares keys explicitly and the seal stays uniform.
//!
//! Self-addressing blocks: internal nodes carry (depth, route — any key beneath them), leaves carry their key, furrows their owner key + index. A relocated block read back from its new position names its own repair path — no reverse-pointer maps, nothing to lose in a crash.

use crate::block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::mirror::Mirror;
use crate::ring::MAGIC;
use crate::tract::{sealed_hp, Liveness, Reloc, Tract};
use vsf::decoding::parse::parse;
use vsf::types::VsfType;

pub const SCHEMA_NODE: &str = "manifestus.hamt";
pub const SCHEMA_LONE: &str = "manifestus.lone";
pub const SCHEMA_EXTENT: &str = "manifestus.extent";
/// Legacy per-lba leaf format — decoded for migration, never written. The reap rewrites such values into extent form the first time it touches one of their blocks.
pub const SCHEMA_DIRECT: &str = "manifestus.direct";
pub const SCHEMA_FURROW: &str = "manifestus.furrow";

use alloc::{format, string::ToString, vec, vec::Vec};
use hashbrown::HashMap;

/// 5-bit chunk of the key at `depth`. 256 bits / 5 = 51 full levels — two distinct keys always diverge within 52.
fn chunk(key: &[u8; 32], depth: u8) -> u8 {
    let bit = depth as usize * 5;
    let byte = bit / 8;
    let off = bit % 8;
    let hi = (key[byte] as u16) << 8;
    let lo = if byte + 1 < 32 { key[byte + 1] as u16 } else { 0 };
    (((hi | lo) >> (11 - off)) & 0x1F) as u8
}

/// (lba, hp) pairs the vault must add to / remove from its live map. Accumulated across operations, drained by `take_delta`.
#[derive(Debug, Default)]
pub struct Delta {
    pub added: Vec<(u64, [u8; 32])>,
    pub removed: Vec<(u64, [u8; 32])>,
}

/// A committed pointer whose target reads as all-zero: a fast-deleted leaf whose index unlink never landed. `route` is a key that descends to the pointer (path chunks set, rest zero).
#[derive(Debug, Clone, PartialEq)]
pub struct StalePointer {
    pub route: [u8; 32],
    pub hash: [u8; 32],
    pub lba: u64,
}

/// A committed pointer whose target no longer holds the block it names — the reap retired the slot and the plow reused it while the pointer survived (pre-fix tombstone damage), or the target decodes but its furrows are gone. Whatever it referenced is LOST; repair prunes the pointer and reports it.
#[derive(Debug, Clone, PartialEq)]
pub struct DanglingPointer {
    pub route: [u8; 32],
    pub hash: [u8; 32],
    pub lba: u64,
    /// The leaf's own key when the leaf still decodes (furrow loss); None when the block itself is foreign/corrupt.
    pub key: Option<[u8; 32]>,
    pub reason: alloc::string::String,
}

/// `base` with the 5-bit chunk at `depth` set to `slot` — threads the descent path down to children so a stale pointer can be routed back to.
fn route_with_chunk(mut base: [u8; 32], depth: u8, slot: u8) -> [u8; 32] {
    let bit = depth as usize * 5;
    let byte = bit / 8;
    let off = bit % 8;
    let window = ((base[byte] as u16) << 8) | if byte + 1 < 32 { base[byte + 1] as u16 } else { 0 };
    let shift = 11 - off;
    let mask = 0x1Fu16 << shift;
    let new = (window & !mask) | ((slot as u16) << shift);
    base[byte] = (new >> 8) as u8;
    if byte + 1 < 32 {
        base[byte + 1] = (new & 0xFF) as u8;
    }
    base
}

#[derive(Debug, Clone, PartialEq)]
enum Child {
    /// On-disk, verified by hash before trust.
    Committed { hash: [u8; 32], lba: u64 },
    /// In the dirty arena, awaiting flush.
    Dirty(usize),
}

/// In-memory internal node (dirty). Committed nodes are decoded into this on COW touch.
#[derive(Debug, Clone)]
struct Node {
    depth: u8,
    /// Any key beneath this node — the self-address: descending `depth` chunks of `route` from the root lands here.
    route: [u8; 32],
    children: Vec<Option<Child>>, // exactly 32
}

impl Node {
    fn new(depth: u8, route: [u8; 32]) -> Self {
        Self { depth, route, children: vec![None; 32] }
    }
}

/// Decoded tract block, by schema.
enum TractDoc {
    Node(Node),
    Lone { key: [u8; 32], value: Vec<u8> },
    /// Extent leaf: the value's furrows as (start, count) runs — any size, one block.
    Extent { key: [u8; 32], size: u64, runs: Vec<(u64, u64)> },
    /// Legacy per-lba leaf. Read-only; rewritten as Extent by the reap.
    Direct { key: [u8; 32], size: u64, furrows: Vec<u64> },
    Furrow { key: [u8; 32], index: u64, payload: Vec<u8> },
}

pub struct Hamt {
    root: Option<Child>,
    arena: Vec<Node>,
    delta: Delta,
}

impl Hamt {
    pub fn empty() -> Self {
        Self { root: None, arena: Vec::new(), delta: Delta::default() }
    }

    /// Resume from a committed root (spine entry's hamt_root). All-zero hash = empty index (genesis convention).
    pub fn from_root(hash: [u8; 32], lba: u64) -> Self {
        let root = if hash == [0u8; 32] {
            None
        } else {
            Some(Child::Committed { hash, lba })
        };
        Self { root, arena: Vec::new(), delta: Delta::default() }
    }

    pub fn is_dirty(&self) -> bool {
        matches!(self.root, Some(Child::Dirty(_)))
    }

    pub fn take_delta(&mut self) -> Delta {
        core::mem::take(&mut self.delta)
    }

    // ======================================================================== lookup =================================================================

    pub fn lookup<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        key: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        let mut current = match &self.root {
            None => return Ok(None),
            Some(c) => c.clone(),
        };
        let mut depth = 0u8;
        loop {
            match current {
                Child::Dirty(idx) => {
                    let node = &self.arena[idx];
                    debug_assert_eq!(node.depth, depth);
                    match &node.children[chunk(key, depth) as usize] {
                        None => return Ok(None),
                        Some(c) => {
                            current = c.clone();
                            depth += 1;
                        }
                    }
                }
                Child::Committed { hash, lba } => {
                    let doc = match read_doc(mirror, tract, lba, &hash)? {
                        None => return Ok(None), // zeroed: fast-deleted target
                        Some(d) => d,
                    };
                    match doc {
                        TractDoc::Node(node) => {
                            match &node.children[chunk(key, depth) as usize] {
                                None => return Ok(None),
                                Some(c) => {
                                    current = c.clone();
                                    depth += 1;
                                }
                            }
                        }
                        TractDoc::Lone { key: k, value } => {
                            return Ok(if &k == key { Some(value) } else { None });
                        }
                        TractDoc::Direct { key: k, size, furrows } => {
                            if &k != key {
                                return Ok(None);
                            }
                            return Ok(Some(read_furrows(mirror, tract, key, size, &furrows)?));
                        }
                        TractDoc::Extent { key: k, size, runs } => {
                            if &k != key {
                                return Ok(None);
                            }
                            let positions = expand_runs(&runs, size)?;
                            return Ok(Some(read_furrows(mirror, tract, key, size, &positions)?));
                        }
                        TractDoc::Furrow { .. } => {
                            return Err(Error::Corrupt("furrow reached via index walk".into()));
                        }
                    }
                }
            }
        }
    }

    // ======================================================================== put ====================================================================

    /// Insert or overwrite. Leaf (and furrow) blocks are appended to the tract IMMEDIATELY (VAULT.md write path: object first, index second); the index path goes dirty in RAM until `flush`. A refused append (Fenced/TractFull) leaves no side effects — the delta is rolled back to its entry state.
    pub fn put<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        key: &[u8; 32],
        value: &[u8],
    ) -> Result<()> {
        let added_mark = self.delta.added.len();
        let removed_mark = self.delta.removed.len();
        let r = self.put_inner(mirror, tract, key, value);
        if r.is_err() {
            self.delta.added.truncate(added_mark);
            self.delta.removed.truncate(removed_mark);
        }
        r
    }

    fn put_inner<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        key: &[u8; 32],
        value: &[u8],
    ) -> Result<()> {
        let lone_max = lone_capacity();
        let (leaf_lba, leaf_hash) = if value.len() <= lone_max {
            let leaf = encode_lone(key, value);
            let lba = tract.append(mirror, core::slice::from_ref(&leaf))?[0];
            let hash = sealed_hp(&leaf).unwrap();
            self.delta.added.push((lba, hash));
            (lba, hash)
        } else {
            // Furrows first (the leaf references their positions, so they must land first).
            // One contiguous append — the runs come back as one extent, two at a ring wrap.
            let per = furrow_capacity();
            let payload: Vec<Block> = value
                .chunks(per)
                .enumerate()
                .map(|(i, c)| encode_furrow(key, i as u64, c))
                .collect();
            let placed = tract.append(mirror, &payload)?;
            for (lba, b) in placed.iter().zip(&payload) {
                self.delta.added.push((*lba, sealed_hp(b).unwrap()));
            }
            let runs = compress_runs(&placed);
            let leaf = encode_extent(key, value.len() as u64, &runs)?;
            let lba = tract.append(mirror, core::slice::from_ref(&leaf))?[0];
            let hash = sealed_hp(&leaf).unwrap();
            self.delta.added.push((lba, hash));
            (lba, hash)
        };

        // Thread the new leaf into the trie (COW path).
        let root = self.root.clone();
        let new_root = self.insert_child(mirror, tract, root, 0, key, Child::Committed { hash: leaf_hash, lba: leaf_lba })?;
        self.root = Some(new_root);
        Ok(())
    }

    /// COW insert: returns the (dirty) replacement for `slot`.
    fn insert_child<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        slot: Option<Child>,
        depth: u8,
        key: &[u8; 32],
        leaf: Child,
    ) -> Result<Child> {
        match slot {
            None => Ok(leaf),
            Some(Child::Dirty(idx)) => {
                let c = chunk(key, depth) as usize;
                let sub = self.arena[idx].children[c].clone();
                let new_sub = self.insert_child(mirror, tract, sub, depth + 1, key, leaf)?;
                self.arena[idx].children[c] = Some(new_sub);
                Ok(Child::Dirty(idx))
            }
            Some(Child::Committed { hash, lba }) => {
                let Some(doc) = read_doc(mirror, tract, lba, &hash)? else {
                    // Stale pointer at a fast-deleted (zeroed) leaf: the new leaf simply replaces it — resurrection after delete.
                    return Ok(leaf);
                };
                match doc {
                    TractDoc::Node(node) => {
                        // COW: committed node enters the arena, then recurse.
                        let idx = self.arena.len();
                        self.arena.push(node);
                        let c = chunk(key, depth) as usize;
                        let sub = self.arena[idx].children[c].clone();
                        let new_sub = self.insert_child(mirror, tract, sub, depth + 1, key, leaf)?;
                        self.arena[idx].children[c] = Some(new_sub);
                        // The committed version is superseded once we flush; record now (flush commits the batch).
                        self.delta.removed.push((lba, hash));
                        Ok(Child::Dirty(idx))
                    }
                    TractDoc::Lone { key: k, .. }
                    | TractDoc::Direct { key: k, .. }
                    | TractDoc::Extent { key: k, .. } => {
                        if &k == key {
                            // Overwrite: the old leaf (and its furrows) become dead.
                            self.remove_leaf_blocks(mirror, tract, lba, &hash)?;
                            return Ok(leaf);
                        }
                        // Key collision on the path so far: split — push internals until the chunks diverge.
                        Ok(self.split(depth, (k, Child::Committed { hash, lba }), (*key, leaf)))
                    }
                    TractDoc::Furrow { .. } => Err(Error::Corrupt("furrow in index position".into())),
                }
            }
        }
    }

    /// Create the internal chain separating two keys from `depth` down.
    fn split(&mut self, depth: u8, a: ([u8; 32], Child), b: ([u8; 32], Child)) -> Child {
        let ca = chunk(&a.0, depth) as usize;
        let cb = chunk(&b.0, depth) as usize;
        let mut node = Node::new(depth, a.0);
        if ca == cb {
            let sub = self.split(depth + 1, a, b);
            node.children[ca] = Some(sub);
        } else {
            node.children[ca] = Some(a.1);
            node.children[cb] = Some(b.1);
        }
        let idx = self.arena.len();
        self.arena.push(node);
        Child::Dirty(idx)
    }

    // ======================================================================== delete =================================================================

    /// Delete: zero the leaf (and furrows) on both mirrors, then COW-unlink the pointer from the index.
    ///
    /// The unlink is load-bearing, not hygiene. The original fast-delete design left the committed pointer stale ("lookups hit the zeroed block and return None; the plow reaps the slots") — but that safety argument only holds while the slot stays zero. The reap correctly retires the zeroed slot as dead, and one plow lap later an append REUSES it; the stale pointer then aims at foreign sealed content, `read_doc` reports Seal instead of None, and the next `walk_live` at open bricks the vault. (Forensic case 2026-07-24: root slot 18 → a leaf deleted ~1500 generations earlier, its slot reused by another key's value.)
    pub fn delete<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        key: &[u8; 32],
    ) -> Result<bool> {
        // Find the leaf lba by walking (without mutating).
        let Some((lba, hash)) = self.find_leaf(mirror, tract, key)? else {
            return Ok(false);
        };
        self.remove_leaf_blocks(mirror, tract, lba, &hash)?;
        // Zero the blocks themselves.
        if let Some(doc) = read_doc(mirror, tract, lba, &hash)? {
            match doc {
                TractDoc::Direct { furrows, .. } => {
                    for f in furrows {
                        tract.zero_delete(mirror, f)?;
                    }
                }
                TractDoc::Extent { size, runs, .. } => {
                    for pos in expand_runs(&runs, size)? {
                        tract.zero_delete(mirror, pos)?;
                    }
                }
                _ => {}
            }
            tract.zero_delete(mirror, lba)?;
        }
        // Unlink the pointer thru the COW path so no committed generation past this one carries it. A crash before the retiring commit leaves the OLD head, whose pointer targets the now-zero slot — still the legal "deleted, reads None" state, and resume prunes it.
        self.prune(mirror, tract, key, (hash, lba))?;
        Ok(true)
    }

    /// COW-unlink the child that points at exactly `old` (hash, lba), descending along `route`. No-op if the pointer is not on that path.
    pub(crate) fn prune<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        route: &[u8; 32],
        old: ([u8; 32], u64),
    ) -> Result<()> {
        let root = self.root.clone();
        let new_root = self.prune_child(mirror, tract, root, 0, route, old)?;
        self.root = new_root;
        Ok(())
    }

    fn prune_child<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        slot: Option<Child>,
        depth: u8,
        route: &[u8; 32],
        old: ([u8; 32], u64),
    ) -> Result<Option<Child>> {
        match slot {
            None => Ok(None),
            Some(Child::Committed { hash, lba }) if hash == old.0 && lba == old.1 => Ok(None),
            Some(Child::Dirty(idx)) => {
                let c = chunk(route, depth) as usize;
                let sub = self.arena[idx].children[c].clone();
                let new_sub = self.prune_child(mirror, tract, sub, depth + 1, route, old)?;
                self.arena[idx].children[c] = new_sub;
                Ok(Some(Child::Dirty(idx)))
            }
            Some(Child::Committed { hash, lba }) => {
                let Some(doc) = read_doc(mirror, tract, lba, &hash)? else {
                    // A different stale target on the path (someone else's tombstone) — not ours to touch here.
                    return Ok(Some(Child::Committed { hash, lba }));
                };
                match doc {
                    TractDoc::Node(node) => {
                        let idx = self.arena.len();
                        self.arena.push(node);
                        self.delta.removed.push((lba, hash));
                        let c = chunk(route, depth) as usize;
                        let sub = self.arena[idx].children[c].clone();
                        let new_sub = self.prune_child(mirror, tract, sub, depth + 1, route, old)?;
                        self.arena[idx].children[c] = new_sub;
                        Ok(Some(Child::Dirty(idx)))
                    }
                    _ => Ok(Some(Child::Committed { hash, lba })), // a leaf that isn't the target
                }
            }
        }
    }

    fn find_leaf<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        key: &[u8; 32],
    ) -> Result<Option<(u64, [u8; 32])>> {
        let mut current = match &self.root {
            None => return Ok(None),
            Some(c) => c.clone(),
        };
        let mut depth = 0u8;
        loop {
            match current {
                Child::Dirty(idx) => match &self.arena[idx].children[chunk(key, depth) as usize] {
                    None => return Ok(None),
                    Some(c) => {
                        current = c.clone();
                        depth += 1;
                    }
                },
                Child::Committed { hash, lba } => {
                    let Some(doc) = read_doc(mirror, tract, lba, &hash)? else { return Ok(None) };
                    match doc {
                        TractDoc::Node(node) => match &node.children[chunk(key, depth) as usize] {
                            None => return Ok(None),
                            Some(c) => {
                                current = c.clone();
                                depth += 1;
                            }
                        },
                        TractDoc::Lone { key: k, .. }
                        | TractDoc::Direct { key: k, .. }
                        | TractDoc::Extent { key: k, .. } => {
                            return Ok(if &k == key { Some((lba, hash)) } else { None });
                        }
                        TractDoc::Furrow { .. } => return Err(Error::Corrupt("furrow in index position".into())),
                    }
                }
            }
        }
    }

    /// Record a leaf (and its furrows) as no longer live.
    fn remove_leaf_blocks<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        lba: u64,
        hash: &[u8; 32],
    ) -> Result<()> {
        self.delta.removed.push((lba, *hash));
        match read_doc(mirror, tract, lba, hash)? {
            Some(TractDoc::Direct { furrows, .. }) => {
                let mut buf = ZERO_BLOCK;
                for f in furrows {
                    tract.read(mirror, f, &mut buf)?;
                    if let Some(h) = sealed_hp(&buf) {
                        self.delta.removed.push((f, h));
                    }
                }
            }
            Some(TractDoc::Extent { size, runs, .. }) => {
                let mut buf = ZERO_BLOCK;
                for pos in expand_runs(&runs, size)? {
                    tract.read(mirror, pos, &mut buf)?;
                    if let Some(h) = sealed_hp(&buf) {
                        self.delta.removed.push((pos, h));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ======================================================================== flush ==================================================================

    /// Write every dirty internal node to the tract, bottom-up, and return the new committed root (hash, lba). The all-zero hash means an empty index. Appends never relocate anything, so one pass suffices; a Fenced/TractFull error leaves already-flushed children Committed in the arena and a retry resumes where it stopped.
    pub fn flush<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
    ) -> Result<([u8; 32], u64)> {
        let root = self.root.clone();
        let committed = match root {
            None => return Ok(([0u8; 32], 0)),
            Some(Child::Committed { hash, lba }) => (hash, lba),
            Some(Child::Dirty(idx)) => {
                let (hash, lba) = self.flush_node(mirror, tract, idx)?;
                self.root = Some(Child::Committed { hash, lba });
                (hash, lba)
            }
        };
        self.arena.clear();
        Ok(committed)
    }

    fn flush_node<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        idx: usize,
    ) -> Result<([u8; 32], u64)> {
        // Children first.
        for c in 0..32 {
            if let Some(Child::Dirty(sub)) = self.arena[idx].children[c].clone() {
                let (hash, lba) = self.flush_node(mirror, tract, sub)?;
                self.arena[idx].children[c] = Some(Child::Committed { hash, lba });
            }
        }
        let block = encode_node(&self.arena[idx]);
        let lba = tract.append(mirror, core::slice::from_ref(&block))?[0];
        let hash = sealed_hp(&block).unwrap();
        self.delta.added.push((lba, hash));
        Ok((hash, lba))
    }

    /// Collect (lba, hash) of every live block reachable from the COMMITTED root: internal nodes, leaves, and furrows. The vault rebuilds its live set with this at open. Dirty state is not walked — call after from_root / flush.
    pub fn walk_live<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        out: &mut Vec<(u64, [u8; 32])>,
    ) -> Result<()> {
        let mut stale = Vec::new();
        self.walk_live_collect(mirror, tract, out, &mut stale)
    }

    /// `walk_live` that also reports stale pointers — committed pointers whose target reads as all-zero (a fast-deleted leaf whose unlink never landed: pre-fix vaults, or a crash between the zero and the retiring commit). `route` descends back to the pointer for [`Self::prune`].
    pub fn walk_live_collect<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        out: &mut Vec<(u64, [u8; 32])>,
        stale: &mut Vec<StalePointer>,
    ) -> Result<()> {
        let root = self.root.clone();
        if let Some(Child::Committed { hash, lba }) = root {
            self.walk_child(mirror, tract, lba, &hash, [0u8; 32], 0, out, stale)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_child<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        lba: u64,
        hash: &[u8; 32],
        route: [u8; 32],
        depth: u8,
        out: &mut Vec<(u64, [u8; 32])>,
        stale: &mut Vec<StalePointer>,
    ) -> Result<()> {
        let Some(doc) = read_doc(mirror, tract, lba, hash)? else {
            // Fast-deleted leaf behind a stale pointer: not live — and report it so resume can unlink it before the slot is ever reused.
            stale.push(StalePointer { route, hash: *hash, lba });
            return Ok(());
        };
        out.push((lba, *hash));
        match doc {
            TractDoc::Node(node) => {
                for (slot, c) in node.children.iter().enumerate() {
                    if let Some(Child::Committed { hash, lba }) = c {
                        let (h, l) = (*hash, *lba);
                        let child_route = route_with_chunk(route, depth, slot as u8);
                        self.walk_child(mirror, tract, l, &h, child_route, depth + 1, out, stale)?;
                    }
                }
            }
            TractDoc::Direct { furrows, .. } => {
                let mut buf = ZERO_BLOCK;
                for f in furrows {
                    tract.read(mirror, f, &mut buf)?;
                    if let Some(fh) = sealed_hp(&buf) {
                        out.push((f, fh));
                    }
                }
            }
            TractDoc::Extent { size, runs, .. } => {
                let mut buf = ZERO_BLOCK;
                for pos in expand_runs(&runs, size)? {
                    tract.read(mirror, pos, &mut buf)?;
                    if let Some(fh) = sealed_hp(&buf) {
                        out.push((pos, fh));
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// REPAIR walk — `walk_live_collect` that survives dangling pointers instead of erroring. A pointer whose target fails the seal, fails decode, or names furrows that no longer verify is recorded in `dangling` (and contributes nothing to `out`); everything sound is collected exactly as `walk_live` would. Used by `Vault::open_repairing`.
    pub fn walk_live_repair<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        out: &mut Vec<(u64, [u8; 32])>,
        stale: &mut Vec<StalePointer>,
        dangling: &mut Vec<DanglingPointer>,
    ) -> Result<()> {
        let root = self.root.clone();
        if let Some(Child::Committed { hash, lba }) = root {
            self.walk_child_repair(mirror, tract, lba, &hash, [0u8; 32], 0, out, stale, dangling)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_child_repair<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        lba: u64,
        hash: &[u8; 32],
        route: [u8; 32],
        depth: u8,
        out: &mut Vec<(u64, [u8; 32])>,
        stale: &mut Vec<StalePointer>,
        dangling: &mut Vec<DanglingPointer>,
    ) -> Result<()> {
        let doc = match read_doc(mirror, tract, lba, hash) {
            Ok(None) => {
                stale.push(StalePointer { route, hash: *hash, lba });
                return Ok(());
            }
            Ok(Some(d)) => d,
            Err(Error::Seal) => {
                dangling.push(DanglingPointer {
                    route,
                    hash: *hash,
                    lba,
                    key: None,
                    reason: "target reused: sealed block does not match the pointer hash".into(),
                });
                return Ok(());
            }
            Err(Error::Corrupt(reason)) => {
                dangling.push(DanglingPointer { route, hash: *hash, lba, key: None, reason });
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        match doc {
            TractDoc::Node(node) => {
                out.push((lba, *hash));
                for (slot, c) in node.children.iter().enumerate() {
                    if let Some(Child::Committed { hash, lba }) = c {
                        let (h, l) = (*hash, *lba);
                        let child_route = route_with_chunk(route, depth, slot as u8);
                        self.walk_child_repair(mirror, tract, l, &h, child_route, depth + 1, out, stale, dangling)?;
                    }
                }
            }
            TractDoc::Lone { .. } => out.push((lba, *hash)),
            TractDoc::Direct { key, furrows, .. } => {
                self.repair_check_furrows(mirror, tract, lba, hash, route, &key, &furrows, out, dangling)?;
            }
            TractDoc::Extent { key, size, runs } => match expand_runs(&runs, size) {
                Ok(positions) => {
                    self.repair_check_furrows(mirror, tract, lba, hash, route, &key, &positions, out, dangling)?;
                }
                Err(Error::Corrupt(reason)) => {
                    dangling.push(DanglingPointer { route, hash: *hash, lba, key: Some(key), reason });
                }
                Err(e) => return Err(e),
            },
            TractDoc::Furrow { .. } => {
                dangling.push(DanglingPointer {
                    route,
                    hash: *hash,
                    lba,
                    key: None,
                    reason: "furrow block in index position".into(),
                });
            }
        }
        Ok(())
    }

    /// Verify a sharded value's furrows (seal + owner + index). All sound → leaf and furrows join `out`; any loss → the whole leaf is dangling (a partial value cannot be served).
    #[allow(clippy::too_many_arguments)]
    fn repair_check_furrows<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        leaf_lba: u64,
        leaf_hash: &[u8; 32],
        route: [u8; 32],
        key: &[u8; 32],
        positions: &[u64],
        out: &mut Vec<(u64, [u8; 32])>,
        dangling: &mut Vec<DanglingPointer>,
    ) -> Result<()> {
        let mut furrow_live = Vec::with_capacity(positions.len());
        for (i, pos) in positions.iter().enumerate() {
            let mut buf = ZERO_BLOCK;
            tract.read(mirror, *pos, &mut buf)?;
            let ok = sealed_hp(&buf)
                .filter(|_| {
                    matches!(decode_doc(&buf), Ok(TractDoc::Furrow { key: k, index, .. }) if &k == key && index as usize == i)
                })
                .map(|h| (*pos, h));
            match ok {
                Some(entry) => furrow_live.push(entry),
                None => {
                    dangling.push(DanglingPointer {
                        route,
                        hash: *leaf_hash,
                        lba: leaf_lba,
                        key: Some(*key),
                        reason: format!("furrow {i} @{pos} lost (unsealed/foreign/mismatched owner)"),
                    });
                    return Ok(());
                }
            }
        }
        out.push((leaf_lba, *leaf_hash));
        out.extend(furrow_live);
        Ok(())
    }

    // ======================================================================== the reap ==============================================================

    /// Clean one window at the reap: classify [reap, reap + window), re-append every survivor at the plow (clean space — source and target can never overlap), repair the index thru the COW path, and advance the reap. The caller commits the retiring generation; a crash or error before that commit leaves the committed head pointing at the intact originals and the window simply replays.
    pub fn reap_window<A: BlockDev, B: BlockDev, L: Liveness>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        oracle: &L,
        window: u64,
    ) -> Result<()> {
        let start = tract.reap;
        let w = window.min(tract.plow - start);
        if w == 0 {
            return Ok(());
        }

        // 1. Classify the window. Garbage (zeroed, torn, orphaned, superseded) is simply    not collected; survivors are grouped by what their self-address says they are.
        let mut lones: Vec<(u64, [u8; 32])> = Vec::new();
        let mut leaves: Vec<(u64, [u8; 32])> = Vec::new();
        let mut nodes: Vec<(u64, [u8; 32])> = Vec::new();
        let mut furrow_owners: HashMap<[u8; 32], Vec<(u64, u64)>> = HashMap::new();
        let mut buf = ZERO_BLOCK;
        for m in start..start + w {
            let pos = m % tract.len;
            tract.read(mirror, pos, &mut buf)?;
            let Some(hp) = sealed_hp(&buf) else { continue };
            if !oracle.is_live(pos, &hp) {
                continue;
            }
            match decode_doc(&buf)? {
                TractDoc::Lone { .. } => lones.push((pos, hp)),
                TractDoc::Direct { .. } | TractDoc::Extent { .. } => leaves.push((pos, hp)),
                TractDoc::Node(_) => nodes.push((pos, hp)),
                TractDoc::Furrow { key, index, .. } => {
                    furrow_owners.entry(key).or_default().push((pos, index))
                }
            }
        }

        // 2. Value-data moves, grouped per owner so each leaf is rebuilt once. Per move:
        //    physical copy first, index repair second, liveness delta last — an error    between steps leaves only verified copies that a later window reaps as orphans.
        for (key, mut group) in furrow_owners {
            let Some((leaf_lba, leaf_hash)) = self.find_leaf(mirror, tract, &key)? else {
                continue; // owner deleted — orphan furrows, garbage
            };
            match read_doc(mirror, tract, leaf_lba, &leaf_hash)? {
                Some(TractDoc::Extent { key: k, size, runs }) if k == key => {
                    group.sort_by_key(|&(_, idx)| idx);
                    let mut payload = Vec::with_capacity(group.len());
                    for &(pos, _) in &group {
                        let mut b = ZERO_BLOCK;
                        tract.read(mirror, pos, &mut b)?;
                        payload.push(b);
                    }
                    let placed = tract.append(mirror, &payload)?;
                    // Patch the moved positions into the run list, coalescing.
                    // TODO(scale): expand_runs materializes one u64 per furrow (~24MB
                    // transiently for a 12GB value) — fine on hosts, wants a run-walking
                    // iterator for the no_std kernel profile.
                    let mut positions = expand_runs(&runs, size)?;
                    for (&(_, idx), &newpos) in group.iter().zip(&placed) {
                        let i = idx as usize;
                        if i >= positions.len() {
                            return Err(Error::Corrupt("furrow index beyond its extent".into()));
                        }
                        positions[i] = newpos;
                    }
                    let new_runs = compress_runs(&positions);
                    let new_leaf = encode_extent(&key, size, &new_runs)?;
                    let nl = tract.append(mirror, core::slice::from_ref(&new_leaf))?[0];
                    let nh = sealed_hp(&new_leaf).unwrap();
                    self.replace_leaf(mirror, tract, &key, (leaf_hash, leaf_lba), (nh, nl))?;
                    for (b, &lba) in payload.iter().zip(&placed) {
                        self.delta.added.push((lba, sealed_hp(b).unwrap()));
                    }
                    for (&(pos, _), b) in group.iter().zip(&payload) {
                        self.delta.removed.push((pos, sealed_hp(b).unwrap()));
                    }
                    self.delta.added.push((nl, nh));
                    self.delta.removed.push((leaf_lba, leaf_hash));
                }
                Some(TractDoc::Direct { key: k, size, furrows }) if k == key => {
                    // Legacy per-lba value (bounded by the old ~1MB cap): rewrite whole, upgrading it to extent form. put() retires every old block.
                    let value = read_furrows(mirror, tract, &key, size, &furrows)?;
                    self.put(mirror, tract, &key, &value)?;
                }
                _ => continue,
            }
        }

        // 3. Standalone block moves: leaves first, then nodes (leaf repoints COW ancestor    nodes, superseding some — those are skipped, not moved). A block our own work    already retired (delta.removed) is garbage now.
        for (pos, hp) in lones.into_iter().chain(leaves).chain(nodes) {
            if self.delta.removed.iter().any(|&(l, h)| l == pos && h == hp) {
                continue;
            }
            let mut b = ZERO_BLOCK;
            tract.read(mirror, pos, &mut b)?;
            if sealed_hp(&b) != Some(hp) {
                continue; // changed underneath us — retired by an earlier step
            }
            let to = tract.append(mirror, core::slice::from_ref(&b))?[0];
            self.repair_relocs(mirror, tract, &[Reloc { hp, from: pos, to }])?;
            self.delta.added.push((to, hp));
            self.delta.removed.push((pos, hp));
        }

        tract.reap = start + w;
        Ok(())
    }

    // ======================================================================== index repair ===========================================================

    /// Apply block moves to the index: each moved block self-addresses (leaf → key, node → depth + route), so the repair is a directed descent, no reverse maps. Furrow moves never arrive here — the reap rebuilds their owner's extent list instead.
    pub fn repair_relocs<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        relocs: &[Reloc],
    ) -> Result<()> {
        for r in relocs {
            let mut buf = ZERO_BLOCK;
            tract.read(mirror, r.to, &mut buf)?;
            let Some(hash) = sealed_hp(&buf) else {
                return Err(Error::Corrupt("relocated block unreadable at destination".into()));
            };
            debug_assert_eq!(hash, r.hp);
            match decode_doc(&buf)? {
                TractDoc::Lone { key, .. }
                | TractDoc::Direct { key, .. }
                | TractDoc::Extent { key, .. } => {
                    let root = self.root.clone();
                    let new_root =
                        self.repoint(mirror, tract, root, 0, &key, u8::MAX, (r.hp, r.from), (r.hp, r.to))?;
                    self.root = new_root;
                }
                TractDoc::Furrow { .. } => {
                    return Err(Error::Corrupt("furrow move must be handled by the reap".into()));
                }
                TractDoc::Node(node) => {
                    let root = self.root.clone();
                    let new_root = self.repoint(
                        mirror,
                        tract,
                        root,
                        0,
                        &node.route,
                        node.depth,
                        (r.hp, r.from),
                        (r.hp, r.to),
                    )?;
                    self.root = new_root;
                }
            }
        }
        Ok(())
    }

    /// Swap a leaf pointer for a REBUILT leaf (new hash AND new lba) — the reap's extent-list update.
    fn replace_leaf<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        key: &[u8; 32],
        old: ([u8; 32], u64),
        new: ([u8; 32], u64),
    ) -> Result<()> {
        let root = self.root.clone();
        let new_root = self.repoint(mirror, tract, root, 0, key, u8::MAX, old, new)?;
        self.root = new_root;
        Ok(())
    }

    /// Descend along `key` to the child whose (hash, lba) matches `old`, COWing the path, and swap in `new`; stop at `target_depth` for internal nodes (u8::MAX = leaf hunt).
    #[allow(clippy::too_many_arguments)]
    fn repoint<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        slot: Option<Child>,
        depth: u8,
        key: &[u8; 32],
        target_depth: u8,
        old: ([u8; 32], u64),
        new: ([u8; 32], u64),
    ) -> Result<Option<Child>> {
        match slot {
            None => Ok(None),
            Some(Child::Committed { hash, lba }) if hash == old.0 && lba == old.1 => {
                Ok(Some(Child::Committed { hash: new.0, lba: new.1 }))
            }
            Some(Child::Committed { hash, lba }) => {
                if target_depth != u8::MAX && depth > target_depth + 1 {
                    return Ok(Some(Child::Committed { hash, lba })); // overshoot: not on this path — real depths are ≤ 51 so the +1 cannot overflow, and the MAX sentinel never overshoots
                }
                let Some(doc) = read_doc(mirror, tract, lba, &hash)? else {
                    return Ok(Some(Child::Committed { hash, lba }));
                };
                match doc {
                    TractDoc::Node(node) => {
                        let idx = self.arena.len();
                        self.arena.push(node);
                        self.delta.removed.push((lba, hash));
                        let c = chunk(key, depth) as usize;
                        let sub = self.arena[idx].children[c].clone();
                        let new_sub =
                            self.repoint(mirror, tract, sub, depth + 1, key, target_depth, old, new)?;
                        self.arena[idx].children[c] = new_sub;
                        Ok(Some(Child::Dirty(idx)))
                    }
                    _ => Ok(Some(Child::Committed { hash, lba })), // leaf that isn't the target
                }
            }
            Some(Child::Dirty(idx)) => {
                let c = chunk(key, depth) as usize;
                let sub = self.arena[idx].children[c].clone();
                let new_sub = self.repoint(mirror, tract, sub, depth + 1, key, target_depth, old, new)?;
                self.arena[idx].children[c] = new_sub;
                Ok(Some(Child::Dirty(idx)))
            }
        }
    }

    /// TEST/MIGRATION AID — write a value in the LEGACY per-lba direct format, exactly as pre-extent engines did. Exists so migration tests can build old-format state.
    #[doc(hidden)]
    pub fn put_legacy_direct_for_tests<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        key: &[u8; 32],
        value: &[u8],
    ) -> Result<()> {
        let per = furrow_capacity();
        let payload: Vec<Block> = value
            .chunks(per)
            .enumerate()
            .map(|(i, c)| encode_furrow(key, i as u64, c))
            .collect();
        let placed = tract.append(mirror, &payload)?;
        for (lba, b) in placed.iter().zip(&payload) {
            self.delta.added.push((*lba, sealed_hp(b).unwrap()));
        }
        let leaf = encode_direct(key, value.len() as u64, &placed);
        let lba = tract.append(mirror, core::slice::from_ref(&leaf))?[0];
        let hash = sealed_hp(&leaf).unwrap();
        self.delta.added.push((lba, hash));
        let root = self.root.clone();
        let new_root = self.insert_child(mirror, tract, root, 0, key, Child::Committed { hash, lba })?;
        self.root = Some(new_root);
        Ok(())
    }
}

// ============================================================================ codecs =================================================================

fn put_field(buf: &mut Block, cursor: &mut usize, name: &str, value: VsfType) {
    let n = VsfType::d(name.to_string()).flatten();
    buf[*cursor..*cursor + n.len()].copy_from_slice(&n);
    *cursor += n.len();
    let v = value.flatten();
    buf[*cursor..*cursor + v.len()].copy_from_slice(&v);
    *cursor += v.len();
}

fn seal_block(buf: &mut Block, body_start: usize) {
    let hash = blake3::hash(&buf[body_start..]);
    let hp = VsfType::hp(hash.as_bytes().to_vec()).flatten();
    buf[4..4 + hp.len()].copy_from_slice(&hp);
}

fn begin_block(schema: &str) -> (Block, usize) {
    let mut buf = ZERO_BLOCK;
    buf[..4].copy_from_slice(&MAGIC);
    let hp0 = VsfType::hp(vec![0u8; 32]).flatten();
    let hp_len = hp0.len();
    debug_assert_eq!(4 + hp_len + 1, body_start());
    buf[4..4 + hp_len].copy_from_slice(&hp0);
    buf[4 + hp_len] = b'>';
    let mut cursor = body_start();
    let s = VsfType::d(schema.to_string()).flatten();
    buf[cursor..cursor + s.len()].copy_from_slice(&s);
    cursor += s.len();
    (buf, cursor)
}

/// Computed from the actual hp flatten length — never assumed.
fn body_start() -> usize {
    4 + VsfType::hp(vec![0u8; 32]).flatten().len() + 1
}

/// Max lone value: block minus envelope (schema, key field, value field header) with margin for EWE length growth.
pub fn lone_capacity() -> usize {
    BLOCK - body_start() - (1 << 7)
}

/// Run slots one extent leaf can hold: each run is two EWE fields (start, count), conservatively ≤ 32 bytes, against a 96-byte envelope margin. Fresh values use 1-2 runs regardless of size; only reap-window boundary crossings add fragments, and consecutive windows re-coalesce them — the bound is never approached in practice.
pub fn max_runs() -> usize {
    (BLOCK - body_start() - 96) / 32
}

/// Max furrow payload per block.
pub fn furrow_capacity() -> usize {
    BLOCK - body_start() - (1 << 7)
}

fn encode_lone(key: &[u8; 32], value: &[u8]) -> Block {
    let (mut buf, mut cursor) = begin_block(SCHEMA_LONE);
    put_field(&mut buf, &mut cursor, "key", VsfType::hp(key.to_vec()));
    put_field(&mut buf, &mut cursor, "v", VsfType::v(b'r', value.to_vec()));
    seal_block(&mut buf, body_start());
    buf
}

fn encode_extent(key: &[u8; 32], size: u64, runs: &[(u64, u64)]) -> Result<Block> {
    if runs.len() > max_runs() {
        return Err(Error::Corrupt(format!(
            "extent leaf overflow: {} runs > {} — value pathologically fragmented",
            runs.len(),
            max_runs()
        )));
    }
    let (mut buf, mut cursor) = begin_block(SCHEMA_EXTENT);
    put_field(&mut buf, &mut cursor, "key", VsfType::hp(key.to_vec()));
    put_field(&mut buf, &mut cursor, "size", VsfType::u(size as usize, false));
    for (s, c) in runs {
        put_field(&mut buf, &mut cursor, "s", VsfType::u(*s as usize, false));
        put_field(&mut buf, &mut cursor, "c", VsfType::u(*c as usize, false));
    }
    seal_block(&mut buf, body_start());
    Ok(buf)
}

/// The value's furrow position for every index, in order. Runs never wrap internally (appends split at the ring boundary), so expansion is plain arithmetic.
fn expand_runs(runs: &[(u64, u64)], size: u64) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    for (s, c) in runs {
        for j in 0..*c {
            out.push(s + j);
        }
    }
    let expect = size.div_ceil(furrow_capacity() as u64) as usize;
    if out.len() != expect {
        return Err(Error::Corrupt(format!(
            "extent run total {} != furrow count {expect}",
            out.len()
        )));
    }
    Ok(out)
}

/// Compress an in-order position list back to (start, count) runs.
fn compress_runs(positions: &[u64]) -> Vec<(u64, u64)> {
    let mut runs: Vec<(u64, u64)> = Vec::new();
    for &p in positions {
        match runs.last_mut() {
            Some((s, c)) if *s + *c == p => *c += 1,
            _ => runs.push((p, 1)),
        }
    }
    runs
}

fn encode_direct(key: &[u8; 32], size: u64, furrows: &[u64]) -> Block {
    let (mut buf, mut cursor) = begin_block(SCHEMA_DIRECT);
    put_field(&mut buf, &mut cursor, "key", VsfType::hp(key.to_vec()));
    put_field(&mut buf, &mut cursor, "size", VsfType::u(size as usize, false));
    for lba in furrows {
        put_field(&mut buf, &mut cursor, "f", VsfType::u(*lba as usize, false));
    }
    seal_block(&mut buf, body_start());
    buf
}

fn encode_furrow(key: &[u8; 32], index: u64, payload: &[u8]) -> Block {
    let (mut buf, mut cursor) = begin_block(SCHEMA_FURROW);
    put_field(&mut buf, &mut cursor, "key", VsfType::hp(key.to_vec()));
    put_field(&mut buf, &mut cursor, "i", VsfType::u(index as usize, false));
    put_field(&mut buf, &mut cursor, "v", VsfType::v(b'r', payload.to_vec()));
    seal_block(&mut buf, body_start());
    buf
}

fn encode_node(node: &Node) -> Block {
    let (mut buf, mut cursor) = begin_block(SCHEMA_NODE);
    put_field(&mut buf, &mut cursor, "depth", VsfType::u(node.depth as usize, false));
    put_field(&mut buf, &mut cursor, "route", VsfType::hp(node.route.to_vec()));
    let mut presence: u32 = 0;
    for (i, c) in node.children.iter().enumerate() {
        if c.is_some() {
            presence |= 1 << i;
        }
    }
    put_field(&mut buf, &mut cursor, "map", VsfType::u(presence as usize, false));
    for c in node.children.iter().flatten() {
        let Child::Committed { hash, lba } = c else {
            panic!("encode_node on un-flushed child");
        };
        put_field(&mut buf, &mut cursor, "ch", VsfType::hp(hash.to_vec()));
        put_field(&mut buf, &mut cursor, "at", VsfType::u(*lba as usize, false));
    }
    seal_block(&mut buf, body_start());
    buf
}

fn as_u64(v: &VsfType) -> Option<u64> {
    match v {
        VsfType::u(x, _) => Some(*x as u64),
        VsfType::u0(b) => Some(*b as u64),
        VsfType::u3(x) => Some(*x as u64),
        VsfType::u4(x) => Some(*x as u64),
        VsfType::u5(x) => Some(*x as u64),
        VsfType::u6(x) => Some(*x),
        VsfType::u7(x) => u64::try_from(*x).ok(),
        _ => None,
    }
}

/// Read + verify a tract block against its expected hash. Ok(None) = zeroed (fast-deleted). Any other mismatch is Corrupt.
fn read_doc<A: BlockDev, B: BlockDev>(
    mirror: &mut Mirror<A, B>,
    tract: &Tract,
    lba: u64,
    expected: &[u8; 32],
) -> Result<Option<TractDoc>> {
    let mut buf = ZERO_BLOCK;
    tract.read(mirror, lba, &mut buf)?;
    if buf == ZERO_BLOCK {
        return Ok(None);
    }
    let Some(hash) = sealed_hp(&buf) else {
        return Err(Error::Corrupt(format!("unsealed block at tract lba {lba}")));
    };
    if &hash != expected {
        return Err(Error::Seal);
    }
    decode_doc(&buf).map(Some)
}

fn decode_doc(block: &Block) -> Result<TractDoc> {
    let mut ptr = 4usize;
    let _hp = parse(block, &mut ptr).map_err(|e| Error::Corrupt(format!("{e:?}")))?;
    ptr += 1; // '>'
    let VsfType::d(schema) = parse(block, &mut ptr).map_err(|e| Error::Corrupt(format!("{e:?}")))? else {
        return Err(Error::Corrupt("missing schema".into()));
    };

    let mut key: Option<[u8; 32]> = None;
    let mut value: Option<Vec<u8>> = None;
    let mut size: Option<u64> = None;
    let mut index: Option<u64> = None;
    let mut depth: Option<u64> = None;
    let mut route: Option<[u8; 32]> = None;
    let mut map: Option<u64> = None;
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut lbas: Vec<u64> = Vec::new();
    let mut furrows: Vec<u64> = Vec::new();
    let mut run_starts: Vec<u64> = Vec::new();
    let mut run_counts: Vec<u64> = Vec::new();

    while block.get(ptr) == Some(&b'd') {
        let VsfType::d(name) = parse(block, &mut ptr).map_err(|e| Error::Corrupt(format!("{e:?}")))? else {
            return Err(Error::Corrupt("bad field name".into()));
        };
        let v = parse(block, &mut ptr).map_err(|e| Error::Corrupt(format!("{e:?}")))?;
        match (name.as_str(), v) {
            ("key", VsfType::hp(h)) => key = Some(h.try_into().map_err(|_| Error::Corrupt("key len".into()))?),
            ("v", VsfType::v(_, bytes)) => value = Some(bytes),
            ("size", ref u) if as_u64(u).is_some() => size = as_u64(u),
            ("i", ref u) if as_u64(u).is_some() => index = as_u64(u),
            ("depth", ref u) if as_u64(u).is_some() => depth = as_u64(u),
            ("route", VsfType::hp(h)) => route = Some(h.try_into().map_err(|_| Error::Corrupt("route len".into()))?),
            ("map", ref u) if as_u64(u).is_some() => map = as_u64(u),
            ("ch", VsfType::hp(h)) => hashes.push(h.try_into().map_err(|_| Error::Corrupt("ch len".into()))?),
            ("at", ref u) if as_u64(u).is_some() => lbas.push(as_u64(u).unwrap()),
            ("f", ref u) if as_u64(u).is_some() => furrows.push(as_u64(u).unwrap()),
            ("s", ref u) if as_u64(u).is_some() => run_starts.push(as_u64(u).unwrap()),
            ("c", ref u) if as_u64(u).is_some() => run_counts.push(as_u64(u).unwrap()),
            _ => {}
        }
    }

    match schema.as_str() {
        SCHEMA_LONE => Ok(TractDoc::Lone {
            key: key.ok_or_else(|| Error::Corrupt("lone: missing key".into()))?,
            value: value.ok_or_else(|| Error::Corrupt("lone: missing value".into()))?,
        }),
        SCHEMA_EXTENT => {
            if run_starts.len() != run_counts.len() {
                return Err(Error::Corrupt("extent: run start/count mismatch".into()));
            }
            Ok(TractDoc::Extent {
                key: key.ok_or_else(|| Error::Corrupt("extent: missing key".into()))?,
                size: size.ok_or_else(|| Error::Corrupt("extent: missing size".into()))?,
                runs: run_starts.into_iter().zip(run_counts).collect(),
            })
        }
        SCHEMA_DIRECT => Ok(TractDoc::Direct {
            key: key.ok_or_else(|| Error::Corrupt("direct: missing key".into()))?,
            size: size.ok_or_else(|| Error::Corrupt("direct: missing size".into()))?,
            furrows,
        }),
        SCHEMA_FURROW => Ok(TractDoc::Furrow {
            key: key.ok_or_else(|| Error::Corrupt("furrow: missing key".into()))?,
            index: index.ok_or_else(|| Error::Corrupt("furrow: missing index".into()))?,
            payload: value.ok_or_else(|| Error::Corrupt("furrow: missing payload".into()))?,
        }),
        SCHEMA_NODE => {
            let presence = map.ok_or_else(|| Error::Corrupt("node: missing map".into()))? as u32;
            if presence.count_ones() as usize != hashes.len() || hashes.len() != lbas.len() {
                return Err(Error::Corrupt("node: presence/children mismatch".into()));
            }
            let mut node = Node::new(
                depth.ok_or_else(|| Error::Corrupt("node: missing depth".into()))? as u8,
                route.ok_or_else(|| Error::Corrupt("node: missing route".into()))?,
            );
            let mut next = 0usize;
            for bit in 0..32 {
                if presence & (1 << bit) != 0 {
                    node.children[bit] = Some(Child::Committed {
                        hash: hashes[next],
                        lba: lbas[next],
                    });
                    next += 1;
                }
            }
            Ok(TractDoc::Node(node))
        }
        other => Err(Error::Corrupt(format!("unknown tract schema: {other}"))),
    }
}

fn read_furrows<A: BlockDev, B: BlockDev>(
    mirror: &mut Mirror<A, B>,
    tract: &Tract,
    key: &[u8; 32],
    size: u64,
    furrows: &[u64],
) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size as usize);
    for (i, lba) in furrows.iter().enumerate() {
        let mut buf = ZERO_BLOCK;
        tract.read(mirror, *lba, &mut buf)?;
        if sealed_hp(&buf).is_none() {
            return Err(Error::Corrupt(format!("furrow {i} unsealed")));
        }
        match decode_doc(&buf)? {
            TractDoc::Furrow { key: k, index, payload } => {
                if &k != key || index as usize != i {
                    return Err(Error::Corrupt(format!("furrow {i} mismatched owner/index")));
                }
                out.extend_from_slice(&payload);
            }
            _ => return Err(Error::Corrupt(format!("furrow {i} wrong schema"))),
        }
    }
    if out.len() as u64 != size {
        return Err(Error::Corrupt("assembled size mismatch".into()));
    }
    Ok(out)
}
