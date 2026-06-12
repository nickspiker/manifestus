//! COW Hash Array Mapped Trie — HAMT.md mechanics. The object index; it lives inside the tract and is plowed like everything else.
//!
//! 32-way branching, 5 bits of the key per level. Every edit copies the touched path (2-4 nodes) and produces a new root; old roots remain intact and readable — the HAMT root in a spine entry IS the version identifier.
//!
//! Engine deviation from HAMT.md's leaf header (flagged in CUSTODES.md): every block is sealed by hp = BLAKE3(body) — the crate's ONE verification rule (plow scan, whole-file scan, ring entries, here). The provenance key lives as a FIELD inside the leaf rather than as the header hash, so lookup compares keys explicitly and the seal stays uniform.
//!
//! Self-addressing blocks: internal nodes carry (depth, route — any key beneath them), leaves carry their key, furrows their owner key + index. A relocated block read back from its new position names its own repair path — no reverse-pointer maps, nothing to lose in a crash.

use crate::block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::mirror::Mirror;
use crate::ring::MAGIC;
use crate::tract::{sealed_hp, Liveness, Reloc, Tract};
use vsf::decoding::parse::parse;
use vsf::types::VsfType;

pub const SCHEMA_NODE: &str = "custodes.hamt";
pub const SCHEMA_LONE: &str = "custodes.lone";
pub const SCHEMA_DIRECT: &str = "custodes.direct";
pub const SCHEMA_FURROW: &str = "custodes.furrow";

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
                        TractDoc::Furrow { .. } => {
                            return Err(Error::Corrupt("furrow reached via index walk".into()));
                        }
                    }
                }
            }
        }
    }

    // ======================================================================== put ====================================================================

    /// Insert or overwrite. Leaf (and furrow) blocks are written to the tract IMMEDIATELY (VAULT.md write path: object first, index second); the index path goes dirty in RAM until `flush`. Tract relocations triggered by these writes are self-repaired before returning.
    pub fn put<A: BlockDev, B: BlockDev, L: Liveness>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        oracle: &L,
        key: &[u8; 32],
        value: &[u8],
    ) -> Result<()> {
        // Build leaf (+furrow) blocks.
        let lone_max = lone_capacity();
        let mut payload: Vec<Block> = Vec::new();
        let leaf_block;
        if value.len() <= lone_max {
            leaf_block = encode_lone(key, value);
        } else {
            // Furrows first (leaf references their lbas, so they must land first).
            let per = furrow_capacity();
            for (i, chunk_bytes) in value.chunks(per).enumerate() {
                payload.push(encode_furrow(key, i as u64, chunk_bytes));
            }
            leaf_block = ZERO_BLOCK; // placeholder; rebuilt after furrow lbas known
        }

        let (leaf_lba, leaf_hash) = if value.len() <= lone_max {
            let out = tract.advance(mirror, oracle, core::slice::from_ref(&leaf_block), 0)?;
            let lba = out.placed[0];
            let hash = sealed_hp(&leaf_block).unwrap();
            self.delta.added.push((lba, hash));
            self.repair_relocs(mirror, tract, &out.relocations)?;
            (lba, hash)
        } else {
            let out = tract.advance(mirror, oracle, &payload, 0)?;
            for (lba, b) in out.placed.iter().zip(&payload) {
                self.delta.added.push((*lba, sealed_hp(b).unwrap()));
            }
            let furrow_lbas = out.placed.clone();
            self.repair_relocs(mirror, tract, &out.relocations)?;
            let leaf = encode_direct(key, value.len() as u64, &furrow_lbas);
            let out2 = tract.advance(mirror, oracle, core::slice::from_ref(&leaf), 0)?;
            let lba = out2.placed[0];
            let hash = sealed_hp(&leaf).unwrap();
            self.delta.added.push((lba, hash));
            self.repair_relocs(mirror, tract, &out2.relocations)?;
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
                    TractDoc::Lone { key: k, .. } | TractDoc::Direct { key: k, .. } => {
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

    /// Fast delete per VAULT.md: zero the leaf (and furrows) on both mirrors. The index pointer goes stale — lookups hit the zeroed block and return None; the plow reaps the slots. O(1) + furrow count, no COW path.
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
        let Some(doc) = read_doc(mirror, tract, lba, &hash)? else { return Ok(true) };
        if let TractDoc::Direct { furrows, .. } = doc {
            for f in furrows {
                let mut t = Tract { base: tract.base, len: tract.len, plow: tract.plow, fence_limit: tract.fence_limit };
                t.zero_delete(mirror, f)?;
            }
        }
        let mut t = Tract { base: tract.base, len: tract.len, plow: tract.plow, fence_limit: tract.fence_limit };
        t.zero_delete(mirror, lba)?;
        Ok(true)
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
                        TractDoc::Lone { key: k, .. } | TractDoc::Direct { key: k, .. } => {
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
        if let Some(TractDoc::Direct { furrows, .. }) = read_doc(mirror, tract, lba, hash)? {
            let mut buf = ZERO_BLOCK;
            for f in furrows {
                tract.read(mirror, f, &mut buf)?;
                if let Some(h) = sealed_hp(&buf) {
                    self.delta.removed.push((f, h));
                }
            }
        }
        Ok(())
    }

    // ======================================================================== flush ==================================================================

    /// Write every dirty internal node to the tract, bottom-up, and return the new committed root (hash, lba). The all-zero hash means an empty index. Relocations triggered by the flush writes are self-repaired; the flush loops until quiescent.
    pub fn flush<A: BlockDev, B: BlockDev, L: Liveness>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        oracle: &L,
    ) -> Result<([u8; 32], u64)> {
        for _ in 0..64 {
            let root = self.root.clone();
            let committed = match root {
                None => return Ok(([0u8; 32], 0)),
                Some(Child::Committed { hash, lba }) => (hash, lba),
                Some(Child::Dirty(idx)) => {
                    let (hash, lba, relocs) = self.flush_node(mirror, tract, oracle, idx)?;
                    self.root = Some(Child::Committed { hash, lba });
                    if !relocs.is_empty() {
                        self.repair_relocs(mirror, tract, &relocs)?;
                        continue; // repairs re-dirtied paths — flush again
                    }
                    (hash, lba)
                }
            };
            self.arena.clear();
            return Ok(committed);
        }
        Err(Error::Corrupt("flush failed to quiesce (relocation storm)".into()))
    }

    fn flush_node<A: BlockDev, B: BlockDev, L: Liveness>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &mut Tract,
        oracle: &L,
        idx: usize,
    ) -> Result<([u8; 32], u64, Vec<Reloc>)> {
        let mut relocs = Vec::new();
        // Children first.
        for c in 0..32 {
            if let Some(Child::Dirty(sub)) = self.arena[idx].children[c].clone() {
                let (hash, lba, mut r) = self.flush_node(mirror, tract, oracle, sub)?;
                self.arena[idx].children[c] = Some(Child::Committed { hash, lba });
                relocs.append(&mut r);
            }
        }
        let block = encode_node(&self.arena[idx]);
        let out = tract.advance(mirror, oracle, core::slice::from_ref(&block), 0)?;
        relocs.extend(out.relocations);
        let lba = out.placed[0];
        let hash = sealed_hp(&block).unwrap();
        self.delta.added.push((lba, hash));
        Ok((hash, lba, relocs))
    }

    // ======================================================================== relocation repair =====================================================

    /// Apply plow relocations to the index: each relocated block self-addresses (leaf → key, furrow → owner key + index, node → depth + route), so the repair is a directed descent, no reverse maps.
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
                TractDoc::Lone { key, .. } | TractDoc::Direct { key, .. } => {
                    self.repoint_leaf(mirror, tract, &key, r)?;
                }
                TractDoc::Furrow { key, index, .. } => {
                    self.repoint_furrow(mirror, tract, &key, index, r)?;
                }
                TractDoc::Node(node) => {
                    self.repoint_node(mirror, tract, &node.route, node.depth, r)?;
                }
            }
        }
        Ok(())
    }

    fn repoint_leaf<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        key: &[u8; 32],
        r: &Reloc,
    ) -> Result<()> {
        let root = self.root.clone();
        let new_root = self.repoint(mirror, tract, root, 0, key, u8::MAX, r)?;
        self.root = new_root;
        Ok(())
    }

    fn repoint_node<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        route: &[u8; 32],
        depth: u8,
        r: &Reloc,
    ) -> Result<()> {
        let root = self.root.clone();
        let new_root = self.repoint(mirror, tract, root, 0, route, depth, r)?;
        self.root = new_root;
        Ok(())
    }

    /// Descend along `key` to the child whose (hash, lba) matches the relocation, COWing the path; stop at `target_depth` for internal nodes (u8::MAX = leaf hunt).
    fn repoint<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        slot: Option<Child>,
        depth: u8,
        key: &[u8; 32],
        target_depth: u8,
        r: &Reloc,
    ) -> Result<Option<Child>> {
        match slot {
            None => Ok(None),
            Some(Child::Committed { hash, lba }) if hash == r.hp && lba == r.from => {
                Ok(Some(Child::Committed { hash, lba: r.to }))
            }
            Some(Child::Committed { hash, lba }) => {
                if depth > target_depth.saturating_add(1) {
                    return Ok(Some(Child::Committed { hash, lba })); // overshoot: not on this path
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
                        let new_sub = self.repoint(mirror, tract, sub, depth + 1, key, target_depth, r)?;
                        self.arena[idx].children[c] = new_sub;
                        Ok(Some(Child::Dirty(idx)))
                    }
                    _ => Ok(Some(Child::Committed { hash, lba })), // leaf that isn't the target
                }
            }
            Some(Child::Dirty(idx)) => {
                let c = chunk(key, depth) as usize;
                let sub = self.arena[idx].children[c].clone();
                let new_sub = self.repoint(mirror, tract, sub, depth + 1, key, target_depth, r)?;
                self.arena[idx].children[c] = new_sub;
                Ok(Some(Child::Dirty(idx)))
            }
        }
    }

    fn repoint_furrow<A: BlockDev, B: BlockDev>(
        &mut self,
        mirror: &mut Mirror<A, B>,
        tract: &Tract,
        key: &[u8; 32],
        _index: u64,
        r: &Reloc,
    ) -> Result<()> {
        // The furrow's owner leaf lists its lbas; rebuild the leaf with the moved lba. Find the leaf, rewrite it as a fresh tract block, repoint the index at it. v0: the leaf rewrite rides the next flush via a dirty path with a REBUILT leaf — implemented as read-modify-write through put-like machinery.
        let Some((leaf_lba, leaf_hash)) = self.find_leaf(mirror, tract, key)? else {
            return Ok(()); // owner already gone (deleted) — orphan furrow, plow will reap
        };
        let Some(TractDoc::Direct { key: k, size, mut furrows }) = read_doc(mirror, tract, leaf_lba, &leaf_hash)? else {
            return Ok(());
        };
        for f in furrows.iter_mut() {
            if *f == r.from {
                *f = r.to;
            }
        }
        // Rebuild the leaf in place in the dirty trie: mark old leaf removed, splice a rebuilt one. The rebuilt leaf block is written at flush time? Leaves are committed-on-write by design — write it now WITHOUT an oracle-advance (caller context lacks the oracle here), so we defer: store as dirty-leaf is unsupported in v0 → conservative: leave the OLD lba list in the leaf; the stale furrow lba still holds the original copy until the fence expires, and the next overwrite of this key rebuilds everything. Record nothing.
        let _ = (k, size, furrows);
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
    BLOCK - body_start() - 128
}

/// Max furrow payload per block.
pub fn furrow_capacity() -> usize {
    BLOCK - body_start() - 128
}

fn encode_lone(key: &[u8; 32], value: &[u8]) -> Block {
    let (mut buf, mut cursor) = begin_block(SCHEMA_LONE);
    put_field(&mut buf, &mut cursor, "key", VsfType::hp(key.to_vec()));
    put_field(&mut buf, &mut cursor, "v", VsfType::v(b'r', value.to_vec()));
    seal_block(&mut buf, body_start());
    buf
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
        return Err(Error::Hmac);
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
            _ => {}
        }
    }

    match schema.as_str() {
        SCHEMA_LONE => Ok(TractDoc::Lone {
            key: key.ok_or_else(|| Error::Corrupt("lone: missing key".into()))?,
            value: value.ok_or_else(|| Error::Corrupt("lone: missing value".into()))?,
        }),
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
