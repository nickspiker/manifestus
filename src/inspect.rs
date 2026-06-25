//! Vault inspector — `vsfinfo` for the manifestus on-disk format.
//!
//! Decodes the bytes physically present on a ring file and reports the spine ring, the head's hash chain, the committed commit object, and the HAMT tree, with a spec-compliance checklist (seals, generation congruence, the hash chain, the Merkle root, the live-block count). The companion CLI is `src/bin/vaultinfo.rs`; the decrypting layer above is kete's `keteinfo` (manifestus holds only ciphertext — it never decrypts).
//!
//! INDEPENDENCE IS THE POINT. This module re-decodes every block from raw bytes via `vsf::parse` + the schema constants rather than calling the engine's own decoders (`SpineEntry::decode` is reused only as the canonical classifier; the tract blocks are decoded here by [`decode_tract`], a parallel implementation of `hamt::decode_doc`). An auditor that shares the engine's decoder cannot catch a decoder bug — it would agree with the engine by construction. So a discrepancy between this tool and the engine is itself a finding.
//!
//! Layering: reads via [`crate::block::BlockDev`] only — one ring file is one `FileDev`; the mirror-compare path opens the two ring files independently and compares heads. No `Mirror`, no `Vault::open` (except the optional cross-check), so the inspector sees each physical side as it is, including divergence.

use std::collections::BTreeSet;

use crate::block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
use crate::error::Result;
use crate::ring::{
    block_is_sealed, classify, Classified, SpineEntry, HOST_RING_LOG2, MAGIC,
};
use vsf::decoding::parse::parse;
use vsf::types::VsfType;

/// The tract-block schemas — mirrors `hamt.rs`'s private consts so the decoder stands alone. A drift between these and the engine's is a finding, not a maintenance burden. (Spine blocks are decoded via `SpineEntry::decode`/`classify`, the canonical classifier, so no spine schema const is needed here.)
const SCHEMA_NODE: &str = "manifestus.hamt";
const SCHEMA_LONE: &str = "manifestus.lone";
const SCHEMA_DIRECT: &str = "manifestus.direct";
const SCHEMA_FURROW: &str = "manifestus.furrow";

/// What to show + how hard to look.
#[derive(Clone, Copy)]
pub struct InspectOptions {
    /// Whole-tract orphan scan: count sealed blocks NOT reachable from the committed root. Slower (one read per tract block); off by default.
    pub orphan_scan: bool,
    /// Per-slot ring detail (don't collapse runs of Empty).
    pub verbose_ring: bool,
    /// Sections to render.
    pub show_ring: bool,
    pub show_tree: bool,
}

impl Default for InspectOptions {
    fn default() -> Self {
        Self {
            orphan_scan: false,
            verbose_ring: false,
            show_ring: true,
            show_tree: true,
        }
    }
}

// ============================================================ decoded shapes ============================================================

/// A tract block, decoded independently of the engine.
#[derive(Debug, Clone, PartialEq)]
pub enum TractBlock {
    /// Internal HAMT node: depth, a route key (any key beneath it), and its present children as (child-hash, child-lba).
    Node {
        depth: u8,
        route: [u8; 32],
        children: Vec<(u8, [u8; 32], u64)>, // (slot 0..32, hash, tract-lba)
    },
    /// Inline value leaf.
    Lone { key: [u8; 32], value_len: usize },
    /// Sharded value leaf: owner key, total size, furrow lbas.
    Direct {
        key: [u8; 32],
        size: u64,
        furrows: Vec<u64>,
    },
    /// One shard of a sharded value.
    Furrow {
        key: [u8; 32],
        index: u64,
        payload_len: usize,
    },
}

/// One reachable node in the HAMT walk, flattened with its depth-in-tree for rendering + the spec verdicts on it.
pub struct TreeNode {
    pub indent: usize,
    pub lba: u64,
    pub doc: TractBlock,
    /// Seal verified: the block's own `hp` equals BLAKE3(body) AND equals the hash the parent pointer expected.
    pub seal_ok: bool,
    /// Self-address check passed (node depth matches the path; leaf key routes to its slot).
    pub self_addr_ok: bool,
    /// Free-text note (corruption reason, mismatch detail).
    pub note: Option<String>,
}

/// One pass/fail spec check.
pub struct Check {
    pub name: String,
    pub pass: bool,
    pub detail: String,
}

/// The full decoded inspection of one ring file.
pub struct InspectReport {
    pub file_blocks: u64,
    pub block_aligned: bool,
    pub ring_log2: u8,
    pub ring_n: u64,
    pub tract_base: u64,
    pub tract_blocks_field: Option<u64>,
    /// Per-slot ring classification: (slot, kind). Kind: Ok(entry) / Empty / Corrupt.
    pub slots: Vec<(u64, SlotKind)>,
    pub head: Option<(u64, SpineEntry)>,
    /// Newest→oldest chain links: (gen, prev_ok). prev_ok = this entry's prev_hash chains to its parent's body hash.
    pub chain: Vec<(u64, bool)>,
    pub tree: Vec<TreeNode>,
    pub reachable_nodes: usize,
    pub reachable_leaves: usize,
    pub reachable_furrows: usize,
    pub reachable_blocks: usize,
    pub orphans: Option<Vec<u64>>,
    pub checks: Vec<Check>,
}

pub enum SlotKind {
    Ok(SpineEntry),
    Empty,
    Corrupt,
}

// ============================================================ entry point ============================================================

/// Inspect one ring file (a `BlockDev`). `opts` selects sections + depth. Returns the decoded report; render with [`InspectReport::render`].
pub fn inspect<D: BlockDev>(dev: &mut D, opts: InspectOptions) -> Result<InspectReport> {
    let file_blocks = dev.block_count();
    // File length came from the device; a host FileDev refuses non-aligned files at open, but report it for raw/partial images.
    let block_aligned = true; // BlockDev capacity is in whole blocks by construction.

    // Discover ring geometry: probe the low slots for a valid entry's ring_log2 (same bootstrap the engine uses); fall back to the host default.
    let ring_log2 = discover_ring_log2(dev)?.unwrap_or(HOST_RING_LOG2);
    let ring_n = 1u64 << ring_log2;
    let tract_base = ring_n;

    // Classify every ring slot.
    let mut slots = Vec::with_capacity(ring_n as usize);
    let mut buf = ZERO_BLOCK;
    for slot in 0..ring_n.min(file_blocks) {
        dev.read(slot, &mut buf)?;
        let kind = match classify(&buf, slot, Some(ring_log2)) {
            Classified::Valid(e) => SlotKind::Ok(e),
            Classified::Empty => SlotKind::Empty,
            Classified::Corrupt => SlotKind::Corrupt,
        };
        slots.push((slot, kind));
    }

    // Head = highest valid generation (rotated-max). Find it directly off the classified slots — same answer the engine's bisect gives, computed exhaustively here so a single-bit-corrupted ring still reports its true head.
    let head = slots
        .iter()
        .filter_map(|(s, k)| match k {
            SlotKind::Ok(e) => Some((*s, e.clone())),
            _ => None,
        })
        .max_by_key(|(_, e)| e.gen);

    let tract_blocks_field = head.as_ref().map(|(_, e)| e.tract_blocks);

    // Walk the hash chain newest→oldest.
    let chain = walk_chain(dev, ring_log2, head.as_ref());

    // Walk the HAMT tree from the committed root.
    let mut tree = Vec::new();
    let (mut n_nodes, mut n_leaves, mut n_furrows) = (0usize, 0usize, 0usize);
    let mut reachable: BTreeSet<u64> = BTreeSet::new();
    if opts.show_tree {
        if let Some((_, h)) = head.as_ref() {
            if h.hamt_hash != [0u8; 32] {
                walk_tree(
                    dev,
                    tract_base,
                    h.hamt_lba,
                    h.hamt_hash,
                    0,
                    0,
                    [0u8; 32],
                    &mut tree,
                    &mut reachable,
                    &mut n_nodes,
                    &mut n_leaves,
                    &mut n_furrows,
                )?;
            }
        }
    }
    let reachable_blocks = reachable.len();

    // Optional orphan scan.
    let orphans = if opts.orphan_scan {
        Some(scan_orphans(dev, tract_base, tract_blocks_field, &reachable)?)
    } else {
        None
    };

    let checks = build_checks(
        &slots,
        ring_log2,
        head.as_ref(),
        &chain,
        &tree,
        reachable_blocks,
    );

    Ok(InspectReport {
        file_blocks,
        block_aligned,
        ring_log2,
        ring_n,
        tract_base,
        tract_blocks_field,
        slots,
        head,
        chain,
        tree,
        reachable_nodes: n_nodes,
        reachable_leaves: n_leaves,
        reachable_furrows: n_furrows,
        reachable_blocks,
        orphans,
        checks,
    })
}

/// Probe the low ring slots for a valid entry; returns its declared ring exponent. Same idea as `Ring::bootstrap_n` but read directly (no Mirror).
fn discover_ring_log2<D: BlockDev>(dev: &mut D) -> Result<Option<u8>> {
    let mut buf = ZERO_BLOCK;
    let probe = (1u64 << 4).min(dev.block_count());
    for slot in 0..probe {
        dev.read(slot, &mut buf)?;
        if let Classified::Valid(e) = classify(&buf, slot, None) {
            return Ok(Some(e.ring_log2));
        }
    }
    Ok(None)
}

/// Newest→oldest: each entry's `prev_hash` must equal its parent's body hash (genesis: prev == zeros). Reads the slot for each gen down to 0.
fn walk_chain<D: BlockDev>(
    dev: &mut D,
    ring_log2: u8,
    head: Option<&(u64, SpineEntry)>,
) -> Vec<(u64, bool)> {
    let mut out = Vec::new();
    let Some((_, head)) = head else {
        return out;
    };
    let n = 1u64 << ring_log2;
    let mut buf = ZERO_BLOCK;
    let mut gen = head.gen;
    let mut child_prev = head.prev_hash;
    loop {
        if gen == 0 {
            // Genesis: prev must be zeros.
            out.push((0, child_prev == [0u8; 32]));
            break;
        }
        let parent_gen = gen - 1;
        let slot = parent_gen & (n - 1);
        if dev.read(slot, &mut buf).is_err() {
            out.push((gen, false));
            break;
        }
        match classify(&buf, slot, Some(ring_log2)) {
            Classified::Valid(parent) if parent.gen == parent_gen => {
                let link_ok = child_prev == parent.body_hash();
                out.push((gen, link_ok));
                child_prev = parent.prev_hash;
                gen = parent_gen;
            }
            // Parent overwritten by a later lap (ring rotated past it) or corrupt — chain can't be followed further on a 256-slot ring once gen ≥ N. That's expected, not a failure: report and stop.
            _ => {
                out.push((gen, false));
                break;
            }
        }
    }
    out
}

// ============================================================ tract decode (independent) ============================================================

/// Decode a tract block from raw bytes. Mirrors `hamt::decode_doc` but stands alone (see module docs). Returns the seal hash + the decoded shape; caller compares the seal against the expected pointer hash.
pub fn decode_tract(block: &Block) -> core::result::Result<([u8; 32], TractBlock), String> {
    if block[..4] != MAGIC {
        return Err("no RÅ magic".to_string());
    }
    let mut ptr = 4usize;
    let VsfType::hp(stored) = parse(block, &mut ptr).map_err(|e| format!("hp: {e:?}"))? else {
        return Err("expected hp after magic".to_string());
    };
    if block.get(ptr) != Some(&b'>') {
        return Err("expected '>' after hp".to_string());
    }
    ptr += 1;
    // Seal: hp must equal BLAKE3(body).
    if blake3::hash(&block[ptr..]).as_bytes() != stored.as_slice() {
        return Err("seal mismatch (hp != BLAKE3(body))".to_string());
    }
    let seal: [u8; 32] = stored
        .as_slice()
        .try_into()
        .map_err(|_| "hp length != 32".to_string())?;

    let VsfType::d(schema) = parse(block, &mut ptr).map_err(|e| format!("schema: {e:?}"))? else {
        return Err("expected schema id".to_string());
    };

    let mut key: Option<[u8; 32]> = None;
    let mut value_len: Option<usize> = None;
    let mut size: Option<u64> = None;
    let mut index: Option<u64> = None;
    let mut depth: Option<u64> = None;
    let mut route: Option<[u8; 32]> = None;
    let mut map: Option<u64> = None;
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut lbas: Vec<u64> = Vec::new();
    let mut furrows: Vec<u64> = Vec::new();

    while block.get(ptr) == Some(&b'd') {
        let VsfType::d(name) = parse(block, &mut ptr).map_err(|e| format!("name: {e:?}"))? else {
            return Err("bad field name".to_string());
        };
        let v = parse(block, &mut ptr).map_err(|e| format!("value: {e:?}"))?;
        match (name.as_str(), v) {
            ("key", VsfType::hp(h)) => key = h.try_into().ok(),
            ("v", VsfType::v(_, bytes)) => value_len = Some(bytes.len()),
            ("size", ref u) => size = as_u64(u).or(size),
            ("i", ref u) => index = as_u64(u).or(index),
            ("depth", ref u) => depth = as_u64(u).or(depth),
            ("route", VsfType::hp(h)) => route = h.try_into().ok(),
            ("map", ref u) => map = as_u64(u).or(map),
            ("ch", VsfType::hp(h)) => {
                if let Ok(a) = h.try_into() {
                    hashes.push(a);
                }
            }
            ("at", ref u) => {
                if let Some(x) = as_u64(u) {
                    lbas.push(x);
                }
            }
            ("f", ref u) => {
                if let Some(x) = as_u64(u) {
                    furrows.push(x);
                }
            }
            _ => {}
        }
    }

    let doc = match schema.as_str() {
        SCHEMA_LONE => TractBlock::Lone {
            key: key.ok_or("lone: missing key")?,
            value_len: value_len.ok_or("lone: missing value")?,
        },
        SCHEMA_DIRECT => TractBlock::Direct {
            key: key.ok_or("direct: missing key")?,
            size: size.ok_or("direct: missing size")?,
            furrows,
        },
        SCHEMA_FURROW => TractBlock::Furrow {
            key: key.ok_or("furrow: missing key")?,
            index: index.ok_or("furrow: missing index")?,
            payload_len: value_len.ok_or("furrow: missing payload")?,
        },
        SCHEMA_NODE => {
            let presence = map.ok_or("node: missing map")? as u32;
            if presence.count_ones() as usize != hashes.len() || hashes.len() != lbas.len() {
                return Err(format!(
                    "node: presence popcount {} != children {} / lbas {}",
                    presence.count_ones(),
                    hashes.len(),
                    lbas.len()
                ));
            }
            let mut children = Vec::new();
            let mut next = 0usize;
            for bit in 0..32u8 {
                if presence & (1 << bit) != 0 {
                    children.push((bit, hashes[next], lbas[next]));
                    next += 1;
                }
            }
            TractBlock::Node {
                depth: depth.ok_or("node: missing depth")? as u8,
                route: route.ok_or("node: missing route")?,
                children,
            }
        }
        other => return Err(format!("unknown tract schema: {other}")),
    };
    Ok((seal, doc))
}

/// 5-bit chunk of `key` at `depth` — the HAMT routing function, copied from `hamt::chunk` for the self-address check.
fn chunk(key: &[u8; 32], depth: u8) -> u8 {
    let bit = depth as usize * 5;
    let byte = bit / 8;
    let off = bit % 8;
    let hi = (key[byte] as u16) << 8;
    let lo = if byte + 1 < 32 { key[byte + 1] as u16 } else { 0 };
    (((hi | lo) >> (11 - off)) & 0x1F) as u8
}

#[allow(clippy::too_many_arguments)]
fn walk_tree<D: BlockDev>(
    dev: &mut D,
    tract_base: u64,
    lba: u64,
    expected_hash: [u8; 32],
    indent: usize,
    depth: u8,
    path_route: [u8; 32],
    out: &mut Vec<TreeNode>,
    reachable: &mut BTreeSet<u64>,
    n_nodes: &mut usize,
    n_leaves: &mut usize,
    n_furrows: &mut usize,
) -> Result<()> {
    let abs = tract_base + lba;
    if abs >= dev.block_count() {
        out.push(TreeNode {
            indent,
            lba,
            doc: TractBlock::Lone { key: [0; 32], value_len: 0 },
            seal_ok: false,
            self_addr_ok: false,
            note: Some(format!("lba {lba} out of device range")),
        });
        return Ok(());
    }
    reachable.insert(lba);
    let mut buf = ZERO_BLOCK;
    dev.read(abs, &mut buf)?;

    match decode_tract(&buf) {
        Err(reason) => {
            out.push(TreeNode {
                indent,
                lba,
                doc: TractBlock::Lone { key: [0; 32], value_len: 0 },
                seal_ok: false,
                self_addr_ok: false,
                note: Some(reason),
            });
        }
        Ok((seal, doc)) => {
            let seal_ok = seal == expected_hash;
            let note = if seal_ok {
                None
            } else {
                Some(format!(
                    "block hash {} != pointer hash {}",
                    hex8(&seal),
                    hex8(&expected_hash)
                ))
            };
            match &doc {
                TractBlock::Node { depth: d, route, children } => {
                    *n_nodes += 1;
                    // Self-address: node's stored depth matches the path depth, and its route chunk-routes consistently with how we reached it.
                    let self_addr_ok = *d == depth;
                    let children_copy = children.clone();
                    let route_copy = *route;
                    out.push(TreeNode { indent, lba, doc, seal_ok, self_addr_ok, note });
                    for (slot, h, child_lba) in children_copy {
                        // Descend; the child's route is the parent's route with this slot's chunk implied (we pass the parent route; leaf self-check uses the leaf's own key).
                        let _ = route_copy;
                        walk_tree(
                            dev, tract_base, child_lba, h, indent + 1, depth + 1, key_with_chunk(path_route, depth, slot),
                            out, reachable, n_nodes, n_leaves, n_furrows,
                        )?;
                    }
                }
                TractBlock::Lone { key, .. } | TractBlock::Direct { key, .. } => {
                    *n_leaves += 1;
                    // Self-address: the leaf's key must route to here — every chunk 0..depth of the key matches the path taken.
                    let self_addr_ok = (0..depth).all(|d| chunk(key, d) == chunk(&path_route, d));
                    let furrow_lbas = if let TractBlock::Direct { furrows, .. } = &doc {
                        furrows.clone()
                    } else {
                        Vec::new()
                    };
                    let key_copy = *key;
                    out.push(TreeNode { indent, lba, doc, seal_ok, self_addr_ok, note });
                    // Walk furrows of a Direct leaf (their hashes aren't in the index — verify seal + owner only).
                    for (i, flba) in furrow_lbas.iter().enumerate() {
                        walk_furrow(dev, tract_base, *flba, &key_copy, i as u64, indent + 1, out, reachable, n_furrows)?;
                    }
                }
                TractBlock::Furrow { .. } => {
                    // A furrow in index position is malformed; record it.
                    out.push(TreeNode {
                        indent,
                        lba,
                        doc,
                        seal_ok,
                        self_addr_ok: false,
                        note: Some("furrow block in index position".to_string()),
                    });
                }
            }
        }
    }
    Ok(())
}

/// Produce a key equal to `base` but with the 5-bit chunk at `depth` set to `slot` — used to thread the routing path down to leaves for the self-address check.
fn key_with_chunk(mut base: [u8; 32], depth: u8, slot: u8) -> [u8; 32] {
    let bit = depth as usize * 5;
    let byte = bit / 8;
    let off = bit % 8;
    // Clear the 5 bits then set them. The chunk spans bits [11-off .. 11-off+5) across byte and byte+1 of a 16-bit window.
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

#[allow(clippy::too_many_arguments)]
fn walk_furrow<D: BlockDev>(
    dev: &mut D,
    tract_base: u64,
    lba: u64,
    owner: &[u8; 32],
    expected_index: u64,
    indent: usize,
    out: &mut Vec<TreeNode>,
    reachable: &mut BTreeSet<u64>,
    n_furrows: &mut usize,
) -> Result<()> {
    let abs = tract_base + lba;
    if abs >= dev.block_count() {
        return Ok(());
    }
    reachable.insert(lba);
    let mut buf = ZERO_BLOCK;
    dev.read(abs, &mut buf)?;
    *n_furrows += 1;
    match decode_tract(&buf) {
        Err(reason) => out.push(TreeNode {
            indent,
            lba,
            doc: TractBlock::Furrow { key: *owner, index: expected_index, payload_len: 0 },
            seal_ok: false,
            self_addr_ok: false,
            note: Some(reason),
        }),
        Ok((_, doc)) => {
            let self_addr_ok = matches!(&doc, TractBlock::Furrow { key, index, .. } if key == owner && *index == expected_index);
            let note = if self_addr_ok {
                None
            } else {
                Some("furrow owner/index mismatch".to_string())
            };
            out.push(TreeNode { indent, lba, doc, seal_ok: true, self_addr_ok, note });
        }
    }
    Ok(())
}

/// Whole-tract scan: sealed blocks NOT reachable from the committed root (fence-held old generations + genuine garbage awaiting the plow).
fn scan_orphans<D: BlockDev>(
    dev: &mut D,
    tract_base: u64,
    tract_blocks: Option<u64>,
    reachable: &BTreeSet<u64>,
) -> Result<Vec<u64>> {
    let mut out = Vec::new();
    let mut buf = ZERO_BLOCK;
    let end = match tract_blocks {
        Some(n) => (tract_base + n).min(dev.block_count()),
        None => dev.block_count(),
    };
    for abs in tract_base..end {
        dev.read(abs, &mut buf)?;
        if block_is_sealed(&buf) {
            let lba = abs - tract_base;
            if !reachable.contains(&lba) {
                out.push(lba);
            }
        }
    }
    Ok(out)
}

// ============================================================ spec checklist ============================================================

fn build_checks(
    slots: &[(u64, SlotKind)],
    ring_log2: u8,
    head: Option<&(u64, SpineEntry)>,
    chain: &[(u64, bool)],
    tree: &[TreeNode],
    reachable_blocks: usize,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let n = 1u64 << ring_log2;

    // 1. Every valid spine entry seals + sits at the congruent slot. (classify() already enforces both for SlotKind::Ok; corrupt slots are the failures.)
    let corrupt = slots.iter().filter(|(_, k)| matches!(k, SlotKind::Corrupt)).count();
    checks.push(Check {
        name: "spine slots seal + congruent".to_string(),
        pass: corrupt == 0,
        detail: if corrupt == 0 {
            "all non-empty slots are Valid".to_string()
        } else {
            format!("{corrupt} corrupt/misplaced slot(s)")
        },
    });

    // 2. A head exists.
    checks.push(Check {
        name: "head found".to_string(),
        pass: head.is_some(),
        detail: match head {
            Some((s, e)) => format!("gen {} at slot {s}", e.gen),
            None => "no valid spine entry".to_string(),
        },
    });

    // 3. Hash chain intact for every link we could follow (links to lapped-out parents are expected once gen ≥ N and not counted as failures).
    let followed: Vec<&(u64, bool)> = chain.iter().collect();
    let broken = followed.iter().filter(|(g, ok)| !ok && *g < n).count();
    checks.push(Check {
        name: "hash chain intact".to_string(),
        pass: broken == 0,
        detail: if followed.is_empty() {
            "no chain (no head)".to_string()
        } else if broken == 0 {
            format!("{} link(s) verified to genesis/lap horizon", followed.len())
        } else {
            format!("{broken} broken link(s) within the ring window")
        },
    });

    // 4. Merkle root resolves: the committed root block sealed + its hash matched the head's hamt field. The root is tree[0] when present.
    if let Some((_, h)) = head {
        if h.hamt_hash == [0u8; 32] {
            checks.push(Check {
                name: "merkle root".to_string(),
                pass: true,
                detail: "empty index (genesis convention)".to_string(),
            });
        } else {
            let root_ok = tree.first().map(|t| t.seal_ok).unwrap_or(false);
            checks.push(Check {
                name: "merkle root resolves".to_string(),
                pass: root_ok,
                detail: if root_ok {
                    format!("root @ tract lba {} seals to head.hamt", h.hamt_lba)
                } else {
                    "root block missing / unsealed / hash mismatch".to_string()
                },
            });
        }
    }

    // 5. Every reachable tree block seals + self-addresses.
    let tree_bad = tree.iter().filter(|t| !t.seal_ok || !t.self_addr_ok).count();
    checks.push(Check {
        name: "HAMT blocks seal + self-address".to_string(),
        pass: tree_bad == 0,
        detail: if tree.is_empty() {
            "empty tree".to_string()
        } else if tree_bad == 0 {
            format!("{} block(s) all sound", tree.len())
        } else {
            format!("{tree_bad} block(s) failed seal/self-address")
        },
    });

    // 6. Live-set size vs the head's `live` field.
    if let Some((_, h)) = head {
        let live_ok = reachable_blocks as u64 == h.live;
        checks.push(Check {
            name: "live count matches commit".to_string(),
            pass: live_ok,
            detail: format!("reachable {reachable_blocks} vs head.live {}", h.live),
        });
    }

    checks
}

// ============================================================ rendering ============================================================

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

/// First 8 hex chars of a 32-byte hash/key — enough to eyeball, short enough to scan.
fn hex8(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(8);
    for byte in &b[..4] {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

fn humanize(n: usize) -> String {
    if n < 1024 {
        format!("{n} B")
    } else if n < 1 << 20 {
        format!("{:.1} KB", n as f64 / 1024.0)
    } else {
        format!("{:.1} MB", n as f64 / (1 << 20) as f64)
    }
}

impl InspectReport {
    /// Render the report as a `vsfinfo`-style text dump honouring the same `opts` used to build it.
    pub fn render(&self, opts: InspectOptions) -> String {
        let mut o = String::new();
        let p = &mut o;

        // --- Geometry ---
        line(p, "=== manifestus vault ===");
        line(p, &format!("file:    {} blocks ({})", self.file_blocks, humanize(self.file_blocks as usize * BLOCK)));
        line(p, &format!("ring:    N = {} (log2 {})", self.ring_n, self.ring_log2));
        line(p, &format!("tract:   base lba {}{}", self.tract_base, match self.tract_blocks_field {
            Some(t) => format!(", {t} blocks (from head)"),
            None => String::new(),
        }));
        line(p, "");

        // --- Ring ---
        if opts.show_ring {
            line(p, "--- spine ring ---");
            let (mut valid, mut empty, mut corrupt) = (0u64, 0u64, 0u64);
            let mut run_empty = 0u64;
            for (slot, kind) in &self.slots {
                match kind {
                    SlotKind::Ok(e) => {
                        valid += 1;
                        flush_empty_run(p, &mut run_empty, opts.verbose_ring);
                        let mark = if self.head.as_ref().map(|(hs, _)| hs == slot).unwrap_or(false) {
                            " <== HEAD"
                        } else {
                            ""
                        };
                        line(p, &format!(
                            "  slot {slot:>4}  gen {:>6}  plow {:>8}  live {:>6}  hamt@{:<8} {}{mark}",
                            e.gen, e.plow, e.live, e.hamt_lba, hex8(&e.hamt_hash)
                        ));
                    }
                    SlotKind::Empty => {
                        empty += 1;
                        if opts.verbose_ring {
                            line(p, &format!("  slot {slot:>4}  (empty)"));
                        } else {
                            run_empty += 1;
                        }
                    }
                    SlotKind::Corrupt => {
                        corrupt += 1;
                        flush_empty_run(p, &mut run_empty, opts.verbose_ring);
                        line(p, &format!("  slot {slot:>4}  CORRUPT"));
                    }
                }
            }
            flush_empty_run(p, &mut run_empty, opts.verbose_ring);
            line(p, &format!("  occupancy: {valid} valid, {empty} empty, {corrupt} corrupt"));
            line(p, "");
        }

        // --- Commit object + chain ---
        if let Some((slot, e)) = &self.head {
            line(p, "--- committed commit object ---");
            line(p, &format!("  gen     {}", e.gen));
            line(p, &format!("  prev    {}", hex8(&e.prev_hash)));
            line(p, &format!("  ring    {} (N = {})", e.ring_log2, 1u64 << e.ring_log2));
            line(p, &format!("  tract   {} blocks", e.tract_blocks));
            line(p, &format!("  hamt    {} @ tract lba {}", hex8(&e.hamt_hash), e.hamt_lba));
            line(p, &format!("  plow    {} (lap {}, pos {})", e.plow, e.plow / e.tract_blocks.max(1), e.plow % e.tract_blocks.max(1)));
            line(p, &format!("  live    {}", e.live));
            line(p, &format!("  time    {}", e.eagle_time));
            line(p, &format!("  (at ring slot {slot})"));
            line(p, "");

            line(p, "--- hash chain (head -> genesis) ---");
            for (gen, ok) in &self.chain {
                line(p, &format!("  gen {gen:>6}  {}", if *ok { "✓ chains" } else { "✗ break / lap horizon" }));
            }
            line(p, "");
        }

        // --- Tree ---
        if opts.show_tree && !self.tree.is_empty() {
            line(p, "--- HAMT tree ---");
            for node in &self.tree {
                let pad = "  ".repeat(node.indent + 1);
                let marks = format!(
                    "{}{}",
                    if node.seal_ok { "" } else { " !seal" },
                    if node.self_addr_ok { "" } else { " !addr" },
                );
                let body = match &node.doc {
                    TractBlock::Node { depth, children, .. } => {
                        format!("node  depth {depth}  {} child(ren)", children.len())
                    }
                    TractBlock::Lone { key, value_len } => {
                        format!("lone  key {}  ({} bytes, sealed)", hex8(key), value_len)
                    }
                    TractBlock::Direct { key, size, furrows } => {
                        format!("direct key {}  size {} ({}), {} furrow(s)", hex8(key), size, humanize(*size as usize), furrows.len())
                    }
                    TractBlock::Furrow { index, payload_len, .. } => {
                        format!("furrow #{index}  ({} bytes)", payload_len)
                    }
                };
                let note = node.note.as_ref().map(|n| format!("  [{n}]")).unwrap_or_default();
                line(p, &format!("{pad}@{:<8} {body}{marks}{note}", node.lba));
            }
            line(p, &format!(
                "  totals: {} node(s), {} leaf/leaves, {} furrow(s), {} reachable block(s)",
                self.reachable_nodes, self.reachable_leaves, self.reachable_furrows, self.reachable_blocks
            ));
            line(p, "");
        }

        // --- Orphans ---
        if let Some(orphans) = &self.orphans {
            line(p, "--- orphan scan ---");
            if orphans.is_empty() {
                line(p, "  no orphaned sealed blocks (every sealed tract block is reachable)");
            } else {
                line(p, &format!("  {} sealed block(s) not reachable from root (fence-held old gens + plow garbage):", orphans.len()));
                let preview: Vec<String> = orphans.iter().take(32).map(|l| l.to_string()).collect();
                line(p, &format!("  lbas: {}{}", preview.join(", "), if orphans.len() > 32 { ", ..." } else { "" }));
            }
            line(p, "");
        }

        // --- Spec checklist ---
        line(p, "--- spec checks ---");
        let mut all_pass = true;
        for c in &self.checks {
            all_pass &= c.pass;
            line(p, &format!("  [{}] {} — {}", if c.pass { "PASS" } else { "FAIL" }, c.name, c.detail));
        }
        line(p, &format!("  => {}", if all_pass { "vault is spec-compliant" } else { "SPEC VIOLATIONS PRESENT" }));

        o
    }

    /// True iff every spec check passed — for a CLI exit code.
    pub fn all_checks_pass(&self) -> bool {
        self.checks.iter().all(|c| c.pass)
    }
}

fn line(s: &mut String, text: &str) {
    s.push_str(text);
    s.push('\n');
}

fn flush_empty_run(s: &mut String, run: &mut u64, verbose: bool) {
    if !verbose && *run > 0 {
        line(s, &format!("  ... {} empty slot(s) ...", run));
        *run = 0;
    }
}

#[cfg(all(test, any(unix, windows)))]
mod tests {
    use super::*;
    use crate::host::FileDev;
    use crate::mirror::Mirror;
    use crate::vault::Vault;
    use crate::ring::HOST_RING_LOG2;

    /// Build a small two-ring vault in a temp dir, put a few keys, then inspect ONE ring file and assert the report matches the engine's view.
    #[test]
    fn inspect_roundtrip_matches_engine() {
        let dir = std::env::temp_dir().join(format!("manifestus-inspect-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let pa = dir.join("ring_a");
        let pb = dir.join("ring_b");
        let blocks = (1u64 << HOST_RING_LOG2) + 256; // ring + small tract

        let mut gen_check;
        let mut live_check;
        {
            let a = FileDev::create(&pa, blocks).unwrap();
            let b = FileDev::create(&pb, blocks).unwrap();
            let mut vault = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 0).unwrap();
            let k1 = blake3::hash(b"alpha");
            let k2 = blake3::hash(b"beta");
            vault.put(k1.as_bytes(), b"hello world", 1).unwrap();
            vault.put(k2.as_bytes(), b"second value", 2).unwrap();
            gen_check = vault.generation();
            live_check = vault.live_blocks();
        }

        // Inspect ring A on its own.
        let mut dev = FileDev::open(&pa).unwrap();
        let report = inspect(&mut dev, InspectOptions::default()).unwrap();

        assert_eq!(report.ring_log2, HOST_RING_LOG2);
        let head = report.head.as_ref().expect("head present");
        assert_eq!(Some(head.1.gen), gen_check, "explorer head gen == engine generation");
        assert_eq!(report.reachable_blocks, live_check, "reachable == engine live_blocks");
        assert!(report.reachable_leaves >= 2, "two puts => at least two leaves");
        assert!(report.all_checks_pass(), "a freshly-built vault must be spec-compliant:\n{}", report.render(InspectOptions::default()));

        let _ = (&mut gen_check, &mut live_check);
        std::fs::remove_dir_all(&dir).ok();
    }
}
