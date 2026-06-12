//! The ring — generation-numbered commit objects, binary-searched. RING.md / VAULT_ROOT.md mechanics; CUSTODES.md host resolutions.
//!
//! Each entry is a complete commit object: parent pointer (prev_hash), content root (hamt_root), geometry (ring/tract), write head (plow), health (live), sealed by hp. Generation g lives at slot `g & (N-1)`. Empty is a verification state, not a generation number — None < Some(0), and generation 0 is legal (first commit, slot 0).
//!
//! Three-way block classification is load-bearing:
//! - Valid(entry): RÅ magic, hp passes, schema matches, congruence g & (N-1) == slot holds.
//! - Empty: zeroed / no magic — expected state (sparse ring, pre-genesis), sorts below all valid.
//! - Corrupt: magic present but hp fails, OR valid-but-misplaced (congruence fails) — AMBIGUOUS, never compared; head search branches both halves around it.

use crate::block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::mirror::Mirror;
use vsf::decoding::parse::parse;
use vsf::types::{EtType, VsfType};

/// "RÅ<" — R, Å (UTF-8 two bytes), '<'. The only magic in the file.
pub const MAGIC: [u8; 4] = [0x52, 0xC3, 0x85, 0x3C];

/// Spine schema identifier. A wire break publishes a new name — per-entry dialect, no superblock.
pub const SCHEMA: &str = "custodes.spine";

/// Host + kernel-STEM ring exponent: N = 256.
pub const HOST_RING_LOG2: u8 = 8;

/// Rollback fence depth: the last K generations are always fully restorable.
pub const FENCE_K: u64 = 1 << 2;

/// One spine commit object. See CUSTODES.md "Spine Entry Format".
#[derive(Debug, Clone, PartialEq)]
pub struct SpineEntry {
    pub gen: u64,
    /// hp of the previous entry's body; genesis = [0u8; 32].
    pub prev_hash: [u8; 32],
    /// Ring exponent r: N = 1 << r. Exponent-encoded — power-of-two BY LAW.
    pub ring_log2: u8,
    /// Tract length in blocks — arbitrary, full EWE (kernel tract is "rest of device").
    pub tract_blocks: u64,
    /// Merkle root of the entire vault state (BLAKE3) + its tract-relative lba.
    pub hamt_hash: [u8; 32],
    pub hamt_lba: u64,
    /// Tract write head, tract-relative.
    pub plow: u64,
    /// Live tract blocks — feeds the spin trigger.
    pub live: u64,
    /// Caller-clock timestamp (eagle oscillations); the engine never interprets it.
    pub eagle_time: i64,
}

impl SpineEntry {
    /// Encode into a full 4KB block: RÅ< hp{body} > schema, then named EWE fields, zero padding. hp covers everything after '>' INCLUDING the padding — tampered padding reads Corrupt.
    pub fn encode(&self) -> Block {
        let mut buf = ZERO_BLOCK;
        buf[..4].copy_from_slice(&MAGIC);

        // Placeholder hp to fix the header length, patched after the body hash is known.
        let hp_placeholder = VsfType::hp(vec![0u8; 32]).flatten();
        let hp_len = hp_placeholder.len();
        buf[4..4 + hp_len].copy_from_slice(&hp_placeholder);
        buf[4 + hp_len] = b'>';
        let body_start = 4 + hp_len + 1;

        let mut cursor = body_start;
        let mut put = |bytes: Vec<u8>, cursor: &mut usize| {
            buf[*cursor..*cursor + bytes.len()].copy_from_slice(&bytes);
            *cursor += bytes.len();
        };

        // Schema id first, standalone — then name:value pairs.
        put(VsfType::d(SCHEMA.to_string()).flatten(), &mut cursor);
        let pairs: Vec<(&str, VsfType)> = vec![
            ("gen", VsfType::u(self.gen as usize, false)),
            ("prev", VsfType::hp(self.prev_hash.to_vec())),
            ("ring", VsfType::u(self.ring_log2 as usize, false)),
            ("tract", VsfType::u(self.tract_blocks as usize, false)),
            ("hamt", VsfType::hp(self.hamt_hash.to_vec())),
            ("hamtat", VsfType::u(self.hamt_lba as usize, false)),
            ("plow", VsfType::u(self.plow as usize, false)),
            ("live", VsfType::u(self.live as usize, false)),
            ("time", VsfType::e(EtType::e6(self.eagle_time))),
        ];
        for (name, value) in pairs {
            put(VsfType::d(name.to_string()).flatten(), &mut cursor);
            put(value.flatten(), &mut cursor);
        }
        debug_assert!(cursor < BLOCK, "spine entry overflowed 4KB");

        // Seal: hp = BLAKE3(body incl. padding), patched into the header.
        let hash = blake3::hash(&buf[body_start..]);
        let hp = VsfType::hp(hash.as_bytes().to_vec()).flatten();
        debug_assert_eq!(hp.len(), hp_len);
        buf[4..4 + hp_len].copy_from_slice(&hp);
        buf
    }

    /// Decode + verify a block. Errors are CLASSIFICATION inputs, not diagnostics — callers map any failure to Corrupt.
    pub fn decode(block: &Block) -> Result<Self> {
        if block[..4] != MAGIC {
            return Err(Error::BadMagic);
        }
        let mut ptr = 4usize;
        let VsfType::hp(stored) = parse(block, &mut ptr).map_err(decode_err)? else {
            return Err(Error::Corrupt("expected hp after magic".into()));
        };
        if block.get(ptr) != Some(&b'>') {
            return Err(Error::Corrupt("expected '>' after hp".into()));
        }
        ptr += 1;

        // Seal check before believing a single field.
        if blake3::hash(&block[ptr..]).as_bytes() != stored.as_slice() {
            return Err(Error::Seal);
        }

        let VsfType::d(schema) = parse(block, &mut ptr).map_err(decode_err)? else {
            return Err(Error::Corrupt("expected schema id".into()));
        };
        if schema != SCHEMA {
            return Err(Error::Corrupt(format!("foreign schema: {schema}")));
        }

        let mut gen = None;
        let mut prev = None;
        let mut ring = None;
        let mut tract = None;
        let mut hamt = None;
        let mut hamtat = None;
        let mut plow = None;
        let mut live = None;
        let mut time = None;

        // Named pairs until zero padding ('d' = 0x64; padding = 0x00). Unknown names are parsed-and-skipped — kernel-profile fields ride thru.
        while block.get(ptr) == Some(&b'd') {
            let VsfType::d(name) = parse(block, &mut ptr).map_err(decode_err)? else {
                return Err(Error::Corrupt("expected field name".into()));
            };
            let value = parse(block, &mut ptr).map_err(decode_err)?;
            match (name.as_str(), value) {
                ("gen", v) if as_u64(&v).is_some() => gen = as_u64(&v),
                ("prev", VsfType::hp(h)) => prev = Some(to32(&h)?),
                ("ring", v) if as_u64(&v).is_some() => ring = as_u64(&v).map(|x| x as u8),
                ("tract", v) if as_u64(&v).is_some() => tract = as_u64(&v),
                ("hamt", VsfType::hp(h)) => hamt = Some(to32(&h)?),
                ("hamtat", v) if as_u64(&v).is_some() => hamtat = as_u64(&v),
                ("plow", v) if as_u64(&v).is_some() => plow = as_u64(&v),
                ("live", v) if as_u64(&v).is_some() => live = as_u64(&v),
                ("time", VsfType::e(EtType::e6(t))) => time = Some(t),
                _ => {} // forward-compat: unknown field or unexpected type — skip
            }
        }

        let entry = Self {
            gen: gen.ok_or_else(|| Error::Corrupt("missing gen".into()))?,
            prev_hash: prev.ok_or_else(|| Error::Corrupt("missing prev".into()))?,
            ring_log2: ring.ok_or_else(|| Error::Corrupt("missing ring".into()))?,
            tract_blocks: tract.ok_or_else(|| Error::Corrupt("missing tract".into()))?,
            hamt_hash: hamt.ok_or_else(|| Error::Corrupt("missing hamt".into()))?,
            hamt_lba: hamtat.ok_or_else(|| Error::Corrupt("missing hamtat".into()))?,
            plow: plow.ok_or_else(|| Error::Corrupt("missing plow".into()))?,
            live: live.ok_or_else(|| Error::Corrupt("missing live".into()))?,
            eagle_time: time.ok_or_else(|| Error::Corrupt("missing time".into()))?,
        };
        if entry.ring_log2 == 0 || entry.ring_log2 > 32 {
            return Err(Error::Corrupt(format!("insane ring exponent {}", entry.ring_log2)));
        }
        Ok(entry)
    }

    /// hp of this entry's encoded body — what the NEXT entry's prev_hash must be.
    pub fn body_hash(&self) -> [u8; 32] {
        let block = self.encode();
        let mut ptr = 4usize;
        let _ = parse(&block, &mut ptr); // hp
        ptr += 1; // '>'
        *blake3::hash(&block[ptr..]).as_bytes()
    }
}

/// The auto-sized writer (`VsfType::u`) flattens to a concrete EWE size class; parse returns the sized variant. Collapse them all back to u64.
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

fn to32(v: &[u8]) -> Result<[u8; 32]> {
    v.try_into()
        .map_err(|_| Error::Corrupt(format!("hash length {} != 32", v.len())))
}

fn decode_err<E: core::fmt::Debug>(e: E) -> Error {
    Error::Corrupt(format!("vsf parse: {e:?}"))
}

/// Three-way classification. Misplaced-but-sealed entries (congruence failure) are Corrupt — a block cannot lie about its generation because the slot's expected residue is known before the read is trusted.
pub enum Classified {
    Valid(SpineEntry),
    Empty,
    Corrupt,
}

/// Classify a block READ FROM `slot` in a ring of `1 << ring_log2` slots. Pass `None` for bootstrap reads where N is not yet known (congruence deferred).
pub fn classify(block: &Block, slot: u64, ring_log2: Option<u8>) -> Classified {
    if block == &ZERO_BLOCK {
        return Classified::Empty;
    }
    if block[..4] != MAGIC {
        // Non-zero, non-VSF: trash.
        return Classified::Corrupt;
    }
    match SpineEntry::decode(block) {
        Ok(e) => {
            let r = ring_log2.unwrap_or(e.ring_log2);
            if e.ring_log2 != r {
                return Classified::Corrupt; // claims a different geometry than this ring
            }
            let n = 1u64 << r;
            if e.gen & (n - 1) != slot {
                return Classified::Corrupt; // misplaced — cannot lie about generation
            }
            Classified::Valid(e)
        }
        Err(_) => Classified::Corrupt,
    }
}

/// A spine ring over a mirrored block device. The ring occupies blocks [0, N); the tract begins at N (callers add the base).
pub struct Ring<A: BlockDev, B: BlockDev> {
    mirror: Mirror<A, B>,
    ring_log2: u8,
    /// Cached head after open/append: (slot, entry).
    head: Option<(u64, SpineEntry)>,
}

impl<A: BlockDev, B: BlockDev> Ring<A, B> {
    pub fn n(&self) -> u64 {
        1u64 << self.ring_log2
    }

    pub fn ring_log2(&self) -> u8 {
        self.ring_log2
    }

    pub fn head(&self) -> Option<&SpineEntry> {
        self.head.as_ref().map(|(_, e)| e)
    }

    pub fn mirror(&mut self) -> &mut Mirror<A, B> {
        &mut self.mirror
    }

    /// Bootstrap: discover the ring exponent from the file itself. Slot 0 holds generation 0 from the very first commit and is rewritten every lap, so it is Valid in any vault with history; walk a few slots forward past killswitch damage. Returns None on an apparently-empty/trash region — the caller escalates to the whole-file scan (genesis rule).
    pub fn bootstrap_n(mirror: &mut Mirror<A, B>) -> Result<Option<u8>> {
        let mut buf = ZERO_BLOCK;
        let probe = (1u64 << 4).min(mirror.block_count());
        for slot in 0..probe {
            mirror.read(slot, &mut buf)?;
            if let Classified::Valid(e) = classify(&buf, slot, None) {
                return Ok(Some(e.ring_log2));
            }
        }
        Ok(None)
    }

    /// Open a ring with a known exponent (from bootstrap or profile default) and find its head.
    pub fn open(mirror: Mirror<A, B>, ring_log2: u8) -> Result<Self> {
        let mut ring = Self {
            mirror,
            ring_log2,
            head: None,
        };
        ring.head = ring.head_search()?;
        Ok(ring)
    }

    /// Append the next generation. Enforces the chain: gen = head+1 (or 0 at genesis), prev_hash = head's body hash (or zeros). Slot = gen & (N-1) — the congruence is by construction here and re-verified by every future read.
    pub fn append(&mut self, entry: &SpineEntry) -> Result<()> {
        match &self.head {
            Some((_, h)) => {
                if entry.gen != h.gen + 1 {
                    return Err(Error::Corrupt(format!(
                        "append gen {} after head {}",
                        entry.gen, h.gen
                    )));
                }
                if entry.prev_hash != h.body_hash() {
                    return Err(Error::Corrupt("prev_hash does not chain to head".into()));
                }
            }
            None => {
                if entry.gen != 0 {
                    return Err(Error::Corrupt(format!("genesis must be gen 0, got {}", entry.gen)));
                }
                if entry.prev_hash != [0u8; 32] {
                    return Err(Error::Corrupt("genesis prev_hash must be zeros".into()));
                }
            }
        }
        if entry.ring_log2 != self.ring_log2 {
            return Err(Error::Corrupt("entry geometry does not match ring".into()));
        }

        let slot = entry.gen & (self.n() - 1);
        let block = entry.encode();
        self.mirror.write_verified(slot, &block)?;
        self.head = Some((slot, entry.clone()));
        Ok(())
    }

    /// Plow positions of the last `k` generations (newest first) — the rollback fence input. Fewer than k exist near genesis; returns what's there.
    pub fn recent_plows(&mut self, k: u64) -> Result<Vec<u64>> {
        let Some((_, head)) = &self.head else {
            return Ok(Vec::new());
        };
        let head_gen = head.gen;
        let n = self.n();
        let mut out = Vec::new();
        let mut buf = ZERO_BLOCK;
        let count = k.min(head_gen + 1);
        for back in 0..count {
            let gen = head_gen - back;
            let slot = gen & (n - 1);
            self.mirror.read(slot, &mut buf)?;
            match classify(&buf, slot, Some(self.ring_log2)) {
                Classified::Valid(e) if e.gen == gen => out.push(e.plow),
                // A corrupt/lapped slot inside the fence window: be conservative — report plow 0 (maximally restrictive fence).
                _ => out.push(0),
            }
        }
        Ok(out)
    }

    /// Find the newest valid entry: bisect on the rotated-maximum invariant, branching BOTH halves around Corrupt blocks (no pruning decision is possible on an ambiguous read). Returns None for a ring with no valid entries.
    pub fn head_search(&mut self) -> Result<Option<(u64, SpineEntry)>> {
        let n = self.n();
        self.search(0, n - 1)
    }

    fn gen_at(&mut self, slot: u64) -> Result<Classified> {
        let mut buf = ZERO_BLOCK;
        self.mirror.read(slot, &mut buf)?;
        Ok(classify(&buf, slot, Some(self.ring_log2)))
    }

    fn search(&mut self, mut lo: u64, hi: u64) -> Result<Option<(u64, SpineEntry)>> {
        // Restore the anchor: advance lo past Corrupt blocks (killswitch bounds this to ~1).
        let mut lo_entry = loop {
            if lo > hi {
                return Ok(None);
            }
            match self.gen_at(lo)? {
                Classified::Corrupt => lo += 1,
                Classified::Empty => break None,
                Classified::Valid(e) => break Some(e),
            }
        };

        let mut lo_slot = lo;
        let mut hi = hi;
        while lo < hi {
            let mid = (lo + hi + 1) >> 1;
            match self.gen_at(mid)? {
                Classified::Corrupt => {
                    // Ambiguous: no pruning decision possible — search both halves, take the higher generation.
                    let left = self.search(lo, mid - 1)?;
                    let right = self.search(mid, hi)?;
                    return Ok(max_by_gen(left, right));
                }
                cls => {
                    let mid_gen = match &cls {
                        Classified::Valid(e) => Some(e.gen),
                        _ => None,
                    };
                    let lo_gen = lo_entry.as_ref().map(|e: &SpineEntry| e.gen);
                    if mid_gen > lo_gen {
                        lo = mid;
                        lo_slot = mid;
                        lo_entry = match cls {
                            Classified::Valid(e) => Some(e),
                            _ => None,
                        };
                    } else {
                        hi = mid - 1;
                    }
                }
            }
        }
        Ok(lo_entry.map(|e| (lo_slot, e)))
    }
}

fn max_by_gen(
    a: Option<(u64, SpineEntry)>,
    b: Option<(u64, SpineEntry)>,
) -> Option<(u64, SpineEntry)> {
    match (a, b) {
        (Some(x), Some(y)) => {
            if x.1.gen >= y.1.gen {
                Some(x)
            } else {
                Some(y)
            }
        }
        (Some(x), None) => Some(x),
        (None, Some(y)) => Some(y),
        (None, None) => None,
    }
}

/// Generic "is anything real here" check for the whole-file trash scan: RÅ magic + self-hash valid, ANY schema (spine entries, HAMT nodes, furrows all count). 2^-256 false-positive rate — a valid block is its own proof.
pub fn block_is_sealed(block: &Block) -> bool {
    if block[..4] != MAGIC {
        return false;
    }
    let mut ptr = 4usize;
    let Ok(VsfType::hp(stored)) = parse(block, &mut ptr) else {
        return false;
    };
    if block.get(ptr) != Some(&b'>') {
        return false;
    }
    blake3::hash(&block[ptr + 1..]).as_bytes() == stored.as_slice()
}

/// Whole-file scan (genesis rule): true if ANY 4KB block on the device is a sealed VSF document. Cost ~tens of ms for host vaults; paid only on the path that ends in "this file contains nothing".
pub fn any_sealed_block<D: BlockDev>(dev: &mut D) -> Result<bool> {
    let mut buf = ZERO_BLOCK;
    for lba in 0..dev.block_count() {
        dev.read(lba, &mut buf)?;
        if block_is_sealed(&buf) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Zero the ring region (Corrupt → Empty) so post-genesis head searches never pay branch-on-corrupt tax for stale wreckage. Used only after the whole-file scan proved emptiness.
pub fn zero_ring<A: BlockDev, B: BlockDev>(mirror: &mut Mirror<A, B>, ring_log2: u8) -> Result<()> {
    for slot in 0..(1u64 << ring_log2) {
        mirror.write_verified(slot, &ZERO_BLOCK)?;
    }
    Ok(())
}
