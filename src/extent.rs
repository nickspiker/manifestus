//! Single-copy extents (opt-in): bulk data written once at the medium's full rate into an area of its own, outside the tract and its mirror; the vault keeps the record.
//!
//! For values too large and too fast for the tract's write-verify-then-mirror path: a RAW video clip is minutes of 150 to 500 MB a second (ferros docs/RAW-VIDEO.md), and the mirror's write, read back and second write would halve the rate and double the wear.
//! The owner, 2026-11-19: "single, no dual write".
//!
//! What is mirrored and what is not:
//! - **The table** ([`Extents`]) is an ordinary value of the vault under [`table_key`]: committed, mirrored, crash-proof like every other value. It says which stretches of the area are taken, by whom, how long each extent's data is and its BLAKE3.
//! - **The data** goes to the embedder's area device directly, one copy, never read back by this crate: its integrity is the hash the table records at [`Extents::seal`], and the format's own checks (a RAW clip's frames chain by BLAKE3).
//!
//! Crash behaviour: a reservation is committed before any of its data is written, so a crash mid-recording leaves an open (unsealed) extent whose blocks are still taken; its owner finds it with [`Extents::find`], reads what was written, and seals or drops it.
//! A crash between a seal's data and its commit leaves the extent open, never a record naming blocks another extent holds.
//! An extent is found only by its name, the BLAKE3 of the embedder's key for it: the table carries no keys, as the HAMT's leaves carry none.
//!
//! Nothing here touches a vault that never calls it: the table's key is one no other value can have, and a vault without a table has no extents.

use crate::error::{Error, Result};
use crate::{BlockDev, Vault};
use alloc::vec::Vec;
use vsf::types::{Tensor, VsfType};

/// The table's key in the vault: BLAKE3 in derive-key mode of a context of this crate's own, never a value's address (those are derived from the embedder's keys).
pub fn table_key() -> [u8; 32] {
    blake3::derive_key("manifestus 2026-11-19 single-copy extent table", &[])
}

/// One extent: `blocks` blocks of the area from `first`, `bytes` of them written and sealed (0 and no hash while open).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    /// BLAKE3 of the embedder's key for it.
    pub name: [u8; 32],
    /// The embedder's owner tag (a domain's id, so a domain dropped whole drops its extents): BLAKE3 of whatever the embedder groups by.
    pub owner: [u8; 32],
    pub first: u64,
    pub blocks: u64,
    pub bytes: u64,
    pub hash: [u8; 32],
    pub sealed: bool,
    /// When it was reserved or sealed, the embedder's clock (Eagle time on ferros).
    pub at: i64,
}

impl Extent {
    /// Whether `n` blocks from block `at` of the extent lie inside it.
    pub fn holds(&self, at: u64, n: u64) -> bool {
        at.checked_add(n).is_some_and(|end| end <= self.blocks)
    }
}

/// The table: every extent of an area of `area` blocks, ordered by first block, none overlapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extents {
    pub area: u64,
    list: Vec<Extent>,
}

const SECTION: &str = "extents";

impl Extents {
    /// An empty table over an area of `area` blocks.
    pub fn new(area: u64) -> Extents {
        Extents { area, list: Vec::new() }
    }

    /// The table as the vault holds it, or an empty one over `area` blocks when it holds none.
    /// A table recorded over another area size is refused: the embedder moved its area, and the records would name blocks that are not its.
    pub fn load<A: BlockDev, B: BlockDev>(vault: &mut Vault<A, B>, area: u64) -> Result<Extents> {
        match vault.get(&table_key())? {
            None => Ok(Extents::new(area)),
            Some(bytes) => {
                let t = Extents::decode(&bytes)?;
                if t.area != area {
                    return Err(Error::Corrupt(alloc::format!("extent table over {} blocks, the area is {}", t.area, area)));
                }
                Ok(t)
            }
        }
    }

    /// Commit the table (one put: every change to it is atomic).
    pub fn store<A: BlockDev, B: BlockDev>(&self, vault: &mut Vault<A, B>, now: i64) -> Result<()> {
        vault.put(&table_key(), &self.encode()?, now)
    }

    pub fn list(&self) -> &[Extent] {
        &self.list
    }

    pub fn find(&self, name: &[u8; 32]) -> Option<&Extent> {
        self.list.iter().find(|e| e.name == *name)
    }

    /// Blocks taken by every extent.
    pub fn taken(&self) -> u64 {
        self.list.iter().map(|e| e.blocks).sum()
    }

    /// The longest free stretch.
    pub fn largest_free(&self) -> u64 {
        let mut at = 0;
        let mut most = 0;
        for e in &self.list {
            most = most.max(e.first - at);
            at = e.first + e.blocks;
        }
        most.max(self.area - at)
    }

    /// Reserve `blocks` blocks under `name` (first fit, from the area's start); an extent already under the name is refused (drop it first).
    /// Not committed: the caller stores the table before writing a byte of the data.
    pub fn reserve(&mut self, name: [u8; 32], owner: [u8; 32], blocks: u64, at: i64) -> Result<Extent> {
        if blocks == 0 || self.find(&name).is_some() {
            return Err(Error::Corrupt(alloc::format!("extent reserve of {blocks} blocks under a name {}", if blocks == 0 { "for nothing" } else { "already taken" })));
        }
        let mut start = 0;
        let mut slot = self.list.len();
        for (i, e) in self.list.iter().enumerate() {
            if e.first - start >= blocks {
                slot = i;
                break;
            }
            start = e.first + e.blocks;
        }
        if slot == self.list.len() && self.area - start < blocks {
            return Err(Error::TractFull);
        }
        let e = Extent { name, owner, first: start, blocks, bytes: 0, hash: [0; 32], sealed: false, at };
        self.list.insert(slot, e);
        Ok(e)
    }

    /// Seal `name`: its length and BLAKE3 recorded, its blocks past the length given back.
    pub fn seal(&mut self, name: &[u8; 32], bytes: u64, hash: [u8; 32], at: i64) -> Result<Extent> {
        let e = self.list.iter_mut().find(|e| e.name == *name).ok_or_else(|| Error::Corrupt("extent seal of a name with none".into()))?;
        let need = bytes.div_ceil(crate::BLOCK as u64);
        if need > e.blocks {
            return Err(Error::Bounds(need));
        }
        // WHY the max: a seal of zero bytes needs no blocks, but `decode` refuses an extent of zero blocks.
        // PROOF: without it, an empty sealed extent would be stored as 0 blocks and the whole table would be refused at the next load, losing every extent's record.
        e.blocks = need.max(1);
        e.bytes = bytes;
        e.hash = hash;
        e.sealed = true;
        e.at = at;
        Ok(*e)
    }

    /// Drop `name`'s extent, its blocks free again.
    pub fn remove(&mut self, name: &[u8; 32]) -> Option<Extent> {
        let i = self.list.iter().position(|e| e.name == *name)?;
        Some(self.list.remove(i))
    }

    /// Drop every extent of `owner`: how many went.
    pub fn remove_owner(&mut self, owner: &[u8; 32]) -> usize {
        let n = self.list.len();
        self.list.retain(|e| e.owner != *owner);
        n - self.list.len()
    }

    /// The table as one VSF section, its columns as tensors.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let n = self.list.len();
        let col32 = |f: fn(&Extent) -> [u8; 32]| VsfType::t_u3(Tensor::new(alloc::vec![n, 32], self.list.iter().flat_map(f).collect()));
        let col64 = |f: fn(&Extent) -> u64| VsfType::t_u6(Tensor::new(alloc::vec![n], self.list.iter().map(f).collect()));
        let mut s = vsf::file_format::VsfSection::new(SECTION);
        s.add_field("area", VsfType::u(self.area as usize, false));
        s.add_field("count", VsfType::u(n, false));
        s.add_field("names", col32(|e| e.name));
        s.add_field("owners", col32(|e| e.owner));
        s.add_field("first", col64(|e| e.first));
        s.add_field("blocks", col64(|e| e.blocks));
        s.add_field("bytes", col64(|e| e.bytes));
        s.add_field("hashes", col32(|e| e.hash));
        s.add_field("sealed", VsfType::t_u3(Tensor::new(alloc::vec![n], self.list.iter().map(|e| e.sealed as u8).collect())));
        s.add_field("at", VsfType::t_i6(Tensor::new(alloc::vec![n], self.list.iter().map(|e| e.at).collect())));
        vsf::vsf_builder::VsfBuilder::new().add_section_direct(s).build().map_err(Error::Corrupt)
    }

    pub fn decode(bytes: &[u8]) -> Result<Extents> {
        let bad = |what: &str| Error::Corrupt(alloc::format!("extent table: {what}"));
        let doc = vsf::container::Document::open(bytes).map_err(|e| Error::Corrupt(alloc::format!("extent table: {e}")))?;
        let entry = doc.entry(SECTION).ok_or_else(|| bad("no section"))?;
        let s = doc.section(entry).map_err(|e| Error::Corrupt(alloc::format!("extent table: {e}")))?;
        let first = |name: &str| s.get_field(name).and_then(|f| f.values.first());
        let area = s.uint("area").ok_or_else(|| bad("no area"))?;
        let n = s.uint("count").ok_or_else(|| bad("no count"))? as usize;
        let col32 = |name: &str| -> Result<Vec<[u8; 32]>> {
            match first(name) {
                Some(VsfType::t_u3(t)) if t.data.len() == n * 32 => Ok(t.data.chunks(32).map(|c| c.try_into().expect("32-byte chunk")).collect()),
                _ => Err(bad(name)),
            }
        };
        let col64 = |name: &str| -> Result<Vec<u64>> {
            match first(name) {
                Some(VsfType::t_u6(t)) if t.data.len() == n => Ok(t.data.clone()),
                _ => Err(bad(name)),
            }
        };
        let (names, owners, hashes) = (col32("names")?, col32("owners")?, col32("hashes")?);
        let (firsts, blocks, lens) = (col64("first")?, col64("blocks")?, col64("bytes")?);
        let sealed = match first("sealed") {
            Some(VsfType::t_u3(t)) if t.data.len() == n => t.data.clone(),
            _ => return Err(bad("sealed")),
        };
        let at = match first("at") {
            Some(VsfType::t_i6(t)) if t.data.len() == n => t.data.clone(),
            _ => return Err(bad("at")),
        };
        let list: Vec<Extent> = (0..n).map(|i| Extent { name: names[i], owner: owners[i], first: firsts[i], blocks: blocks[i], bytes: lens[i], hash: hashes[i], sealed: sealed[i] != 0, at: at[i] }).collect();
        // WHY: the table is read from the medium; ordered, inside the area and apart is what every reservation and write bound relies on, so a table that is not is refused whole.
        let mut end = 0u64;
        for e in &list {
            let stop = e.first.checked_add(e.blocks).ok_or_else(|| bad("an extent past the end of numbers"))?;
            if e.first < end || stop > area || e.blocks == 0 {
                return Err(bad("extents out of order, overlapping or outside the area"));
            }
            end = stop;
        }
        Ok(Extents { area, list })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn reserve_seal_remove_and_round_trip() {
        let mut t = Extents::new(1000);
        let a = t.reserve(n(1), n(9), 300, 5).unwrap();
        let b = t.reserve(n(2), n(9), 300, 6).unwrap();
        assert_eq!((a.first, b.first), (0, 300));
        assert!(t.reserve(n(1), n(9), 10, 7).is_err());
        assert!(matches!(t.reserve(n(3), n(9), 401, 7), Err(Error::TractFull)));
        // Sealed short, a's tail goes back: the next reservation fits there.
        t.seal(&n(1), 4096 * 100 + 1, n(7), 8).unwrap();
        assert_eq!(t.find(&n(1)).unwrap().blocks, 101);
        let c = t.reserve(n(3), n(8), 150, 9).unwrap();
        assert_eq!(c.first, 101);
        assert!(t.find(&n(3)).unwrap().holds(149, 1) && !t.find(&n(3)).unwrap().holds(149, 2));
        let back = Extents::decode(&t.encode().unwrap()).unwrap();
        assert_eq!(back, t);
        assert_eq!(t.remove_owner(&n(9)), 2);
        assert_eq!(t.list().len(), 1);
        assert_eq!(t.largest_free(), 1000 - 251);
        assert!(t.seal(&n(3), 151 * 4096, n(0), 10).is_err());
    }
}
