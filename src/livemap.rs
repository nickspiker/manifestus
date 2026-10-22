//! The live map on disk (2026-10-22): one bit per tract position, set where the committed index references a block (nodes, leaves, furrows), in copy-on-write pages under a small table the spine entry names. Opening a vault reads the table and its pages — a few blocks for any number of entries — instead of walking every node and leaf of the index to rebuild the same knowledge.
//!
//! The map does not record its own blocks: writing a page moves it, and a map that recorded its own pages would never settle. Their positions are what the table lists; the vault holds them live beside the bits (see `LiveSet::own`).
//!
//! Pages and tables are sealed tract blocks like every other (RÅ + hp), appended under the commit they belong to and kept by the fence for the last K generations like the index.

use crate::block::{Block, BLOCK, ZERO_BLOCK};
use crate::error::{Error, Result};
use crate::ring::MAGIC;
use alloc::{format, string::ToString, vec, vec::Vec};
use vsf::decoding::parse::parse;
use vsf::types::VsfType;

pub const SCHEMA_PAGE: &str = "manifestus.livepage";
pub const SCHEMA_TABLE: &str = "manifestus.livetab";

/// The largest tract whose whole bitmap rides inside the spine entry (3 KiB of bits — the entry has room to spare, and is written every commit anyway). Up to here the map costs no tract block; past it, pages and tables.
pub const INLINE_MAX_BITS: u64 = 3 * 1024 * 8;

/// Positions one page covers: 2 KiB of bits.
pub const PAGE_BITS: u64 = 1 << 14;
/// u64 words in a page.
pub const PAGE_WORDS: usize = (PAGE_BITS / 64) as usize;
/// Children one table block holds. One table covers 64 pages (4 GiB of tract); a larger tract gets a root table over sub-tables (256 GiB).
pub const TABLE_FANOUT: usize = 64;

/// A sealed child pointer: (hash, tract position).
pub type Ptr = ([u8; 32], u64);

/// What a tract block of the live map is.
pub enum Doc {
    Page { index: u64, words: Vec<u64> },
    /// `level` 1 lists pages, 2 lists level-1 tables. `len` is the tract length the map was written for.
    Table { level: u8, len: u64, children: Vec<Ptr> },
}

pub fn pages_for(len: u64) -> usize {
    len.div_ceil(PAGE_BITS) as usize
}

fn body_start() -> usize {
    4 + VsfType::hp(vec![0u8; 32]).flatten().len() + 1
}

fn begin(schema: &str) -> (Block, usize) {
    let mut buf = ZERO_BLOCK;
    buf[..4].copy_from_slice(&MAGIC);
    let hp0 = VsfType::hp(vec![0u8; 32]).flatten();
    buf[4..4 + hp0.len()].copy_from_slice(&hp0);
    buf[4 + hp0.len()] = b'>';
    let mut c = body_start();
    let s = VsfType::d(schema.to_string()).flatten();
    buf[c..c + s.len()].copy_from_slice(&s);
    c += s.len();
    (buf, c)
}

fn put(buf: &mut Block, c: &mut usize, name: &str, v: VsfType) -> Result<()> {
    let n = VsfType::d(name.to_string()).flatten();
    let v = v.flatten();
    if *c + n.len() + v.len() > BLOCK {
        return Err(Error::Corrupt("live map block overflow".into()));
    }
    buf[*c..*c + n.len()].copy_from_slice(&n);
    *c += n.len();
    buf[*c..*c + v.len()].copy_from_slice(&v);
    *c += v.len();
    Ok(())
}

fn seal(mut buf: Block) -> Block {
    let start = body_start();
    let hash = blake3::hash(&buf[start..]);
    let hp = VsfType::hp(hash.as_bytes().to_vec()).flatten();
    buf[4..4 + hp.len()].copy_from_slice(&hp);
    buf
}

pub fn encode_page(index: u64, words: &[u64]) -> Result<Block> {
    let (mut buf, mut c) = begin(SCHEMA_PAGE);
    put(&mut buf, &mut c, "page", VsfType::u(index as usize, false))?;
    let mut bytes = Vec::with_capacity(words.len() * 8);
    for w in words {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    put(&mut buf, &mut c, "bits", VsfType::v(b'r', bytes))?;
    Ok(seal(buf))
}

pub fn encode_table(level: u8, len: u64, children: &[Ptr]) -> Result<Block> {
    if children.len() > TABLE_FANOUT {
        return Err(Error::Corrupt("live map table overflow".into()));
    }
    let (mut buf, mut c) = begin(SCHEMA_TABLE);
    put(&mut buf, &mut c, "lvl", VsfType::u(level as usize, false))?;
    put(&mut buf, &mut c, "len", VsfType::u(len as usize, false))?;
    for (h, at) in children {
        put(&mut buf, &mut c, "ch", VsfType::hp(h.to_vec()))?;
        put(&mut buf, &mut c, "at", VsfType::u(*at as usize, false))?;
    }
    Ok(seal(buf))
}

fn as_u64(v: &VsfType) -> Option<u64> {
    match v {
        VsfType::u(x, _) => Some(*x as u64),
        VsfType::u0(b) => Some(*b as u64),
        VsfType::u3(x) => Some(*x as u64),
        VsfType::u4(x) => Some(*x as u64),
        VsfType::u5(x) => Some(*x as u64),
        VsfType::u6(x) => Some(*x),
        _ => None,
    }
}

/// The schema of a sealed block, if it is a live map block — the reap's question ("is this one of the map's own blocks").
pub fn is_map_block(block: &Block) -> bool {
    let mut ptr = 4usize;
    if parse(block, &mut ptr).is_err() {
        return false;
    }
    ptr += 1;
    matches!(parse(block, &mut ptr), Ok(VsfType::d(s)) if s == SCHEMA_PAGE || s == SCHEMA_TABLE)
}

fn err<E: core::fmt::Debug>(e: E) -> Error {
    Error::Corrupt(format!("{e:?}"))
}

/// Decode a block already checked against its expected hash.
pub fn decode(block: &Block) -> Result<Doc> {
    let mut ptr = 4usize;
    parse(block, &mut ptr).map_err(err)?;
    ptr += 1;
    let VsfType::d(schema) = parse(block, &mut ptr).map_err(err)? else {
        return Err(Error::Corrupt("live map: missing schema".into()));
    };
    let mut index = None;
    let mut bits = None;
    let mut level = None;
    let mut len = None;
    let mut hashes: Vec<[u8; 32]> = Vec::new();
    let mut ats: Vec<u64> = Vec::new();
    while block.get(ptr) == Some(&b'd') {
        let VsfType::d(name) = parse(block, &mut ptr).map_err(err)? else {
            return Err(Error::Corrupt("live map: bad field".into()));
        };
        let v = parse(block, &mut ptr).map_err(err)?;
        match (name.as_str(), v) {
            ("page", ref u) => index = as_u64(u),
            ("bits", VsfType::v(_, b)) => bits = Some(b),
            ("lvl", ref u) => level = as_u64(u),
            ("len", ref u) => len = as_u64(u),
            ("ch", VsfType::hp(h)) => hashes.push(h.try_into().map_err(|_| Error::Corrupt("live map: hash length".into()))?),
            ("at", ref u) => ats.push(as_u64(u).ok_or_else(|| Error::Corrupt("live map: at".into()))?),
            _ => {}
        }
    }
    match schema.as_str() {
        SCHEMA_PAGE => {
            let bits = bits.ok_or_else(|| Error::Corrupt("live page: no bits".into()))?;
            if bits.len() != PAGE_WORDS * 8 {
                return Err(Error::Corrupt("live page: wrong size".into()));
            }
            let words = bits.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
            Ok(Doc::Page { index: index.ok_or_else(|| Error::Corrupt("live page: no index".into()))?, words })
        }
        SCHEMA_TABLE => {
            if hashes.len() != ats.len() {
                return Err(Error::Corrupt("live table: children mismatch".into()));
            }
            Ok(Doc::Table {
                level: level.ok_or_else(|| Error::Corrupt("live table: no level".into()))? as u8,
                len: len.ok_or_else(|| Error::Corrupt("live table: no len".into()))?,
                children: hashes.into_iter().zip(ats).collect(),
            })
        }
        other => Err(Error::Corrupt(format!("not a live map block: {other}"))),
    }
}
