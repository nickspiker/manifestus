//! The live set grows without one large allocation (2026-11-13, ferros's vault process on the 8a: the hashbrown table's doubling from 2^18 to 2^19 buckets asked for 21,495,816 bytes at once, beside the old 10,747,912, and the process's 56 MiB heap refused it while Mahere stowed and wrote its cells), and what the direct index costs against the hashbrown table it replaced.

use manifestus::{Delta, LiveSet, Liveness};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

/// The largest single allocation since the last reset, and bytes held now.
static BIGGEST: AtomicUsize = AtomicUsize::new(0);
static NOW: AtomicUsize = AtomicUsize::new(0);

struct Track;
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        BIGGEST.fetch_max(l.size(), Relaxed);
        NOW.fetch_add(l.size(), Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        NOW.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Track = Track;

/// A stand-in for a block's sealing hash, distinct per position and cheap, so the cost test measures the sets and not BLAKE3.
fn hp(lba: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    for (k, c) in h.chunks_mut(8).enumerate() {
        c.copy_from_slice(&(lba ^ (k as u64)).wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    }
    h
}

/// A tract of 2^20 positions (4 GiB, the 8a's): the open marks 2^17 positions by position alone, then 2^19 + 2^17 blocks are appended with their hashes in commits of 256 (a 1 MiB batch's furrows), as the plow lays them, past the 2^18 entries where the one table doubled to 2^19 buckets.
const TRACT: u64 = 1 << 20;
const HASHED: u64 = (1 << 19) + (1 << 17);
const TREE_AT: u64 = 0;
const TREE: u64 = 1 << 17;

fn fill() -> LiveSet {
    let mut live = LiveSet::default();
    for lba in TREE_AT + HASHED..TREE_AT + HASHED + TREE {
        live.mark_referenced(lba % TRACT);
    }
    let mut at = 0;
    while at < HASHED {
        let added = (at..at + (1 << 8)).map(|l| (l, hp(l))).collect();
        live.apply(Delta { added, removed: Vec::new() });
        at += 1 << 8;
    }
    live
}

#[test]
fn growing_past_half_a_million_hashed_blocks_allocates_little_at_once() {
    BIGGEST.store(0, Relaxed);
    let before = NOW.load(Relaxed);
    let mut live = fill();
    let biggest = BIGGEST.load(Relaxed);
    let held = NOW.load(Relaxed) - before;
    println!("live set: {:?} entries (hashed, by position), the largest allocation {} bytes, {} bytes held ({} by its own count)", live.counts(), biggest, held, live.bytes());
    assert_eq!(live.counts(), (HASHED as usize, TREE as usize));
    // A page's hashes: 2^10 × 32 bytes. The one hashbrown table: 2^20 buckets, 43 MB at once.
    assert!(biggest <= 1 << 15, "the largest allocation {biggest} bytes");
    // The answers.
    assert!(live.is_live(5, &hp(5)));
    assert!(!live.is_live(5, &hp(6)));
    assert!(!live.is_referenced(TRACT - 1 - TREE), "a position never reached");
    assert!(!live.is_referenced(1 << 40), "a position past every page");
    let t = (TREE_AT + HASHED + 3) % TRACT;
    assert!(live.is_referenced(t));
    assert!(live.is_live(t, &hp(99)), "a position live by position alone is live whatever the hash read off its block");
    // Hashed after by position alone: no longer by position alone.
    live.insert(t, hp(7));
    assert!(!live.is_live(t, &hp(99)));
    assert!(live.is_live(t, &hp(7)));
    assert_eq!(live.counts(), (HASHED as usize + 1, TREE as usize - 1));
    // Marking a hashed position by position alone changes nothing.
    live.mark_referenced(5);
    assert!(!live.is_live(5, &hp(6)));
    // Removed only with its own hash; one by position alone by position.
    let t2 = (TREE_AT + HASHED + 4) % TRACT;
    live.apply(Delta { added: Vec::new(), removed: vec![(5, hp(6)), (6, hp(6)), (t2, hp(1)), (1 << 40, hp(1))] });
    assert!(live.is_live(5, &hp(5)));
    assert!(!live.is_referenced(6));
    assert!(!live.is_referenced(t2));
    assert_eq!(live.positions().count(), live.len());
    assert_eq!(live.hashed().count(), HASHED as usize);
    assert!(live.hashed().all(|(l, h)| *h == if l == t { hp(7) } else { hp(l) }));
    // Removing everything gives every page back.
    let gone: Vec<(u64, [u8; 32])> = live.hashed().map(|(l, h)| (l, *h)).collect();
    let tree: Vec<(u64, [u8; 32])> = live.tree_positions().map(|l| (l, [0; 32])).collect();
    live.apply(Delta { added: Vec::new(), removed: gone.into_iter().chain(tree).collect() });
    assert!(live.is_empty());
    assert!(live.bytes() < 1 << 16, "{} bytes left", live.bytes());
}

/// The cost against the hashbrown table it replaced, the same entries, each built the same way: `cargo test --release --test live_memory live_lookup_cost -- --ignored --nocapture`.
#[test]
#[ignore]
fn live_lookup_cost() {
    let probes: Vec<u64> = (0..1u64 << 22).map(|i| i.wrapping_mul(2_654_435_761) % TRACT).collect();
    let mut seen = 0u64;

    let n0 = NOW.load(Relaxed);
    BIGGEST.store(0, Relaxed);
    let t = Instant::now();
    let live = fill();
    let build = t.elapsed();
    let (bytes, biggest) = (NOW.load(Relaxed) - n0, BIGGEST.load(Relaxed));
    let t = Instant::now();
    for &p in &probes {
        seen += live.is_live(p, &hp(p & 7)) as u64 + live.is_referenced(p) as u64;
    }
    let look = t.elapsed();
    println!("direct index: built in {build:?}, {bytes} bytes held, the largest allocation {biggest}; {} lookups in {look:?}", probes.len() * 2);
    drop(live);

    let n0 = NOW.load(Relaxed);
    BIGGEST.store(0, Relaxed);
    let t = Instant::now();
    let mut map: hashbrown::HashMap<u64, [u8; 32]> = hashbrown::HashMap::new();
    let mut set: hashbrown::HashSet<u64> = hashbrown::HashSet::new();
    for lba in TREE_AT + HASHED..TREE_AT + HASHED + TREE {
        set.insert(lba % TRACT);
    }
    for l in 0..HASHED {
        set.remove(&l);
        map.insert(l, hp(l));
    }
    let build = t.elapsed();
    let (bytes, biggest) = (NOW.load(Relaxed) - n0, BIGGEST.load(Relaxed));
    let t = Instant::now();
    for &p in &probes {
        seen += (map.get(&p) == Some(&hp(p & 7)) || set.contains(&p)) as u64 + (map.contains_key(&p) || set.contains(&p)) as u64;
    }
    let look = t.elapsed();
    println!("hashbrown: built in {build:?}, {bytes} bytes held, the largest allocation {biggest}; {} lookups in {look:?}", probes.len() * 2);
    println!("(hp of each probe is computed in both loops: {seen})");

    // As an open leaves it: 3 × 2^18 positions live, one in 18 hashed (a 64 KiB piece's leaf after its 17 furrows), the rest by position alone.
    let n0 = NOW.load(Relaxed);
    let mut live = LiveSet::default();
    for l in 0..3u64 << 18 {
        if l % 18 == 17 {
            live.insert(l, hp(l));
        } else {
            live.mark_referenced(l);
        }
    }
    println!("opened: direct index {:?} entries, {} bytes held", live.counts(), NOW.load(Relaxed) - n0);
    drop(live);
    let n0 = NOW.load(Relaxed);
    let mut map: hashbrown::HashMap<u64, [u8; 32]> = hashbrown::HashMap::new();
    let mut set: hashbrown::HashSet<u64> = hashbrown::HashSet::new();
    for l in 0..3u64 << 18 {
        if l % 18 == 17 {
            map.insert(l, hp(l));
        } else {
            set.insert(l);
        }
    }
    println!("opened: hashbrown {} + {} entries, {} bytes held", map.len(), set.len(), NOW.load(Relaxed) - n0);
}
