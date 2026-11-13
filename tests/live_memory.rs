//! The live set grows without one large allocation (2026-11-13, ferros's vault process on the 8a: the one table's doubling from 2^18 to 2^19 buckets asked for 21,495,816 bytes at once, beside the old 10,747,912, and the process's 56 MiB heap refused it while Mahere stowed and wrote its cells).

use manifestus::{Delta, LiveSet, Liveness};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// The largest single allocation since the last reset.
static BIGGEST: AtomicUsize = AtomicUsize::new(0);

struct Track;
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        BIGGEST.fetch_max(l.size(), Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        BIGGEST.fetch_max(n, Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}
#[global_allocator]
static A: Track = Track;

fn hp(lba: u64) -> [u8; 32] {
    *blake3::hash(&lba.to_le_bytes()).as_bytes()
}

#[test]
fn growing_past_half_a_million_hashed_blocks_allocates_little_at_once() {
    let mut live = LiveSet::default();
    // Past the 8a's death (2^18 + 1 entries made the one table double to 2^19 buckets) and the next doubling after it, in commits of a 1 MiB batch's furrows each (as ferros_store hands a large value to the engine), plus tree-only positions as an open marks them.
    let total = (1u64 << 19) + (1 << 17);
    for lba in (1u64 << 22)..(1u64 << 22) + (1 << 17) {
        live.mark_referenced(lba);
    }
    BIGGEST.store(0, Relaxed);
    let mut at = 0;
    while at < total {
        let added = (at..at + (1 << 8)).map(|l| (l, hp(l))).collect();
        live.apply(Delta { added, removed: Vec::new() });
        at += 1 << 8;
    }
    let biggest = BIGGEST.load(Relaxed);
    println!("live set: {:?} entries (hashed, tree-only), the largest allocation {} bytes", live.counts(), biggest);
    assert_eq!(live.counts(), (total as usize, 1 << 17));
    // One table: 2^20 buckets × 41 bytes, 43 MB in one allocation. Sharded 256 ways: each table holds about 2,600 entries, 4,096 buckets, 168 KiB.
    assert!(biggest < 1 << 20, "the largest allocation {biggest} bytes");
    // The answers are the same as one table's.
    assert!(live.is_live(5, &hp(5)));
    assert!(!live.is_live(5, &hp(6)));
    assert!(live.is_referenced((1 << 22) + 3));
    assert!(live.is_live((1 << 22) + 3, &hp(99)), "a tree-only position is live whatever the hash read off its block");
    // Hashed after tree-only: no longer tree-only.
    live.insert((1 << 22) + 3, hp(7));
    assert!(!live.is_live((1 << 22) + 3, &hp(99)));
    assert!(live.is_live((1 << 22) + 3, &hp(7)));
    // Removed only with its own hash; a tree-only one by position.
    live.apply(Delta { added: Vec::new(), removed: vec![(5, hp(6)), (6, hp(6)), ((1 << 22) + 4, hp(1))] });
    assert!(live.is_live(5, &hp(5)));
    assert!(!live.is_referenced(6));
    assert!(!live.is_referenced((1 << 22) + 4));
    assert_eq!(live.positions().count(), live.len());
}
