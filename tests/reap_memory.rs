//! A reap's memory is bounded whatever the tract (2026-11-12, ferros's vault process: a window is a sixty-fourth of the tract, and a window full of one value's furrows was held twice, read and staged, so a reap needed 32 MiB at a 1 GiB tract and ran its 56 MiB heap out at 2 GiB).

use manifestus::{BlockDev, Block, DeletePolicy, Mirror, Vault, HOST_RING_LOG2, ZERO_BLOCK};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// Bytes allocated now, and the most since the last reset.
static NOW: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Track;
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let n = NOW.fetch_add(l.size(), Relaxed) + l.size();
        PEAK.fetch_max(n, Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        NOW.fetch_sub(l.size(), Relaxed);
        unsafe { System.dealloc(p, l) }
    }
}
#[global_allocator]
static A: Track = Track;

struct Mem(Vec<Block>);
impl BlockDev for Mem {
    fn block_count(&self) -> u64 {
        self.0.len() as u64
    }
    fn read(&mut self, lba: u64, buf: &mut Block) -> manifestus::Result<()> {
        *buf = self.0[lba as usize];
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &Block) -> manifestus::Result<()> {
        self.0[lba as usize] = *buf;
        Ok(())
    }
    fn flush(&mut self) -> manifestus::Result<()> {
        Ok(())
    }
}

#[test]
fn a_reap_of_one_values_furrows_is_bounded() {
    // A tract of 2^16 blocks: its reap window is 2^10 blocks (4 MiB), four times the chunk a reap copies at once.
    let len = 1u64 << 16;
    let blocks = (1u64 << HOST_RING_LOG2) + len;
    let m = Mirror::new(Mem(vec![ZERO_BLOCK; blocks as usize]), Mem(vec![ZERO_BLOCK; blocks as usize]));
    let mut v = Vault::open(m, HOST_RING_LOG2, 1, DeletePolicy::UnlinkOnly).unwrap();
    // One value whose furrows fill the first window.
    let value: Vec<u8> = (0..4usize << 20).map(|i| (i * 31 >> 3) as u8).collect();
    let key = *blake3::hash(b"one large value").as_bytes();
    v.put(&key, &value, 2).unwrap();
    let before = v.engine_stats();
    let base = NOW.load(Relaxed);
    PEAK.store(base, Relaxed);
    assert!(v.reap_one_window(3).unwrap(), "the window holding the value is reaped");
    let used = PEAK.load(Relaxed) - base;
    let after = v.engine_stats();
    assert!(after.reap > before.reap, "the reap moved on ({} to {})", before.reap, after.reap);
    // The window's survivors, about a thousand furrows, read into one vector and staged again by the append: 16.9 MB at the worst before the bound (the copies and the write's own), 4.3 MB with it, and no longer growing with the window.
    assert!(used < 5 << 20, "a reap of a 4 MiB window used {used} bytes at its worst");
    assert_eq!(v.get(&key).unwrap().as_deref(), Some(&value[..]), "the value reads back whole after its furrows moved");
}
