//! Spine ring behavior: codec, classification, head search (incl. the CUSTODES.md deflection counter-example), chain enforcement, genesis rule helpers, kill -9 survival.

use custodes::{
    any_sealed_block, classify, zero_ring, BlockDev, Classified, FileDev, Mirror, Ring,
    SpineEntry, ZERO_BLOCK,
};
use tempfile::TempDir;

fn mk_mirror(dir: &TempDir, name: &str, blocks: u64) -> Mirror<FileDev, FileDev> {
    let a = FileDev::create(&dir.path().join(format!("{name}-a.bin")), blocks).unwrap();
    let b = FileDev::create(&dir.path().join(format!("{name}-b.bin")), blocks).unwrap();
    Mirror::new(a, b)
}

fn entry(gen: u64, prev: [u8; 32], r: u8) -> SpineEntry {
    SpineEntry {
        gen,
        prev_hash: prev,
        ring_log2: r,
        tract_blocks: 16384,
        hamt_hash: [gen as u8; 32],
        hamt_lba: gen,
        plow: gen * 3,
        live: gen,
        eagle_time: 1_000_000 + gen as i64,
    }
}

/// Append generations 0..count, chaining prev_hash properly.
fn build(ring: &mut Ring<FileDev, FileDev>, count: u64, r: u8) {
    for gen in 0..count {
        let prev = ring.head().map(|h| h.body_hash()).unwrap_or([0u8; 32]);
        ring.append(&entry(gen, prev, r)).unwrap();
    }
}

#[test]
fn entry_roundtrip() {
    let e = entry(42, [7u8; 32], 8);
    let block = e.encode();
    let d = SpineEntry::decode(&block).unwrap();
    assert_eq!(e, d);
}

#[test]
fn classification_three_way() {
    let e = entry(0, [0u8; 32], 8);
    let block = e.encode();
    assert!(matches!(classify(&block, 0, Some(8)), Classified::Valid(_)));
    assert!(matches!(classify(&ZERO_BLOCK, 0, Some(8)), Classified::Empty));

    // Flip one body byte: sealed → Corrupt.
    let mut bad = block;
    bad[2000] ^= 1;
    assert!(matches!(classify(&bad, 0, Some(8)), Classified::Corrupt));

    // Non-VSF garbage: Corrupt.
    let mut trash = ZERO_BLOCK;
    trash[..4].copy_from_slice(b"YOLO");
    assert!(matches!(classify(&trash, 0, Some(8)), Classified::Corrupt));
}

#[test]
fn misplaced_entry_is_corrupt() {
    // A bit-perfect entry at the wrong slot fails congruence — the block cannot lie about its generation.
    let e = entry(5, [0u8; 32], 3); // gen 5, N=8 → belongs at slot 5
    let block = e.encode();
    assert!(matches!(classify(&block, 5, Some(3)), Classified::Valid(_)));
    assert!(matches!(classify(&block, 2, Some(3)), Classified::Corrupt));
}

#[test]
fn genesis_and_head() {
    let dir = TempDir::new().unwrap();
    let mirror = mk_mirror(&dir, "g", 8);
    let mut ring = Ring::open(mirror, 3).unwrap();
    assert!(ring.head().is_none(), "fresh ring is pre-genesis");

    build(&mut ring, 1, 3);
    assert_eq!(ring.head().unwrap().gen, 0, "first commit is generation 0 at slot 0");

    build_more(&mut ring, 1, 3);
    assert_eq!(ring.head().unwrap().gen, 1);
}

fn build_more(ring: &mut Ring<FileDev, FileDev>, count: u64, r: u8) {
    for _ in 0..count {
        let h = ring.head().unwrap();
        let next = entry(h.gen + 1, h.body_hash(), r);
        ring.append(&next).unwrap();
    }
}

#[test]
fn head_survives_reopen_across_laps() {
    let dir = TempDir::new().unwrap();
    let mut ring = Ring::open(mk_mirror(&dir, "laps", 8), 3).unwrap();
    // 30 generations over N=8: nearly four laps.
    build(&mut ring, 1, 3);
    build_more(&mut ring, 29, 3);
    assert_eq!(ring.head().unwrap().gen, 29);
    drop(ring);

    // Cold reopen: head found by search, not cache.
    let mirror = Mirror::new(
        FileDev::open(&dir.path().join("laps-a.bin")).unwrap(),
        FileDev::open(&dir.path().join("laps-b.bin")).unwrap(),
    );
    let ring = Ring::open(mirror, 3).unwrap();
    assert_eq!(ring.head().unwrap().gen, 29);
}

#[test]
fn deflection_counter_example() {
    // The deflection counter-example (README "Built for the killswitch"): N=8, gens 8..14 + old 7, slot 4 (gen 12) corrupted. Naive corrupt-as-oldest bisect prunes the true head away and returns gen 11; branch-on-corrupt must find gen 14 at slot 6.
    let dir = TempDir::new().unwrap();
    let mut ring = Ring::open(mk_mirror(&dir, "defl", 8), 3).unwrap();
    build(&mut ring, 1, 3);
    build_more(&mut ring, 14, 3); // head gen 14 → slots [8,9,10,11,12,13,14,7]
    assert_eq!(ring.head().unwrap().gen, 14);
    drop(ring);

    // Corrupt slot 4 (gen 12) on both mirrors: valid magic, broken seal.
    for side in ["a", "b"] {
        let path = dir.path().join(format!("defl-{side}.bin"));
        let mut dev = FileDev::open(&path).unwrap();
        let mut buf = ZERO_BLOCK;
        dev.read(4, &mut buf).unwrap();
        buf[3000] ^= 0xFF;
        dev.write(4, &buf).unwrap();
        dev.flush().unwrap();
    }

    let mirror = Mirror::new(
        FileDev::open(&dir.path().join("defl-a.bin")).unwrap(),
        FileDev::open(&dir.path().join("defl-b.bin")).unwrap(),
    );
    let ring = Ring::open(mirror, 3).unwrap();
    assert_eq!(
        ring.head().unwrap().gen,
        14,
        "branch-on-corrupt must survive the deflection case"
    );
}

#[test]
fn chain_enforcement() {
    let dir = TempDir::new().unwrap();
    let mut ring = Ring::open(mk_mirror(&dir, "chain", 8), 3).unwrap();
    build(&mut ring, 3, 3);
    let h = ring.head().unwrap().clone();

    // Wrong gen.
    assert!(ring.append(&entry(h.gen + 2, h.body_hash(), 3)).is_err());
    // Wrong prev_hash.
    assert!(ring.append(&entry(h.gen + 1, [9u8; 32], 3)).is_err());
    // Genesis constraints on a fresh ring.
    let mut fresh = Ring::open(mk_mirror(&dir, "fresh", 8), 3).unwrap();
    assert!(fresh.append(&entry(1, [0u8; 32], 3)).is_err(), "genesis must be gen 0");
    assert!(fresh.append(&entry(0, [1u8; 32], 3)).is_err(), "genesis prev must be zeros");
}

#[test]
fn bootstrap_discovers_exponent() {
    let dir = TempDir::new().unwrap();
    let mut ring = Ring::open(mk_mirror(&dir, "boot", 16), 3).unwrap();
    build(&mut ring, 5, 3);
    drop(ring);

    let mut mirror = Mirror::new(
        FileDev::open(&dir.path().join("boot-a.bin")).unwrap(),
        FileDev::open(&dir.path().join("boot-b.bin")).unwrap(),
    );
    assert_eq!(Ring::bootstrap_n(&mut mirror).unwrap(), Some(3));

    // Corrupt slots 0-2 on the read side: bootstrap walks forward to slot 3.
    let (a, _) = mirror.devices();
    let dev = a.unwrap();
    let mut buf = ZERO_BLOCK;
    for slot in 0..3 {
        dev.read(slot, &mut buf).unwrap();
        buf[100] ^= 0xFF;
        dev.write(slot, &buf).unwrap();
    }
    dev.flush().unwrap();
    assert_eq!(Ring::bootstrap_n(&mut mirror).unwrap(), Some(3));

    // Pre-genesis file: no exponent to find.
    let mut empty = mk_mirror(&dir, "empty", 16);
    assert_eq!(Ring::bootstrap_n(&mut empty).unwrap(), None);
}

#[test]
fn whole_file_scan_and_zero_ring() {
    let dir = TempDir::new().unwrap();

    // Trash file: garbage everywhere, zero sealed blocks → format-eligible.
    let path = dir.path().join("trash.bin");
    let mut dev = FileDev::create(&path, 16).unwrap();
    let mut junk = ZERO_BLOCK;
    junk.fill(0x5A);
    for lba in 0..16 {
        dev.write(lba, &junk).unwrap();
    }
    dev.flush().unwrap();
    assert!(!any_sealed_block(&mut dev).unwrap(), "garbage must not read as real");

    // One sealed entry buried at a random lba → real vault, format forbidden.
    let block = entry(9, [3u8; 32], 4).encode();
    dev.write(11, &block).unwrap();
    dev.flush().unwrap();
    assert!(any_sealed_block(&mut dev).unwrap(), "one valid block anywhere = real");

    // zero_ring turns Corrupt wreckage into Empty so genesis-era head searches are clean.
    let mut mirror = Mirror::new(
        FileDev::open(&path).unwrap(),
        FileDev::create(&dir.path().join("trash-b.bin"), 16).unwrap(),
    );
    zero_ring(&mut mirror, 4).unwrap();
    let mut buf = ZERO_BLOCK;
    for slot in 0..16 {
        mirror.read(slot, &mut buf).unwrap();
        assert_eq!(buf, ZERO_BLOCK, "slot {slot} not zeroed");
    }
}

#[test]
fn recent_plows_for_fence() {
    let dir = TempDir::new().unwrap();
    let mut ring = Ring::open(mk_mirror(&dir, "fence", 8), 3).unwrap();
    build(&mut ring, 10, 3); // head gen 9, plow = gen*3
    let plows = ring.recent_plows(4).unwrap();
    assert_eq!(plows, vec![27, 24, 21, 18], "newest-first plow history");

    // Near genesis: fewer than k exist.
    let mut young = Ring::open(mk_mirror(&dir, "young", 8), 3).unwrap();
    build(&mut young, 2, 3);
    assert_eq!(young.recent_plows(4).unwrap(), vec![3, 0]);
}

// ============================================================================ kill -9 harness ============================================================

/// Child: open (or genesis) the ring and append forever. Killed mid-append by the parent.
#[test]
fn ring_kill_child_worker() {
    let Ok(path_base) = std::env::var("CUSTODES_RING_KILL") else {
        return;
    };
    let a = FileDev::open(std::path::Path::new(&format!("{path_base}-a.bin"))).unwrap();
    let b = FileDev::open(std::path::Path::new(&format!("{path_base}-b.bin"))).unwrap();
    let mut ring = Ring::open(Mirror::new(a, b), 8).unwrap();
    loop {
        let (gen, prev) = match ring.head() {
            Some(h) => (h.gen + 1, h.body_hash()),
            None => (0, [0u8; 32]),
        };
        let _ = ring.append(&entry(gen, prev, 8));
    }
}

#[test]
fn ring_survives_kill_nine_and_resumes() {
    use std::time::Duration;
    use vsf::types::eagle_time::eagle_time_oscillations;
    let exe = std::env::current_exe().unwrap();
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("kill").to_str().unwrap().to_string();
    FileDev::create(std::path::Path::new(&format!("{base}-a.bin")), 256).unwrap();
    FileDev::create(std::path::Path::new(&format!("{base}-b.bin")), 256).unwrap();

    let mut last_gen: Option<u64> = None;
    for round in 0..3 {
        let mut child = std::process::Command::new(&exe)
            .args(["ring_kill_child_worker", "--exact", "--nocapture", "--test-threads=1"])
            .env("CUSTODES_RING_KILL", &base)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Pseudo-random kill delay 32..160ms from the eagle clock's low oscillation bits — no rand dep, no UNIX epoch.
        let jitter = eagle_time_oscillations() as u64 % (1 << 7);
        std::thread::sleep(Duration::from_millis((1 << 5) + jitter));
        child.kill().unwrap();
        child.wait().unwrap();

        // Reopen: head search must find a committed generation, monotonically growing across rounds, with an intact chain behind it.
        let mirror = Mirror::new(
            FileDev::open(std::path::Path::new(&format!("{base}-a.bin"))).unwrap(),
            FileDev::open(std::path::Path::new(&format!("{base}-b.bin"))).unwrap(),
        );
        let mut ring = Ring::open(mirror, 8).unwrap();
        let head = ring.head().expect("a committed head must survive kill -9").clone();
        if let Some(prev) = last_gen {
            assert!(head.gen > prev, "round {round}: progress must be monotone ({} -> {})", prev, head.gen);
        }
        last_gen = Some(head.gen);

        // Fence inputs are recoverable from the ring alone.
        let plows = ring.recent_plows(4).unwrap();
        assert!(!plows.is_empty());
    }
}
