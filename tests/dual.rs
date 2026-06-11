//! Dual-ring behavior: healing, divergence, degraded tracking.

use tempfile::TempDir;
use vsf_db::DualStore;

const ANCHOR: [u8; 32] = [0xCDu8; 32];

fn fresh() -> (TempDir, [std::path::PathBuf; 2]) {
    let dir = TempDir::new().unwrap();
    let paths = [dir.path().join("ring0.db"), dir.path().join("ring1.db")];
    (dir, paths)
}

#[test]
fn fresh_dual_put_get() {
    let (_dir, paths) = fresh();
    let mut d = DualStore::open_or_create(paths, &ANCHOR).unwrap();
    assert!(!d.degraded());
    d.put([1u8; 32], b"hello", 0, None, 0).unwrap();
    assert_eq!(d.get(&[1u8; 32]).unwrap(), Some(b"hello".to_vec()));
}

#[test]
fn both_rings_written() {
    let (_dir, paths) = fresh();
    {
        let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
        d.put([2u8; 32], b"both", 0, None, 0).unwrap();
    }
    // Open each ring individually as a single Store — both must hold the value.
    for p in &paths {
        let mut s = vsf_db::Store::open_or_create(p, &ANCHOR).unwrap();
        assert_eq!(s.get(&[2u8; 32]).unwrap(), Some(b"both".to_vec()), "ring {:?} missing the write", p);
    }
}

#[test]
fn missing_ring_heals_on_open() {
    let (_dir, paths) = fresh();
    {
        let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
        d.put([3u8; 32], b"survives", 0, None, 0).unwrap();
    }
    std::fs::remove_file(&paths[1]).unwrap();

    let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
    assert_eq!(d.get(&[3u8; 32]).unwrap(), Some(b"survives".to_vec()));
    // Healed ring 1 must now hold the data too.
    drop(d);
    let mut s1 = vsf_db::Store::open_or_create(&paths[1], &ANCHOR).unwrap();
    assert_eq!(s1.get(&[3u8; 32]).unwrap(), Some(b"survives".to_vec()));
}

#[test]
fn torn_tail_ring_heals_via_seq() {
    let (_dir, paths) = fresh();
    {
        let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
        d.put([4u8; 32], b"first", 0, None, 0).unwrap();
        d.put([5u8; 32], b"second", 0, None, 0).unwrap();
    }
    // Tear ring 1's tail: drop the last 30 bytes (mid-record).
    {
        let len = std::fs::metadata(&paths[1]).unwrap().len();
        let f = std::fs::OpenOptions::new().write(true).open(&paths[1]).unwrap();
        f.set_len(len - 30).unwrap();
    }
    let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
    // Both records visible (served from ring 0 which is intact).
    assert_eq!(d.get(&[4u8; 32]).unwrap(), Some(b"first".to_vec()));
    assert_eq!(d.get(&[5u8; 32]).unwrap(), Some(b"second".to_vec()));
    // And ring 1 must be healed to hold both as well.
    drop(d);
    let mut s1 = vsf_db::Store::open_or_create(&paths[1], &ANCHOR).unwrap();
    assert_eq!(s1.get(&[5u8; 32]).unwrap(), Some(b"second".to_vec()));
}

#[test]
fn garbage_ring_repaired_from_survivor() {
    let (_dir, paths) = fresh();
    {
        let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
        d.put([6u8; 32], b"good", 0, None, 0).unwrap();
    }
    // Replace ring 1 with a non-vsf-db file (bad magic).
    std::fs::write(&paths[1], b"this is not a vault").unwrap();

    let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
    assert!(d.degraded(), "hard repair should flag degraded");
    assert_eq!(d.get(&[6u8; 32]).unwrap(), Some(b"good".to_vec()));
    drop(d);
    let mut s1 = vsf_db::Store::open_or_create(&paths[1], &ANCHOR).unwrap();
    assert_eq!(s1.get(&[6u8; 32]).unwrap(), Some(b"good".to_vec()), "ring 1 rebuilt from survivor");
}

#[test]
fn divergent_seqs_converge_to_higher() {
    let (_dir, paths) = fresh();
    {
        let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
        d.put([7u8; 32], b"v1", 0, None, 0).unwrap();
    }
    // Write extra records to ring 0 only (simulates crash between ring writes).
    {
        let mut s0 = vsf_db::Store::open_or_create(&paths[0], &ANCHOR).unwrap();
        s0.put([8u8; 32], b"only-in-0", 0, None, 0).unwrap();
    }
    let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
    assert_eq!(d.get(&[8u8; 32]).unwrap(), Some(b"only-in-0".to_vec()));
    drop(d);
    let mut s1 = vsf_db::Store::open_or_create(&paths[1], &ANCHOR).unwrap();
    assert_eq!(s1.get(&[8u8; 32]).unwrap(), Some(b"only-in-0".to_vec()), "lower-seq ring caught up");
}

#[test]
fn delete_applies_to_both_rings() {
    let (_dir, paths) = fresh();
    {
        let mut d = DualStore::open_or_create(paths.clone(), &ANCHOR).unwrap();
        d.put([9u8; 32], b"doomed", 0, None, 0).unwrap();
        d.delete(&[9u8; 32], 0).unwrap();
    }
    for p in &paths {
        let mut s = vsf_db::Store::open_or_create(p, &ANCHOR).unwrap();
        assert_eq!(s.get(&[9u8; 32]).unwrap(), None, "ring {:?} should have the tombstone", p);
    }
}

#[test]
fn empty_dual_reports_clean() {
    let (_dir, paths) = fresh();
    let d = DualStore::open_or_create(paths, &ANCHOR).unwrap();
    assert!(!d.degraded());
    assert!(d.is_empty());
    assert_eq!(d.anchor_seq(), 0);
}
