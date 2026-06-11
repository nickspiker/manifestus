//! Layer 0 storage behavior under no-clean-shutdown assumptions.

use tempfile::TempDir;
use custodes::Store;

const ANCHOR: [u8; 32] = [0xABu8; 32];

fn fresh() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("vault.db");
    (dir, path)
}

#[test]
fn put_get_roundtrip() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([1u8; 32], b"hello", 7, None, 100).unwrap();
    assert_eq!(s.get(&[1u8; 32]).unwrap(), Some(b"hello".to_vec()));
}

#[test]
fn missing_key_returns_none() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.get(&[99u8; 32]).unwrap(), None);
}

#[test]
fn persistence_across_open() {
    let (_dir, path) = fresh();
    {
        let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
        s.put([2u8; 32], b"persistent", 0, None, 0).unwrap();
    }
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.get(&[2u8; 32]).unwrap(), Some(b"persistent".to_vec()));
}

#[test]
fn overwrite_returns_latest_value() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([3u8; 32], b"first", 0, None, 0).unwrap();
    s.put([3u8; 32], b"second", 0, None, 0).unwrap();
    assert_eq!(s.get(&[3u8; 32]).unwrap(), Some(b"second".to_vec()));
}

#[test]
fn overwrite_accumulates_waste() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([3u8; 32], b"first", 0, None, 0).unwrap();
    assert_eq!(s.wasted_bytes(), 0);
    s.put([3u8; 32], b"second", 0, None, 0).unwrap();
    assert!(s.wasted_bytes() > 0, "overwriting should produce waste");
}

#[test]
fn delete_makes_key_invisible() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([4u8; 32], b"value", 0, None, 0).unwrap();
    s.delete(&[4u8; 32], 0).unwrap();
    assert_eq!(s.get(&[4u8; 32]).unwrap(), None);
    assert_eq!(s.iter().count(), 0);
}

#[test]
fn delete_persists_across_open() {
    let (_dir, path) = fresh();
    {
        let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
        s.put([5u8; 32], b"value", 0, None, 0).unwrap();
        s.delete(&[5u8; 32], 0).unwrap();
    }
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.get(&[5u8; 32]).unwrap(), None);
}

#[test]
fn resurrect_after_delete() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([6u8; 32], b"original", 0, None, 0).unwrap();
    s.delete(&[6u8; 32], 0).unwrap();
    s.put([6u8; 32], b"reborn", 0, None, 0).unwrap();
    assert_eq!(s.get(&[6u8; 32]).unwrap(), Some(b"reborn".to_vec()));
}

#[test]
fn corrupt_tail_silently_truncated() {
    let (_dir, path) = fresh();
    {
        let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
        s.put([7u8; 32], b"alpha", 0, None, 0).unwrap();
        s.put([8u8; 32], b"beta", 0, None, 0).unwrap();
    }
    // Simulate a torn write at the tail by appending garbage.
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        std::io::Write::write_all(&mut f, &[0xFFu8; 200]).unwrap();
    }
    // Reopen: garbage truncated, prior good records intact.
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.get(&[7u8; 32]).unwrap(), Some(b"alpha".to_vec()));
    assert_eq!(s.get(&[8u8; 32]).unwrap(), Some(b"beta".to_vec()));
}

#[test]
fn truncated_mid_record_loses_only_that_record() {
    let (_dir, path) = fresh();
    let after_first;
    {
        let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
        s.put([10u8; 32], b"durable", 0, None, 0).unwrap();
        after_first = s.file_size();
        s.put([11u8; 32], b"in-flight", 0, None, 0).unwrap();
    }
    // Truncate the file mid-second-record (drop the last few bytes).
    {
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len(after_first + 50).unwrap(); // mid-header of the second record
    }
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.get(&[10u8; 32]).unwrap(), Some(b"durable".to_vec()));
    assert_eq!(s.get(&[11u8; 32]).unwrap(), None, "second record should be gone");
    // File should now be exactly at after_first.
    assert_eq!(s.file_size(), after_first, "file truncated to last valid record");
}

#[test]
fn anchor_seq_monotonic() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([12u8; 32], b"a", 0, None, 0).unwrap();
    assert_eq!(s.anchor_seq(), 1);
    s.put([13u8; 32], b"b", 0, None, 0).unwrap();
    assert_eq!(s.anchor_seq(), 2);
    s.delete(&[12u8; 32], 0).unwrap();
    assert_eq!(s.anchor_seq(), 3);
}

#[test]
fn anchor_seq_persists_across_open() {
    let (_dir, path) = fresh();
    {
        let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
        s.put([14u8; 32], b"x", 0, None, 0).unwrap();
        s.put([15u8; 32], b"y", 0, None, 0).unwrap();
        assert_eq!(s.anchor_seq(), 2);
    }
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.anchor_seq(), 2);
    s.put([16u8; 32], b"z", 0, None, 0).unwrap();
    assert_eq!(s.anchor_seq(), 3);
}

#[test]
fn iter_returns_live_entries() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([20u8; 32], b"v1", 0, None, 0).unwrap();
    s.put([21u8; 32], b"v2", 0, None, 0).unwrap();
    s.put([22u8; 32], b"v3", 0, None, 0).unwrap();
    s.delete(&[21u8; 32], 0).unwrap();
    let keys: Vec<[u8; 32]> = s.iter().map(|(k, _)| *k).collect();
    assert_eq!(keys.len(), 2);
    assert!(keys.contains(&[20u8; 32]));
    assert!(keys.contains(&[22u8; 32]));
    assert!(!keys.contains(&[21u8; 32]));
}

#[test]
fn wrong_anchor_key_truncates_everything() {
    // Sharp edge: opening with the wrong anchor_key on an existing file means every record fails HMAC → silent truncate → empty store. The caller (FlatStorage's dual-ring layer) must be careful to only open with the right key. This test pins the behavior.
    let (_dir, path) = fresh();
    {
        let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
        s.put([30u8; 32], b"data", 0, None, 0).unwrap();
    }
    let other_key = [0xFFu8; 32];
    let s = Store::open_or_create(&path, &other_key).unwrap();
    assert!(s.is_empty(), "wrong anchor key → all records dropped");
}

#[test]
fn compact_keeps_live_drops_waste() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([40u8; 32], b"keep_v1", 0, None, 0).unwrap();
    s.put([40u8; 32], b"keep_v2", 0, None, 0).unwrap(); // supersedes v1
    s.put([41u8; 32], b"alive", 0, None, 0).unwrap();
    s.put([42u8; 32], b"doomed", 0, None, 0).unwrap();
    s.delete(&[42u8; 32], 0).unwrap();

    let pre_compact_size = s.file_size();
    assert!(s.wasted_bytes() > 0);

    let target = path.with_extension("compacted");
    s.compact_to(&target).unwrap();

    // Reopen compacted file with same anchor key — should contain only the live entries.
    let mut compacted = Store::open_or_create(&target, &ANCHOR).unwrap();
    assert_eq!(compacted.get(&[40u8; 32]).unwrap(), Some(b"keep_v2".to_vec()));
    assert_eq!(compacted.get(&[41u8; 32]).unwrap(), Some(b"alive".to_vec()));
    assert_eq!(compacted.get(&[42u8; 32]).unwrap(), None);
    assert!(compacted.file_size() < pre_compact_size, "compaction shrinks the file");
    assert_eq!(compacted.wasted_bytes(), 0, "compacted file has no waste");
}

#[test]
fn empty_file_initializes_with_header() {
    let (_dir, path) = fresh();
    let s = Store::open_or_create(&path, &ANCHOR).unwrap();
    assert_eq!(s.file_size(), 8, "fresh file should be 8 bytes (header only)");
    assert!(s.is_empty());
}

#[test]
fn large_value_roundtrip() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    let big: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
    s.put([50u8; 32], &big, 0, None, 0).unwrap();
    assert_eq!(s.get(&[50u8; 32]).unwrap(), Some(big));
}

#[test]
fn zero_length_value_roundtrip() {
    let (_dir, path) = fresh();
    let mut s = Store::open_or_create(&path, &ANCHOR).unwrap();
    s.put([60u8; 32], b"", 0, None, 0).unwrap();
    assert_eq!(s.get(&[60u8; 32]).unwrap(), Some(Vec::new()));
}
