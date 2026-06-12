//! HAMT behavior: COW put/lookup/delete, lone + direct leaves, splits, flush + cold reopen, corruption, relocation repair.

use custodes::block::Block;
use custodes::{lone_capacity, BlockDev, Delta, FileDev, Hamt, Liveness, Mirror, Tract, ZERO_BLOCK};
use std::collections::HashMap;
use tempfile::TempDir;

/// Vault-style live map: applies HAMT deltas, answers the plow's liveness question.
#[derive(Default)]
struct LiveMap(HashMap<u64, [u8; 32]>);

impl LiveMap {
    fn apply(&mut self, d: Delta) {
        for (lba, hp) in d.removed {
            if self.0.get(&lba) == Some(&hp) {
                self.0.remove(&lba);
            }
        }
        for (lba, hp) in d.added {
            self.0.insert(lba, hp);
        }
    }
}

impl Liveness for LiveMap {
    fn is_live(&self, lba: u64, hp: &[u8; 32]) -> bool {
        self.0.get(&lba) == Some(hp)
    }
}

fn key(i: u64) -> [u8; 32] {
    *blake3::hash(&i.to_le_bytes()).as_bytes()
}

fn mk(dir: &TempDir, name: &str, blocks: u64) -> (Mirror<FileDev, FileDev>, Tract) {
    let a = FileDev::create(&dir.path().join(format!("{name}-a.bin")), blocks).unwrap();
    let b = FileDev::create(&dir.path().join(format!("{name}-b.bin")), blocks).unwrap();
    (
        Mirror::new(a, b),
        Tract { base: 0, len: blocks, plow: 0, fence_limit: None },
    )
}

#[test]
fn lone_put_lookup_roundtrip() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "lone", 64);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    h.put(&mut m, &mut t, &live, &key(1), b"hello custodes").unwrap();
    live.apply(h.take_delta());
    assert_eq!(
        h.lookup(&mut m, &t, &key(1)).unwrap(),
        Some(b"hello custodes".to_vec())
    );
    assert_eq!(h.lookup(&mut m, &t, &key(2)).unwrap(), None, "absent key");
}

#[test]
fn overwrite_replaces_value() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "ow", 64);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    h.put(&mut m, &mut t, &live, &key(7), b"first").unwrap();
    live.apply(h.take_delta());
    h.put(&mut m, &mut t, &live, &key(7), b"second").unwrap();
    let d = h.take_delta();
    assert!(!d.removed.is_empty(), "old leaf must be superseded");
    live.apply(d);
    assert_eq!(h.lookup(&mut m, &t, &key(7)).unwrap(), Some(b"second".to_vec()));
}

#[test]
fn many_keys_flush_and_cold_reopen() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "many", 2048);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    for i in 0..200u64 {
        let v = format!("value-{i}");
        h.put(&mut m, &mut t, &live, &key(i), v.as_bytes()).unwrap();
        live.apply(h.take_delta());
    }
    for i in 0..200u64 {
        assert_eq!(
            h.lookup(&mut m, &t, &key(i)).unwrap(),
            Some(format!("value-{i}").into_bytes()),
            "warm lookup {i}"
        );
    }

    let (root_hash, root_lba) = h.flush(&mut m, &mut t, &live).unwrap();
    live.apply(h.take_delta());
    assert_ne!(root_hash, [0u8; 32]);

    // Cold: a fresh Hamt from only the committed root — every read hash-verified on the way down.
    let mut cold = Hamt::from_root(root_hash, root_lba);
    for i in 0..200u64 {
        assert_eq!(
            cold.lookup(&mut m, &t, &key(i)).unwrap(),
            Some(format!("value-{i}").into_bytes()),
            "cold lookup {i}"
        );
    }
    assert_eq!(cold.lookup(&mut m, &t, &key(999)).unwrap(), None);
}

#[test]
fn deep_split_on_shared_prefix() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "deep", 256);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    // Two keys identical until the final bits: the split must chain internals to depth ~50.
    let mut k1 = [0u8; 32];
    let mut k2 = [0u8; 32];
    k1[31] = 0b0000_0001;
    k2[31] = 0b0000_0010;
    h.put(&mut m, &mut t, &live, &k1, b"one").unwrap();
    live.apply(h.take_delta());
    h.put(&mut m, &mut t, &live, &k2, b"two").unwrap();
    live.apply(h.take_delta());

    assert_eq!(h.lookup(&mut m, &t, &k1).unwrap(), Some(b"one".to_vec()));
    assert_eq!(h.lookup(&mut m, &t, &k2).unwrap(), Some(b"two".to_vec()));

    // Survives a flush + cold reopen.
    let (rh, rl) = h.flush(&mut m, &mut t, &live).unwrap();
    live.apply(h.take_delta());
    let mut cold = Hamt::from_root(rh, rl);
    assert_eq!(cold.lookup(&mut m, &t, &k1).unwrap(), Some(b"one".to_vec()));
    assert_eq!(cold.lookup(&mut m, &t, &k2).unwrap(), Some(b"two".to_vec()));
}

#[test]
fn direct_leaf_big_value_roundtrip() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "big", 256);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    // 20KB — photon chain blobs are 16KB+, this is the real consumer shape.
    let big: Vec<u8> = (0..20_000).map(|i| (i % 251) as u8).collect();
    assert!(big.len() > lone_capacity());
    h.put(&mut m, &mut t, &live, &key(42), &big).unwrap();
    live.apply(h.take_delta());
    assert_eq!(h.lookup(&mut m, &t, &key(42)).unwrap(), Some(big.clone()));

    // Cold path too.
    let (rh, rl) = h.flush(&mut m, &mut t, &live).unwrap();
    live.apply(h.take_delta());
    let mut cold = Hamt::from_root(rh, rl);
    assert_eq!(cold.lookup(&mut m, &t, &key(42)).unwrap(), Some(big));
}

#[test]
fn delete_zeroes_and_returns_none() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "del", 256);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    let big: Vec<u8> = vec![0xAB; 12_000];
    h.put(&mut m, &mut t, &live, &key(5), &big).unwrap();
    live.apply(h.take_delta());
    h.put(&mut m, &mut t, &live, &key(6), b"small").unwrap();
    live.apply(h.take_delta());

    assert!(h.delete(&mut m, &mut t, &key(5)).unwrap());
    live.apply(h.take_delta());
    assert_eq!(h.lookup(&mut m, &t, &key(5)).unwrap(), None, "fast delete → None");
    assert_eq!(h.lookup(&mut m, &t, &key(6)).unwrap(), Some(b"small".to_vec()), "neighbor untouched");
    assert!(!h.delete(&mut m, &mut t, &key(5)).unwrap(), "double delete is a no-op");

    // Re-put after delete resurrects.
    h.put(&mut m, &mut t, &live, &key(5), b"reborn").unwrap();
    live.apply(h.take_delta());
    assert_eq!(h.lookup(&mut m, &t, &key(5)).unwrap(), Some(b"reborn".to_vec()));
}

#[test]
fn corrupt_committed_node_is_loud() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "corr", 256);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();
    for i in 0..40u64 {
        h.put(&mut m, &mut t, &live, &key(i), b"x").unwrap();
        live.apply(h.take_delta());
    }
    let (rh, rl) = h.flush(&mut m, &mut t, &live).unwrap();
    live.apply(h.take_delta());

    // Flip a byte in the committed root block.
    let mut buf = ZERO_BLOCK;
    t.read(&mut m, rl, &mut buf).unwrap();
    buf[2500] ^= 1;
    m.write_verified(t.base + rl, &buf).unwrap();

    let mut cold = Hamt::from_root(rh, rl);
    let mut any_err = false;
    for i in 0..40u64 {
        if cold.lookup(&mut m, &t, &key(i)).is_err() {
            any_err = true;
            break;
        }
    }
    assert!(any_err, "corrupt index node must error loudly, never return wrong data");
}

#[test]
fn relocation_repair_keeps_index_correct() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "reloc", 64);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();

    h.put(&mut m, &mut t, &live, &key(1), b"alpha").unwrap();
    live.apply(h.take_delta());
    h.put(&mut m, &mut t, &live, &key(2), b"beta").unwrap();
    live.apply(h.take_delta());
    let (rh, rl) = h.flush(&mut m, &mut t, &live).unwrap();
    live.apply(h.take_delta());
    let _ = (rh, rl);

    // Force relocations: zero-delete nothing, just spin a window past the live blocks from a later plow position so they compact backward.
    let lap_start = t.plow;
    let out = t.spin_window(&mut m, &live, 8).unwrap();
    let _ = lap_start;
    if !out.relocations.is_empty() {
        h.repair_relocs(&mut m, &t, &out.relocations).unwrap();
        // Vault would update the live map from the relocations:
        for r in &out.relocations {
            live.0.remove(&r.from);
            live.0.insert(r.to, r.hp);
        }
    }

    assert_eq!(h.lookup(&mut m, &t, &key(1)).unwrap(), Some(b"alpha".to_vec()));
    assert_eq!(h.lookup(&mut m, &t, &key(2)).unwrap(), Some(b"beta".to_vec()));

    // And the repaired index survives a flush + cold reopen.
    let (rh2, rl2) = h.flush(&mut m, &mut t, &live).unwrap();
    live.apply(h.take_delta());
    let mut cold = Hamt::from_root(rh2, rl2);
    assert_eq!(cold.lookup(&mut m, &t, &key(1)).unwrap(), Some(b"alpha".to_vec()));
    assert_eq!(cold.lookup(&mut m, &t, &key(2)).unwrap(), Some(b"beta".to_vec()));
}

#[test]
fn empty_flush_is_zero_root() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "empty", 16);
    let live = LiveMap::default();
    let mut h = Hamt::empty();
    let (rh, _) = h.flush(&mut m, &mut t, &live).unwrap();
    assert_eq!(rh, [0u8; 32]);
    let _ = m.block_count();
}

#[test]
fn value_byte_sizes_roundtrip_near_lone_boundary() {
    let dir = TempDir::new().unwrap();
    let (mut m, mut t) = mk(&dir, "edge", 512);
    let mut live = LiveMap::default();
    let mut h = Hamt::empty();
    let cap = lone_capacity();
    for (i, len) in [0usize, 1, cap - 1, cap, cap + 1, cap * 2 + 7].into_iter().enumerate() {
        let v: Vec<u8> = (0..len).map(|j| (j % 256) as u8).collect();
        let k = key(1000 + i as u64);
        h.put(&mut m, &mut t, &live, &k, &v).unwrap();
        live.apply(h.take_delta());
        assert_eq!(h.lookup(&mut m, &t, &k).unwrap(), Some(v), "len {len}");
    }
}

/// Block type used in helpers above (kept to silence unused-import lints if shapes change).
#[allow(dead_code)]
fn _shape(_: Block) {}
