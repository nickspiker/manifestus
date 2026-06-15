//! Plow behavior: placement, hole reuse, compaction with relocation, fence, full, zero-delete, killswitch stale-copy property.

use manifestus::ring::MAGIC;
use manifestus::{
    sealed_hp, BlockDev, FileDev, Liveness, Mirror, Tract, ZERO_BLOCK,
};
use manifestus::block::Block;
use std::collections::HashMap;
use tempfile::TempDir;

/// Minimal sealed block: RÅ< hp > + tag payload + zero pad. Content-agnostic from the tract's view.
fn seal(tag: u64) -> Block {
    use vsf::types::VsfType;
    let mut buf = ZERO_BLOCK;
    buf[..4].copy_from_slice(&MAGIC);
    let hp0 = VsfType::hp(vec![0u8; 32]).flatten();
    let hp_len = hp0.len();
    buf[4..4 + hp_len].copy_from_slice(&hp0);
    buf[4 + hp_len] = b'>';
    let body = 4 + hp_len + 1;
    buf[body..body + 8].copy_from_slice(&tag.to_le_bytes());
    let h = blake3::hash(&buf[body..]);
    let hp = VsfType::hp(h.as_bytes().to_vec()).flatten();
    buf[4..4 + hp_len].copy_from_slice(&hp);
    buf
}

#[derive(Default)]
struct MapOracle(HashMap<u64, [u8; 32]>);

impl Liveness for MapOracle {
    fn is_live(&self, lba: u64, hp: &[u8; 32]) -> bool {
        self.0.get(&lba) == Some(hp)
    }
}

fn mk(dir: &TempDir, name: &str, blocks: u64) -> Mirror<FileDev, FileDev> {
    let a = FileDev::create(&dir.path().join(format!("{name}-a.bin")), blocks).unwrap();
    let b = FileDev::create(&dir.path().join(format!("{name}-b.bin")), blocks).unwrap();
    Mirror::new(a, b)
}

fn tract(len: u64) -> Tract {
    Tract { base: 0, len, plow: 0, fence_limit: None }
}

#[test]
fn sealed_hp_accepts_and_rejects() {
    let b = seal(7);
    assert!(sealed_hp(&b).is_some());
    let mut bad = b;
    bad[600] ^= 1;
    assert!(sealed_hp(&bad).is_none());
    assert!(sealed_hp(&ZERO_BLOCK).is_none());
}

#[test]
fn fresh_placement_is_sequential() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "fresh", 8);
    let mut t = tract(8);
    let oracle = MapOracle::default();
    let out = t
        .advance(&mut m, &oracle, &[seal(1), seal(2), seal(3)], 0)
        .unwrap();
    assert_eq!(out.placed, vec![0, 1, 2]);
    assert!(out.relocations.is_empty());
    assert_eq!(t.plow, 3);
    assert_eq!(t.position(), 3);
}

#[test]
fn live_blocks_skipped_in_place_and_holes_reused() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "holes", 8);
    let mut t = tract(8);
    let mut oracle = MapOracle::default();

    // Fill 0..5, keep 0,2,4 live (1,3 become dead holes).
    let blocks: Vec<Block> = (0..5).map(seal).collect();
    let out = t.advance(&mut m, &oracle, &blocks, 0).unwrap();
    assert_eq!(out.placed, vec![0, 1, 2, 3, 4]);
    for lba in [0u64, 2, 4] {
        oracle.0.insert(lba, sealed_hp(&blocks[lba as usize]).unwrap());
    }

    // Two more: positions 5,6 are virgin dead.
    let out = t.advance(&mut m, &oracle, &[seal(10), seal(11)], 0).unwrap();
    assert_eq!(out.placed, vec![5, 6]);

    // Two more across the wrap. The pass compacts: live 0 relocates into dead 7, live 2 into hole 1, live 4 into hole 3 — and the payload lands on the dead orphans at 5,6. Crucially the relocated ORIGINALS (0,2,4) are reserved this pass: payload may not overwrite them (same-pass killswitch guard).
    let out = t.advance(&mut m, &oracle, &[seal(12), seal(13)], 0).unwrap();
    assert_eq!(out.placed, vec![5, 6]);
    assert_eq!(
        out.relocations
            .iter()
            .map(|r| (r.from, r.to))
            .collect::<Vec<_>>(),
        vec![(0, 7), (2, 1), (4, 3)],
        "compaction cascade across the wrap"
    );

    // KILLSWITCH: every relocated original is still sealed in place — a crash before the relocating commit loses nothing.
    let mut buf = ZERO_BLOCK;
    for lba in [0u64, 2, 4] {
        t.read(&mut m, lba, &mut buf).unwrap();
        assert_eq!(
            sealed_hp(&buf),
            Some(sealed_hp(&blocks[lba as usize]).unwrap()),
            "original at {lba} must survive the pass"
        );
    }
}

#[test]
fn spin_compacts_and_reports_relocations() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "spin", 8);
    let mut t = tract(8);
    let mut oracle = MapOracle::default();

    // Layout: pos0 dead-sealed (orphan), pos1 live A, pos2 dead-zero...
    let orphan = seal(99);
    let a = seal(100);
    let out = t.advance(&mut m, &oracle, &[orphan.clone(), a.clone()], 0).unwrap();
    assert_eq!(out.placed, vec![0, 1]);
    let hp_a = sealed_hp(&a).unwrap();
    oracle.0.insert(1, hp_a); // only A is referenced; pos0 is an orphan (commit never landed)

    // Spin a 3-position window from plow=2... wrap to 0: orphan trampled, A relocates 1 → compacted home.
    t.plow = 2;
    let out = t.spin_window(&mut m, &oracle, 3).unwrap();
    // Scan covers 2,3,4 (dead) — but A sits at 1, untouched by this window: no relocs yet.
    assert!(out.relocations.is_empty());
    assert_eq!(out.trampled, 0);

    // Spin from the wrap: window covering 5,6,7,0(orphan→tramples),1(live A, write<scan → relocate).
    t.plow = 5;
    let out = t.spin_window(&mut m, &oracle, 5).unwrap();
    assert_eq!(out.trampled, 1, "orphan at 0 trampled");
    assert_eq!(out.relocations.len(), 1);
    let r = &out.relocations[0];
    assert_eq!((r.hp, r.from), (hp_a, 1));
    assert_eq!(r.to, 5, "A compacts back to the write cursor");

    // KILLSWITCH PROPERTY: the original at pos1 is physically intact until something overwrites it — a crash before the relocating commit leaves the committed index pointing at a valid block.
    let mut buf = ZERO_BLOCK;
    t.read(&mut m, 1, &mut buf).unwrap();
    assert_eq!(sealed_hp(&buf), Some(hp_a), "stale copy must remain sealed in place");
    // And the new copy is sealed at its destination.
    t.read(&mut m, 5, &mut buf).unwrap();
    assert_eq!(sealed_hp(&buf), Some(hp_a));
}

#[test]
fn fence_blocks_writes() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "fence", 8);
    let mut t = tract(8);
    t.fence_limit = Some(2);
    let oracle = MapOracle::default();
    let out = t.advance(&mut m, &oracle, &[seal(1), seal(2)], 0).unwrap();
    assert_eq!(out.placed, vec![0, 1]);
    let err = t.advance(&mut m, &oracle, &[seal(3)], 0);
    assert!(matches!(err, Err(manifestus::Error::Fenced(2))));
}

#[test]
fn full_tract_errors() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "full", 4);
    let mut t = tract(4);
    let mut oracle = MapOracle::default();
    let blocks: Vec<Block> = (0..4).map(seal).collect();
    let out = t.advance(&mut m, &oracle, &blocks, 0).unwrap();
    for (lba, b) in out.placed.iter().zip(&blocks) {
        oracle.0.insert(*lba, sealed_hp(b).unwrap());
    }
    assert!(matches!(
        t.advance(&mut m, &oracle, &[seal(9)], 0),
        Err(manifestus::Error::TractFull)
    ));
}

#[test]
fn zero_delete_zeroes_both_mirrors() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "del", 4);
    let mut t = tract(4);
    let oracle = MapOracle::default();
    t.advance(&mut m, &oracle, &[seal(1)], 0).unwrap();
    t.zero_delete(&mut m, 0).unwrap();
    let (a, b) = m.devices();
    let mut buf = ZERO_BLOCK;
    a.unwrap().read(0, &mut buf).unwrap();
    assert_eq!(buf, ZERO_BLOCK);
    b.unwrap().read(0, &mut buf).unwrap();
    assert_eq!(buf, ZERO_BLOCK);
    assert!(t.zero_delete(&mut m, 4).is_err(), "bounds-checked");
}

#[test]
fn trash_is_trampled() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "trash", 4);
    let mut t = tract(4);
    let oracle = MapOracle::default();
    // Garbage (non-sealed, non-zero) directly at pos 0.
    let mut junk = ZERO_BLOCK;
    junk.fill(0xEE);
    m.write_verified(0, &junk).unwrap();

    let out = t.advance(&mut m, &oracle, &[seal(5)], 0).unwrap();
    assert_eq!(out.placed, vec![0], "trash slot consumed");
    assert_eq!(out.trampled, 1);
}
