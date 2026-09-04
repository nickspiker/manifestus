//! Tract behavior: append placement, contiguity, wrap, fence, full, clean accounting, zero-delete.

use manifestus::block::Block;
use manifestus::ring::MAGIC;
use manifestus::{sealed_hp, BlockDev, FileDev, Mirror, NoLive, Tract, ZERO_BLOCK};
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

fn mk(dir: &TempDir, name: &str, blocks: u64) -> Mirror<FileDev, FileDev> {
    let a = FileDev::create(&dir.path().join(format!("{name}-a.bin")), blocks).unwrap();
    let b = FileDev::create(&dir.path().join(format!("{name}-b.bin")), blocks).unwrap();
    Mirror::new(a, b)
}

fn tract(len: u64) -> Tract {
    Tract { base: 0, len, plow: 0, reap: 0, fence_limit: None }
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
fn appends_are_sequential_and_contiguous() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "fresh", 8);
    let mut t = tract(8);
    let placed = t.append(&mut m, &NoLive, &[seal(1), seal(2), seal(3)]).unwrap();
    assert_eq!(placed, vec![0, 1, 2]);
    assert_eq!(t.plow, 3);
    assert_eq!(t.position(), 3);
    assert_eq!(t.clean_blocks(), 5);
    // Verified on media.
    let mut buf = ZERO_BLOCK;
    t.read(&mut m, 1, &mut buf).unwrap();
    assert_eq!(buf, seal(2));
}

#[test]
fn append_wraps_once_reap_has_advanced() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "wrap", 8);
    let mut t = tract(8);
    t.append(&mut m, &NoLive, &[seal(1), seal(2), seal(3), seal(4), seal(5), seal(6)]).unwrap();
    // The reap retires the first 4 positions (their content is garbage now).
    t.reap = 4;
    assert_eq!(t.clean_blocks(), 6);
    let placed = t.append(&mut m, &NoLive, &[seal(7), seal(8), seal(9)]).unwrap();
    assert_eq!(placed, vec![6, 7, 0], "run split exactly once at the ring boundary");
    assert_eq!(t.position(), 1);
}

#[test]
fn fence_refuses_before_writing() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "fence", 8);
    let mut t = tract(8);
    t.fence_limit = Some(2);
    t.append(&mut m, &NoLive, &[seal(1), seal(2)]).unwrap();
    let err = t.append(&mut m, &NoLive, &[seal(3)]);
    assert!(matches!(err, Err(manifestus::Error::Fenced(2))));
    // Refusal had no side effects.
    assert_eq!(t.plow, 2);
    let mut buf = ZERO_BLOCK;
    t.read(&mut m, 2, &mut buf).unwrap();
    assert_eq!(buf, ZERO_BLOCK);
}

#[test]
fn full_tract_refuses_before_writing() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "full", 8);
    let mut t = tract(8);
    let blocks: Vec<Block> = (0..8).map(seal).collect();
    t.append(&mut m, &NoLive, &blocks).unwrap();
    assert_eq!(t.clean_blocks(), 0);
    assert!(matches!(t.append(&mut m, &NoLive, &[seal(9)]), Err(manifestus::Error::TractFull)));
    assert_eq!(t.plow, 8, "refusal is side-effect free");
}

#[test]
fn zero_delete_zeroes_both_mirrors() {
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "zero", 8);
    let mut t = tract(8);
    t.append(&mut m, &NoLive, &[seal(1)]).unwrap();
    t.zero_delete(&mut m, 0).unwrap();
    let (a, b) = m.devices();
    let mut buf = ZERO_BLOCK;
    a.unwrap().read(0, &mut buf).unwrap();
    assert_eq!(buf, ZERO_BLOCK);
    b.unwrap().read(0, &mut buf).unwrap();
    assert_eq!(buf, ZERO_BLOCK);
}

#[test]
fn originals_survive_until_reap_retires_them() {
    // Killswitch property at the tract level: appends never touch occupied space, so every committed block is byte-intact until the reap explicitly retires its window.
    let dir = TempDir::new().unwrap();
    let mut m = mk(&dir, "intact", 8);
    let mut t = tract(8);
    t.append(&mut m, &NoLive, &[seal(1), seal(2), seal(3)]).unwrap();
    t.append(&mut m, &NoLive, &[seal(4), seal(5)]).unwrap();
    for (lba, tag) in [(0u64, 1u64), (1, 2), (2, 3), (3, 4), (4, 5)] {
        let mut buf = ZERO_BLOCK;
        t.read(&mut m, lba, &mut buf).unwrap();
        assert_eq!(buf, seal(tag), "block {lba} intact");
    }
}
