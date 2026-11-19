//! Single-copy extents (`manifestus::extent`): the table lives in the vault as a value, survives a reopen, and leaves every other value alone.

use manifestus::{DeletePolicy, Extents, FileDev, Mirror, Vault};
use tempfile::TempDir;

const R_LOG2: u8 = 4;
const BLOCKS: u64 = 1 << 12;

fn open(dir: &TempDir, create: bool) -> Vault<FileDev, FileDev> {
    let (pa, pb) = (dir.path().join("a.vsf"), dir.path().join("b.vsf"));
    let (a, b) = if create { (FileDev::create(&pa, BLOCKS).unwrap(), FileDev::create(&pb, BLOCKS).unwrap()) } else { (FileDev::open(&pa).unwrap(), FileDev::open(&pb).unwrap()) };
    Vault::open(Mirror::new(a, b), R_LOG2, 1_000, DeletePolicy::UnlinkOnly).unwrap()
}

#[test]
fn table_is_a_vault_value() {
    let dir = TempDir::new().unwrap();
    let other = *blake3::hash(b"a value of the embedder's").as_bytes();
    {
        let mut v = open(&dir, true);
        v.put(&other, b"kept as it was", 1_100).unwrap();
        let mut t = Extents::load(&mut v, 1 << 20).unwrap();
        assert!(t.list().is_empty());
        t.reserve([1; 32], [9; 32], 1 << 18, 1_200).unwrap();
        t.reserve([2; 32], [9; 32], 1 << 10, 1_201).unwrap();
        t.store(&mut v, 1_300).unwrap();
        t.seal(&[1; 32], 12345, [7; 32], 1_400).unwrap();
        t.store(&mut v, 1_400).unwrap();
    }
    let mut v = open(&dir, false);
    let t = Extents::load(&mut v, 1 << 20).unwrap();
    let a = t.find(&[1; 32]).unwrap();
    assert!(a.sealed && a.bytes == 12345 && a.blocks == 4 && a.hash == [7; 32]);
    assert!(!t.find(&[2; 32]).unwrap().sealed);
    assert_eq!(v.get(&other).unwrap().unwrap(), b"kept as it was");
    // Another area size is not this table's.
    assert!(Extents::load(&mut v, 1 << 19).is_err());
}
