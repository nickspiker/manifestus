//! The fast-delete tombstone bug — forensic reproduction of the 2026-07-24 K0MAz vault brick.
//!
//! `Hamt::delete` zeroes the leaf but historically left the committed pointer in place ("stale pointer, lookups read zero → None").
//! That safety argument only holds while the slot stays zero: the reap correctly classifies the zeroed slot as dead, advances past it, and one plow lap later an unrelated append REUSES the slot.
//! The tombstone pointer then flips from "reads as deleted" to "seal mismatch" — `get` of the deleted key errors, and the next `Vault::open` dies in `walk_live` with `Error::Seal`, bricking the whole vault.
//!
//! The test builds exactly that: put a victim (plus a legacy-Direct value so the migration path runs too), delete the victim, churn overwrites until the plow laps past the victim's old slot, then assert every committed pointer still resolves — in-session get AND a cold reopen.

use manifestus::{Error, FileDev, Mirror, Vault, HOST_RING_LOG2};
use tempfile::TempDir;

const RING: u64 = 1 << HOST_RING_LOG2;
const TRACT: u64 = 128;

fn key(name: &[u8]) -> [u8; 32] {
    *blake3::hash(name).as_bytes()
}

#[test]
fn deleted_key_pointer_survives_slot_reuse() {
    let dir = TempDir::new().unwrap();
    let pa = dir.path().join("a.vsf");
    let pb = dir.path().join("b.vsf");
    let victim = key(b"victim");
    let churn = key(b"churn");
    let legacy = key(b"legacy");

    {
        let a = FileDev::create(&pa, RING + TRACT).unwrap();
        let b = FileDev::create(&pb, RING + TRACT).unwrap();
        let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 0).unwrap();

        // The victim leaf lands at a low tract lba; a legacy-format value exercises the mid-sweep Direct→extent migration alongside.
        v.put(&victim, &[0xAAu8; 700], 1).unwrap();
        v.put_legacy_direct_for_tests(&legacy, &[0xBBu8; 9000], 2).unwrap();

        // Fast delete: zeroes the leaf. The committed index pointer for `victim` must NOT outlive this in a form that can dangle.
        assert!(v.delete(&victim, 3).unwrap());

        // Churn until the plow laps well past the victim's old slot, so the reap retires the zeroed slot and an append reuses it.
        let start = v.tract_blocks_plowed();
        let mut now = 4i64;
        let mut i = 0u64;
        while v.tract_blocks_plowed() < start + 2 * TRACT {
            let val = vec![(i % 251) as u8; 600 + (i % 5) as usize * 100];
            v.put(&churn, &val, now).unwrap();
            now += 1;
            i += 1;
        }

        // In-session: the deleted key must read as absent — never as corruption.
        match v.get(&victim) {
            Ok(None) => {}
            Ok(Some(_)) => panic!("deleted key resurrected"),
            Err(Error::Seal) => panic!("BUG: tombstone pointer dangles into a reused slot (in-session get => Seal)"),
            Err(e) => panic!("unexpected error on deleted-key get: {e}"),
        }

        // The surviving keys must still read.
        assert!(v.get(&churn).unwrap().is_some());
        assert_eq!(v.get(&legacy).unwrap(), Some(vec![0xBBu8; 9000]));
    }

    // Cold reopen: every committed pointer must resolve + seal. This is where the real vault died (walk_live at resume).
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = match Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 100_000) {
        Ok(v) => v,
        Err(e) => panic!("BUG: reopen after delete + lap failed ({e}) — the committed index holds a dangling tombstone pointer"),
    };
    assert_eq!(v.get(&victim).unwrap(), None);
    assert!(v.get(&churn).unwrap().is_some());
    assert_eq!(v.get(&legacy).unwrap(), Some(vec![0xBBu8; 9000]));
}
