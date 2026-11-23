//! A vault on devices of a fixed size (ferros's vault process: a window of the partition) fills them and then says full (Error::TractFull), never Corrupt, and grows into the last blocks the devices hold rather than asking to double past them (ferros's Pro, 2026-11-23).

use manifestus::{Block, BlockDev, DeletePolicy, Error, Mirror, Vault, ZERO_BLOCK};

/// A RAM device of `max` blocks at most, holding `len` now; grown by zeroing, refused past `max`.
struct Fixed {
    blocks: Vec<Block>,
    max: u64,
}

impl BlockDev for Fixed {
    fn block_count(&self) -> u64 {
        self.blocks.len() as u64
    }
    fn max_blocks(&self) -> u64 {
        self.max
    }
    fn read(&mut self, lba: u64, buf: &mut Block) -> manifestus::Result<()> {
        *buf = *self.blocks.get(lba as usize).ok_or(Error::Bounds(lba))?;
        Ok(())
    }
    fn write(&mut self, lba: u64, buf: &Block) -> manifestus::Result<()> {
        *self.blocks.get_mut(lba as usize).ok_or(Error::Bounds(lba))? = *buf;
        Ok(())
    }
    fn flush(&mut self) -> manifestus::Result<()> {
        Ok(())
    }
    fn grow(&mut self, new_blocks: u64) -> manifestus::Result<()> {
        if new_blocks > self.max {
            return Err(Error::Corrupt(format!("past the device: {new_blocks} of {}", self.max)));
        }
        self.blocks.resize(new_blocks as usize, ZERO_BLOCK);
        Ok(())
    }
}

fn value(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u32).wrapping_mul(2654435761).wrapping_add(seed as u32).to_le_bytes()[1]).collect()
}

#[test]
fn a_full_vault_says_full() {
    // Room for a modest tract, not for doubling it twice.
    let max = 1u64 << 12;
    let dev = || Fixed { blocks: vec![ZERO_BLOCK; 1 << 11], max };
    let mut v = Vault::open(Mirror::new(dev(), dev()), 6, 1, DeletePolicy::UnlinkOnly).expect("vault");
    let mut kept = 0u32;
    let err = loop {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&kept.to_le_bytes());
        match v.put(&key, &value(48 << 10, kept as u8), 2) {
            Ok(()) => kept += 1,
            Err(e) => break e,
        }
        assert!(kept < 1 << 10, "a fixed device must fill");
    };
    assert!(matches!(err, Error::TractFull), "full, not {err:?}");
    // The tract took the devices' last blocks before saying so.
    assert!(v.tract_base() + v.tract_blocks() > max - (max >> 3), "tract {} from {} of {}", v.tract_blocks(), v.tract_base(), max);
    // What was kept still reads; deletes land in a full vault; with a third of it removed, there is room again.
    let key_of = |k: u32| {
        let mut key = [0u8; 32];
        key[..4].copy_from_slice(&k.to_le_bytes());
        key
    };
    assert_eq!(v.get(&key_of(0)).unwrap().unwrap(), value(48 << 10, 0));
    for k in (0..kept).filter(|k| k % 3 == 0) {
        let st = v.engine_stats();
        let r = v.delete(&key_of(k), 3);
        if r.is_err() {
            eprintln!("delete {k}: {r:?}; before it tract {} plow {} reap {} (clean {}) live {}", st.tract_blocks, st.plow, st.reap, st.tract_blocks - (st.plow - st.reap), v.live_blocks());
        }
        assert!(r.unwrap(), "delete {k} in a full vault");
    }
    let mut room = 0;
    for k in 0..32u32 {
        let mut fresh = [0xFFu8; 32];
        fresh[..4].copy_from_slice(&k.to_le_bytes());
        if v.put(&fresh, &value(48 << 10, 7), 4).is_ok() {
            room += 1;
        }
    }
    assert!(room > 0, "room again after removals");
    for k in (0..kept).filter(|k| k % 3 != 0).take(8) {
        assert_eq!(v.get(&key_of(k)).unwrap().unwrap(), value(48 << 10, k as u8), "kept {k} reads after");
    }
}
