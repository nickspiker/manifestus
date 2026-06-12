# custodes

**The guards.** Every block guards itself; the guards verify each other. *Quis custodiet ipsos custodes?* They do.

The ferros storage engine: a crash-proof keyed object store over mirrored 4KB block devices. One engine, two worlds — host applications (Photon, Lumis) back it with files; the ferros kernel backs it with UFS/SD. Same blocks, same code, same theorems.

```
┌─────────────────────────────────────────────────────────────┐
│  Vault         keyed object store: put / get / delete       │
│                commit-per-write, durable on return          │
├─────────────────────────────────────────────────────────────┤
│  HAMT          COW 32-way trie — the index indexes itself,  │
│                lives in the tract, plowed like everything   │
├─────────────────────────────────────────────────────────────┤
│  Tract         plow-managed log ring: compaction, spin GC,  │
│                rollback fence, zero-delete                  │
├─────────────────────────────────────────────────────────────┤
│  Ring (spine)  generation-numbered commit objects,          │
│                binary-searched head, hash-chained           │
├─────────────────────────────────────────────────────────────┤
│  Mirror        write → verify → THEN the second device      │
│  BlockDev      4KB blocks; FileDev (host) / HAL (kernel)    │
└─────────────────────────────────────────────────────────────┘
```

## The crash model

Power loss at any byte boundary is **normal operation**. There is no clean shutdown, no recovery mode, no journal replay:

- Every block is a sealed VSF document — `RÅ<hp{BLAKE3(body)}>` — or it is Empty (zeroed) or Corrupt. One verification rule everywhere.
- A spine entry is the transaction commit point. Everything between commits is provisional; orphans classify dead and the plow tramples them.
- The committed generation defines *exactly* what exists: kill -9 mid-write, reopen, and puts `0..G` are intact while put `G` is fully absent — never partial. This is a test, not a slogan.
- The rollback fence keeps the last K=4 generations *fully restorable*: no block any of them references — old or new locations — is overwritten until the orphaning commit is K deep.

## What makes it lean

- **No superblock.** Geometry rides in every spine entry (ring exponent, tract length, plow as a monotone total). Bootstrap reads slot 0, binary-searches the head, and knows everything in ~9 reads — without trusting the OS for so much as the file length.
- **No allocator, no free list, no tombstones.** The plow is the only write mechanism; dead space is reclaimed by trampling; deletion is zeroing (flash's natural state).
- **No reverse maps.** Blocks self-address: leaves carry their key, furrows their owner, index nodes their (depth, route). A relocated block read back at its new home names its own repair path.
- **No unverified bytes.** A write is not a write until it has been read back and compared. Mirror B is not touched until mirror A verifies. Replication is block-level, hash-compare-skip, idempotent — never a file copy.

## Quick start

```rust
use custodes::{FileDev, Mirror, Vault, HOST_RING_LOG2};

let a = FileDev::create(path_a, 256 + 16384)?;   // ring + 64MB tract
let b = FileDev::create(path_b, 256 + 16384)?;
let mut vault = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, now)?;

vault.put(&key, b"value", now)?;                  // durable on return
let v = vault.get(&key)?;
vault.delete(&key, now)?;
```

Keys are 32-byte hashes (derive via [passless-key](../passless-key) or BLAKE3 of your logical key). Values up to ~3.9KB inline (lone leaves); larger values shard into furrows transparently.

## Specs

The design contract lives in the ferros specification set — `RING.md`, `VAULT.md`, `HAMT.md`, `VAULT_ROOT.md` — with host-profile resolutions and every design ruling recorded in [CUSTODES.md](CUSTODES.md). The spec deviations (uniform body-hash sealing; monotone plow; heartbeat generations) are flagged where they occur.

## Status

Engine complete and kill-tested on the host profile: 77 tests including three kill -9 harnesses (block, ring, vault layers). Photon's `FlatStorage` is the first consumer. Kernel profile (UFS/SD HAL backend, no_std core) is the ferros integration phase.

## License

MIT OR Apache-2.0, at your option.
