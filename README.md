# custodes

**The guards.** Every block guards itself; the guards verify each other. *Quis custodiet ipsos custodes?* **Each other.**

The ferros storage engine: a crash-proof keyed object store over mirrored 4KB block devices.
Built host-first — applications back it with plain files (Photon rides it today), and the same engine code is designed to sit directly on UFS/SD HAL devices inside the ferros kernel.
There is no other I/O surface: the engine sees `read(lba)`, `write(lba)`, `flush()`, and nothing else.

Three traditions that never shared a layer, fused into one: capability-model access semantics, log-structured flash physics, and archival self-verification.
Security people built capabilities above storage and ignored the medium; filesystem people did wear and GC but trusted their own metadata; archival people hashed everything but assumed clean shutdowns.
This engine has no someone-else's-layer to defer to, so it does all three jobs with the same handful of invariants.

```
┌─────────────────────────────────────────────────────────────┐
│  Vault         keyed object store: put / get / delete       │
│                commit-per-write, durable on return          │
├─────────────────────────────────────────────────────────────┤
│  HAMT          COW 32-way trie — the index lives in the     │
│                tract it indexes and is plowed like          │
│                everything else                              │
├─────────────────────────────────────────────────────────────┤
│  Tract         plow-managed log ring: compaction, spin GC,  │
│                rollback fence, zero-delete                  │
├─────────────────────────────────────────────────────────────┤
│  Ring (spine)  generation-numbered commit objects,          │
│                hash-chained, binary-searched head           │
├─────────────────────────────────────────────────────────────┤
│  Mirror        write → verify → THEN the second device      │
│  BlockDev      4KB blocks; FileDev (host) / HAL (kernel)    │
└─────────────────────────────────────────────────────────────┘
```

## No permissions

There are no permission bits, no ACLs, no owners, and no path hierarchy — because there is nothing for them to protect that the address space doesn't already protect better.

- **The key IS the access.** Objects live at 32-byte addresses in a 2²⁵⁶ space. Hold the key and the object answers; don't, and it *does not exist* — not "permission denied," which confirms existence and invites escalation, but silence indistinguishable from absence.
- **Keys are derived, never stored.** Capability systems historically hit the rootcap problem — the capability strings themselves need a safe place to live. Here they don't live anywhere: keys fall out of `derive_key` over identity material the caller already holds. Nothing to steal at rest, nothing to lose, nothing to back up.
- **Non-enumerability is structural, not policy.** The index answers exactly one question — *what bytes live under this key* — and supports no iteration, no ranges, no list operation. On disk, leaves store key hashes and ciphertext. Even an attacker holding the raw device can confirm a guessed key at best; enumerating what's there is not an operation that exists.

Permissions were scaffolding for humans browsing shared timesharing machines.
The consumers here are programs holding secrets; kill the browsing and the entire apparatus is dead weight.

## Built for the killswitch (and the cosmic ray)

ferros has a hardware killswitch: flip that switch and power is instantly cut to ALL circuits, with ZERO notice to software.
There is no concept of shutdown, no such thing as unmount, there is no journal, no fsck, and no separate recovery because the recovery path *is* the open path, exercised on every start:

- Power loss at any byte boundary is **normal operation**, not an exceptional event with its own code.
- A spine entry is the transaction commit point; everything between commits is provisional, and orphans classify dead on the next plow pass.
- The committed generation defines *exactly* what exists: kill -9 mid-write, reopen, and puts `0..G` are intact while put `G` is fully absent — never partial. This is a test, not a slogan.
- The rollback fence keeps the last K=4 generations fully restorable: no block any of them references — old location or new — can be physically overwritten until the orphaning commit is K generations deep. Relocation copies land *before* the commit that references them; the originals stay sealed in place behind the fence.
- A torn or scribbled block reads as Corrupt, and the head search bisects around it, branching both halves — an ambiguous read prunes nothing.

A 15ms power cut, a cosmic-ray bit flip, and a tampered byte all produce the identical symptom — a block whose seal fails — and receive the identical treatment: classify Corrupt, route around it, read the mirror's copy, heal on resync.
The engine never needs to know which one happened, so there is one defense instead of three.
(The residual risk is the same bit flipping in the same block on both mirrors; the hash chain still *detects* that loudly, which is all physics permits anyone.)

On the host, `kill -9` is the same event, and the test suite treats it that way: three kill-harnesses (block, ring, and vault layers) SIGKILL a child mid-write loop and assert the survivor's exact committed state.

## Security posture

One verification rule covers the entire engine.
Every 4KB block is a sealed VSF document — `RÅ< hp{BLAKE3(body)} >` — or it is Empty (zeroed) or Corrupt.
The same seal check classifies spine entries, index nodes, leaves, and furrows; there is no second format to audit.

- **The spine is a hash chain.** Every generation carries its parent's hash and the BLAKE3 Merkle root of the entire vault state. Verifying the head entry authenticates everything beneath it.
- **A block cannot lie about its generation.** Generation g lives only at slot `g mod N`, so the expected residue is known before a read is trusted; a sealed-but-misplaced entry classifies Corrupt.
- **The OS is a witness, never the authority.** There is no superblock to forge and no file metadata to trust: geometry (ring exponent, tract length, write head) rides inside every spine entry, and a truncated device is detected against the *committed* geometry, not the other way around.
- **An unverified byte is not a written byte.** Every write is flushed, read back thru the page-cache bypass (O_DIRECT on Linux/Android, F_NOCACHE on macOS), and byte-compared before it counts — verification that reaches media, not verification theater against RAM. The second mirror is not touched until the first verifies.
- **A valid block is its own proof.** Trash-vs-real is decided by scanning the whole device for any sealed block (false-positive rate 2⁻²⁵⁶). A vault whose spine was destroyed but whose tract holds sealed data is detected and refused — the engine never formats over something real.
- **Mirror resync is never a file copy.** `verified_replicate` picks the winner by highest valid generation, then converges the loser block-by-block: hash-compare-skip, write-verified, idempotent, I/O proportional to what actually diverged.

The seal is integrity, not confidentiality — encryption belongs to the layer above (Photon wraps values before they arrive).

## Wear is arithmetic, GC is a side effect

There is no wear-leveling subsystem and no garbage collector, in the same way there is no recovery mode: the jobs are done by the shape of the thing.

- The spine rotates by `generation & (N−1)` — every slot written exactly once per N commits, uniformity as a mathematical property, no counter block to hot-spot, no mechanism by which wear *could* concentrate.
- The tract has exactly one write mechanism: a single head advancing thru it, visiting every block once per lap. Sequential, log-structured, exactly what flash wants (TRIM hooks fire on wrap in the kernel profile).
- Dead space is reclaimed by the head trampling it on arrival — GC is what advancing *is*. When dead space passes 25% of the tract, the plow takes a proactive lap in bounded windows (64 blocks per commit), so amplification is incremental and capped, never saved up, and nothing ever stops the world.
- Compaction repairs its own index: relocated blocks self-address (leaves carry their key, furrows their owner, index nodes their depth and route), so a moved block read back at its new home names its own repair path. No reverse-pointer maps, nothing to lose in a crash.

## Unlimited

Every quantity on disk is EWE-encoded (vsf's exponential width encoding): integers that grow with reality and never hit a ceiling.

- The generation counter never wraps, never saturates, never needs a migration. Generation 10¹⁸ encodes in a few more bytes than generation 10.
- Tract length is arbitrary — grow the device, fallocate, commit the new geometry in the next spine entry; growth is a transaction with the same killswitch semantics as every other write.
- The plow position is a monotone total that counts forever; its wrapped position and lap count are derived, not stored.
- No field anywhere in the format has a "we'll widen it later." There is no year-ten 2³² surprise because there is no 2³² anything.

One v0 implementation asterisk: a single *value* currently tops out near 4MB (one direct leaf indexes ~1000 furrows).
The chained-leaf format that removes the cap is specified in HAMT.md and not yet built — the format is unlimited; the implementation has one TODO.

## The write path

`put` returns durable, every time, and the price is a handful of sequential 4KB writes:

1. The value lands first — one sealed leaf block for values up to ~3.9KB, or furrow blocks plus a leaf above that.
2. The copy-on-write index path follows — typically 2–4 nodes for the touched path; untouched subtrees are shared, not copied.
3. One spine entry commits the generation.

Data is written **once**.
There is no journal, so there is no double-write tax and no replay on open.
Delete is O(1): zero the block — flash erases to zero, so zero *is* the deleted state; the index pointer goes stale and the plow reaps the slot.
Open finds the head in ~9 reads regardless of vault size: one bootstrap read plus a binary search over the 256-slot ring, with no dependence on the OS for so much as the file length.

## What isn't here

The design is what was removed:

- **No permissions.** The key is the capability; absence is the denial.
- **No superblock.** Geometry rides in every commit object.
- **No journal.** Data is written once, where it lives.
- **No allocator, no free list.** The plow reclaims dead space by trampling it.
- **No tombstones.** Zero is the deleted state.
- **No reverse maps.** Blocks self-address.
- **No wear-leveling subsystem.** Rotation is arithmetic.
- **No garbage collector.** Advancing is collecting.
- **No recovery mode.** Opening is recovering.

Two runtime dependencies (blake3 and vsf), ~2,400 lines of engine, and every structural decision falls out of one rule: a block is sealed, empty, or corrupt, and nothing else is believed.

## Quick start

```rust
use custodes::{FileDev, Mirror, Vault, HOST_RING_LOG2};

let a = FileDev::create(path_a, 256 + 16384)?;   // 256-slot ring + 64MB tract
let b = FileDev::create(path_b, 256 + 16384)?;
let mut vault = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, now)?;

vault.put(&key, b"value", now)?;                  // durable on return
let v = vault.get(&key)?;
vault.delete(&key, now)?;                         // durable on return
```

Keys are 32-byte hashes — deriving them is your job (`blake3::derive_key` over your logical key, or a passless-derived key).
Values up to ~3.9KB live inline in a single leaf; larger values shard into furrows transparently.
A vault opens from whatever it finds: an existing spine resumes at its committed head, a genuinely empty device gets genesis, and anything in between is refused, loudly.

## Boundaries

Know what you're holding:

- **Version 0.0.0.** The API will move. The on-disk format is governed by per-entry schema ids and can evolve at generation boundaries, but don't mistake either for stable.
- **Unix only, for now.** `FileDev` is `cfg(unix)`; Windows needs a FILE_FLAG_NO_BUFFERING backend that doesn't exist yet. The engine itself only needs a `BlockDev` — bring your own anywhere else.
- **One process, one writer.** No file locking, no concurrent access; the application layer serializes (Photon uses a mutex).
- **Point lookups only.** No ranges, no iteration, no queries — deliberately. The vault answers one question: what bytes live under this key.
- **Single values cap at ~4MB** until chained leaves land (specified, not built).
- **Recovery ladder is v0-shallow.** A spine-destroyed vault with sealed tract data is detected and protected, but the full tract-scan rebuild is specified, not yet implemented.
- **Kernel profile is the destination, not the claim.** no_std core and HAL backends land with the ferros integration phase.

## Specs

The design contract is the ferros specification set — `RING.md`, `VAULT.md`, `HAMT.md`, `VAULT_ROOT.md` — with host-profile resolutions recorded alongside the engine.
Deviations from spec (uniform body-hash sealing, the monotone plow, heartbeat generations) are flagged in the module docs where they occur.

## Status

Engine complete and kill-tested on the host profile: 51 tests across five suites, including the three kill -9 harnesses.
Photon's `FlatStorage` rides it as the first consumer; battle-soak in real use precedes any crates.io publish.

## License

MIT OR Apache-2.0, at your option.
