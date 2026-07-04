![manifestus](manifestus.webp)

# manifestus

**Struck by the hand.** An unverified byte is not a written byte. Nothing exists until contact with the medium is confirmed.

The vault answers one question per key. Hold it, the object answers. Don't hold it, the object doesn't exist — not "permission denied," which would at least confirm something's there. Silence. The 2²⁵⁶ keyspace makes guessing equivalent to not trying. Internally it's a 32-way hash-mapped trie (HAMT, copy-on-write) built from VSF-sealed blocks on a log-structured ring, with the index living in the tract it indexes. Three operations: `put`, `get`, `delete`.

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
│  Tract         two-cursor log ring: blind appends at the    │
│                plow, windowed cleaning at the reap,         │
│                rollback fence, zero-delete                  │
├─────────────────────────────────────────────────────────────┤
│  Ring (spine)  generation-numbered commit objects,          │
│                hash-chained, binary-searched head;          │
│                optionally MIGRATING thru a residence band   │
│                behind a 4-slot root ring (raw-flash wear)   │
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
- The rollback fence keeps the last K=4 generations fully restorable with one integer compare: appends stay below min(reap_i + len_i) over the window — inside space that was already clean (live-free) at every windowed generation, which therefore contains nothing any of them references. Reap copies land *before* the commit that retires their window; the originals stay sealed in place until that commit is K generations deep.
- The fence cannot deadlock a tight tract, even tho flushing the index needs tract appends, appends can be fenced, and raising the fence needs new generations. Heartbeat generations break the cycle: a commit re-asserting the head verbatim (root, reap, geometry — never in-flight cursors, which would raise the fence past what the committed root survives), written into the ring region the fence never covers, sliding old entries out of the K-window.
- A torn or scribbled block reads as Corrupt, and the head search bisects around it, branching both halves — an ambiguous read prunes nothing. Rank a corrupt slot as "oldest" instead and a single bad block deflects a naive bisect to a stale generation; the counter-example is a pinned test.

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

## The commit object

A generation is one 4KB spine entry — a complete commit object, sealed like every other block:

```
gen      full-EWE generation counter — no ceiling
prev     hp of the parent entry's body — the hash chain
ring     ring exponent r (N = 1 << r)
tract    tract length in blocks — arbitrary, full EWE
hamt     BLAKE3 Merkle root of the entire vault state
hamtat   tract-relative lba of that root
plow     append head, as a monotone total of blocks since genesis
reap     cleaning head, same monotone domain — the fence input
live     live tract block count — feeds the reap trigger
time     caller clock (eagle oscillations); the engine never interprets it
```

About 160 bytes of the 4096 are used; the rest is zero padding, and the seal covers the padding — a tampered tail reads Corrupt.

- **The exponent rule.** Quantities that are power-of-two by law are stored as their log2, so an invalid ring size is *unrepresentable*, not merely rejected. The tract length is deliberately full-EWE arbitrary — the kernel tract is "whatever remains of the device," which is never a power of two.
- **Both cursors are monotone totals.** Wrapped positions are lap-ambiguous; totals are not. Positions and lap counts are derived (`cursor % len`, `cursor / len`), and the rollback fence becomes a pure integer compare. A legacy entry without a reap field contributes zero append budget and ages out over K generations — old vaults migrate themselves thru ordinary cleaning, no format break.
- **Tract-relative addressing.** Every lba in entries and index nodes is 0-based within the tract: a pointer into the ring region is unrepresentable, and the same bytes are valid wherever the tract physically sits — host file today, raw partition on ferros.
- **No genesis entry, no privileged slot.** An all-Empty ring *is* the pre-genesis state; generation 0 lands at slot 0 and the first lap fills the ring in order. Empty is a verification state, not a number — None sorts below Some(0), and every value on the number line is legal.
- **Unknown fields are parsed and skipped.** The kernel profile appends its own fields (ledger head, kernel hash, signature) to the same wire format and host readers ride thru them. One format, both worlds.

## Threat model, stated plainly

manifestus stores only ciphertext and hashes — it never sees plaintext.
Encryption is the layer above; the engine guarantees structure: never a block without a seal, never an unverified byte.
Open source means no security-thru-obscurity — the attacker knows every derivation step, so security rests entirely on which *inputs* are secret.

- **Leaked vault files (backup, cloud sync): safe.** The files hold ciphertext, and the key-derivation inputs live outside the vault directory — a copy of the files cannot derive its own key.
- **Another local user: safe.** Vault files are created mode 0600 — the one defense crypto cannot provide, since machine identity is shared across UIDs.
- **Other apps on a sandboxed OS (Android): strong-ish.** App-private storage plus per-signing-key identity: a malicious app is signed by a different key, derives different secrets, and cannot reach the files anyway. The "ish": ANDROID_ID's keyspace is tiny, so the strength is the sandbox, not the entropy — the platform secret gates access, it does not survive an attacker who already holds the files *and* the device identity.
- **A full-disk image with a known handle: broken — use FDE.** Machine identity travels with the image, so the derivation inputs do too. Full-disk encryption is the answer there, not this layer.
- **Same-user malware on the desktop: not defended, and no file-based scheme can.** A process with your UID has your files, your machine identity, and your public handle — it can recompute every key you can. That is the Unix permission model, not an engine flaw; sandboxed packaging is the real fix on desktops.

The endgame for that last hole is hardware: a write-once key in a physically isolated enclave (PIPE — the ferros hardware anchor) makes the derivation input something no process can read at any privilege.
Until then the honest posture is the one every desktop user already lives, acknowledged or not: trust your software and your device.
People install and run literally everything with sudo all day, and that trust — not the permission bits — is the actual security boundary.
Photon, for the record, never asks for it: the whole stack runs unprivileged.

## Wear is arithmetic, GC is a side effect

There is no wear-leveling subsystem and no garbage collector, in the same way there is no recovery mode: the jobs are done by the shape of the thing.

- The spine rotates by `generation & (N−1)` — every slot written exactly once per N commits, uniformity as a mathematical property, no counter block to hot-spot, no mechanism by which wear *could* concentrate. On raw (FTL-less) flash even the spine's REGION moves: a 4-slot root ring records its residence, the spine hops after a fixed number of rotations, and each indirection level multiplies endurance by slots × P/E (RING.md "Migrating Rings"). Existing fixed-ring vaults are the degenerate case and stay valid.
- The tract has exactly one write mechanism: blind appends at the plow into clean space (live-free by invariant) — no read-before, no classification, no relocation on the write path, and every multi-block value lands as one contiguous run. Sequential, log-structured, exactly what flash wants (TRIM hooks fire on wrap in the kernel profile).
- Dead space is reclaimed by the REAP: a second cursor trailing the plow by at most a lap, retiring occupied space in bounded windows. Survivors re-append at the plow (source and target can never overlap — the target is clean, so redundancy never blinks), garbage is left behind, and the retiring commit advances the reap. Windows run under space pressure and proactively past 25% dead — incremental and capped, never saved up, nothing ever stops the world.
- The reap repairs its own index in the same pass: survivors self-address (leaves carry their key, furrows their owner and index, index nodes their depth and route), so each names its repair path — extent lists rebuilt, nodes and leaves re-anchored thru the COW machinery. No reverse-pointer maps, nothing to lose in a crash.
- Wear leveling still falls out free, now with teeth: the reap forcibly migrates even never-rewritten cold data once per lap, so no position can sit out the rotation.

## Unlimited

Every quantity on disk is EWE-encoded (vsf's exponential width encoding): integers that grow with reality and never hit a ceiling.

- The generation counter never wraps, never saturates, never needs a migration. Generation 10¹⁸ encodes in a few more bytes than generation 10.
- Full generations are also what make two mirrors comparable after unbounded divergence: a restored backup or a stale SD card is internally perfect on both sides, and only an unbounded counter can say which one is newer.
- Tract length is arbitrary — grow the device, fallocate, commit the new geometry in the next spine entry; growth is a transaction with the same killswitch semantics as every other write.
- The plow position is a monotone total that counts forever; its wrapped position and lap count are derived, not stored.
- No field anywhere in the format has a "we'll widen it later." There is no year-ten 2³² surprise because there is no 2³² anything.

Values are unlimited too: an extent leaf records (start, count) runs, not per-block pointers, so one 4KB leaf declares a value of any size — fresh writes are one run (two at a ring wrap), and only reap-window boundaries add fragments, which consecutive windows re-coalesce.

## The write path

`put` returns durable, every time, and the price is a handful of sequential 4KB writes:

1. The value lands first — one sealed leaf block for values up to ~3.9KB, or one contiguous run of furrow blocks plus an extent leaf above that.
2. The copy-on-write index path follows — typically 2–4 nodes for the touched path; untouched subtrees are shared, not copied.
3. One spine entry commits the generation.

Data is written **once**.
There is no journal, so there is no double-write tax and no replay on open.
Delete is O(1) plus furrow count: zero the blocks — flash erases to zero, so zero *is* the deleted state; the index pointer goes stale and the reap retires the slots.
Open finds the head in ~9 reads regardless of vault size: one bootstrap read plus a binary search over the 256-slot ring, with no dependence on the OS for so much as the file length.

## What isn't here

The design is what was removed:

- **No permissions.** The key is the capability; absence is the denial.
- **No superblock.** Geometry rides in every commit object.
- **No journal.** Data is written once, where it lives.
- **No allocator, no free list.** Appends land at the plow; the reap retires dead space behind it.
- **No tombstones.** Zero is the deleted state.
- **No reverse maps.** Blocks self-address.
- **No wear-leveling subsystem.** Rotation is arithmetic.
- **No garbage collector.** Advancing is collecting.
- **No recovery mode.** Opening is recovering.
- **No ownership.** The vault has no provenance metadata. Blocks belonging to an uninstalled app are indistinguishable from live blocks — the plow will not reclaim them. The layer above must maintain a bundle: a VSF object keyed to the app's ihi, recording every key written, consumed as the uninstall manifest.

Two runtime dependencies (blake3 and vsf), ~2,400 lines of engine, and every structural decision falls out of one rule: a block is sealed, empty, or corrupt, and nothing else is believed.

## Quick start

```rust
use manifestus::{FileDev, Mirror, Vault, HOST_RING_LOG2};

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
- **Recovery ladder is v0-shallow.** A spine-destroyed vault with sealed tract data is detected and protected, but the full tract-scan rebuild is specified, not yet implemented.
- **Kernel profile is the destination, not the claim.** no_std core and HAL backends land with the ferros integration phase.
- **Petabyte tracts are a format reality, not yet an implementation one.** The on-disk format has no size ceiling anywhere (EWE integers, constant-fragment extent leaves, size-independent spine), but the host implementation keeps a RAM live-map (one entry per live block) and rebuilds it with a full index walk at open. Both are caches — blocks self-address, so liveness is answerable from the index itself — and both retire with the kernel-profile port. Tracked in `src/vault.rs` (`TODO(scale)`).
- **Migrating-ring endgame is spec'd, not built.** v1 uses a dedicated residence band; the tract-pooled variant (residences carved from clean tract space — one wear pool, the whole device) is deliberately deferred to the raw-NAND target. See RING.md "Migrating Rings".
- **Bundle maintenance is required for clean uninstall.** manifestus cannot enumerate blocks by provenance. Without a bundle, uninstalled app data persists in the HAMT until explicitly deleted. This is a ferros integration concern, not an engine concern — but ignoring it leaks storage permanently.

## Specs

The design contract is the ferros specification set — `RING.md`, `VAULT.md`, `HAMT.md`, `VAULT_ROOT.md` — with the host-profile resolutions recorded in this README.
Deviations from spec (uniform body-hash sealing, monotone cursors, heartbeat generations, extent leaves in place of HAMT.md's chained mode) are flagged in the module docs where they occur.

## Status

Engine complete and kill-tested on the host profile: 62 tests across nine suites, including four kill -9 harnesses (block, ring, vault, and mid-migration), a multi-lap large-value migration test, and a legacy-format self-migration test.
Photon's `FlatStorage` rides it as the first consumer; battle-soak in real use precedes any crates.io publish.

## Terminology

manifestus stores bytes and asks no names, but the layer above keys its bundle on the app's ***ihi*** — the provable identity (handle-layer: `handle_proof`) under which an app's written keys are recorded for the uninstall manifest (see "No ownership", above). The shared identity vocabulary (*ihi*, *ira*, *wairua*, *whakaira*, the chip states) is defined in the cross-stack glossary: `GLOSSARY.md` in the ferros repo.

---

## License

MIT OR Apache-2.0, at your option.