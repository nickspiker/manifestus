# CUSTODES — ferros Storage Engine, Host Profile (PROPOSAL)
**Version:** draft 1
**Author:** Claude, for Nick Spiker's review
**Principle:** One engine. Two worlds. The kernel and the apps read the same blocks.
**Name:** custodes — "the guards." Every block guards itself; the guards verify each other. Quis custodiet ipsos custodes? They do.

---

## Positioning

One standalone crate, sibling to vsf/ihi/spirix/toka. Not inside the
ferros workspace, not inside photon. Everyone depends on it:

```
                ┌─────────────┐
                │  custodes   │   no_std + alloc core
                │  ring/tract │   vsf (default-features = false) for
                │   /hamt     │   EWE + types + BLAKE3 framing
                └──────┬──────┘
         ┌─────────────┼─────────────────┐
   host-file feature   │           ferros_hal backend (later)
   (std, two mirrored  │           UFS + SD at fixed block offsets
    preallocated files)│           same core, zero changes
         │             │                 │
      photon         lumis            ferros kernel
      (AEAD above)   (AEAD above)     (caps + crypto above)
```

The core is generic over a block device. Specs RING.md / VAULT.md /
HAMT.md / VAULT_ROOT.md are the contract; this document only adds the
host profile and resolves implementation questions those specs left open.

This crate succeeds `ferros_vault` — the kernel workspace swaps its
skeleton for this dependency when the kernel storage work lands.

```rust
/// 4KB blocks. The only I/O surface the engine sees.
pub trait BlockDev {
    fn block_count(&self) -> u64;
    fn read(&mut self, lba: u64, buf: &mut [u8; 4096]) -> Result<()>;
    fn write(&mut self, lba: u64, buf: &[u8; 4096]) -> Result<()>;
    fn discard(&mut self, lba: u64, count: u64) -> Result<()>;  // no-op on host
    fn flush(&mut self) -> Result<()>;
}
```

Mirroring is a wrapper, not a backend concern: `Mirror<A: BlockDev,
B: BlockDev>` implements write-verify-then-mirror per RING.md verbatim
(write A → read back → BLAKE3 verify → write B → read back → verify).
Host instantiates `Mirror<FileDev, FileDev>`; kernel instantiates
`Mirror<UfsDev, SdDev>`. Same protocol, same code, same theorems.

**File discipline (host):** mirror files are created at format time and
written only through the per-block write-verify path. No filesystem-level
copies, ever — a byte that hasn't been read back and BLAKE3-verified does
not count as written. (See Verified Replication below: resync, fresh-mirror
rebuild, and resize are all the same primitive, and none of them is a copy.)

---

## Host Profile

```
Two files per vault (paths from passless-key, as today):
  <config_dir>/Photon/<derived>.vsf       mirror A
  <data_dir>/Photon/<derived>.vsf         mirror B

Inside each file, block-addressed geometry (4KB blocks). NO SUPERBLOCK —
geometry is constant, exactly like the kernel layout ("hardcoded
power-of-two-aligned geometry from byte zero", RING.md):

Block range        Size      Purpose
──────────────────────────────────────────────
0 .. 255           1MB       Spine ring (N = 256, matches kernel STEM)
256 .. end         64MB+     Tract (plow-managed), disjoint from ring,
                             lbas tract-relative; default 16384 blocks,
                             grows by fallocate + commit

Every former superblock job lives in the spine entries themselves —
each entry is a complete commit object carrying its own geometry
(see Spine Entry Format below):
  spine N           ring(u{r}) field, N = 1<<r — bootstrap reads slot 0
  tract capacity    tract(u{t}) field, blocks = 1<<t — committed
                    geometry, never trusted from the OS (on ferros we
                    ARE the OS); fs length is a sanity witness only
  format version    per-entry schema id (d("custodes.spine")) — dialect
                    bumps can land at a generation boundary instead of
                    demanding a fresh file
  truncation guard  fs_len ≥ (1<<r) + (1<<t) blocks at open, else loud
  identity          every block is RÅ-or-Empty, as everywhere else

No custom magic anywhere: every block is a VSF document and RÅ is the
magic. One identity system, one liveness scan, one deletion rule (zero
the magic). All blocks use the vsf-mini profile per RING.md/VAULT.md
(RÅ<hp ...> + EWE fields, no z/y/b/l).

Genesis rule (Nick's ruling): the passless-derived filename IS the
ownership proof — a 43-char blake3 name in our app dir is
definitionally ours, so there is no foreign file to protect. The
trash-vs-real determination scans THE WHOLE FILE — every 4KB-aligned
block, both mirrors — because a valid block is its own proof: an
hp-sealed RÅ document arising in garbage is a 2^-256 event. No
geometry knowledge needed to know whether anything real is present;
geometry comes FROM whatever valid entries the scan finds (ring field
of any spine entry; the largest power of two ≤ file blocks brackets
the ring search if slot-0 bootstrap found nothing). Decided at MIRROR
scope:
  any valid block, either side,   → real vault: open/replicate/recover
  anywhere in the file               (spine entries, HAMT nodes,
                                     furrows all count), NEVER format
  zero valid blocks, both files,  → trash or fresh: zero the ring
  exhaustively                       region (Corrupt → Empty, so head
                                     searches never pay branch-on-
                                     corrupt tax for stale wreckage),
                                     then genesis
Cost: ~17k BLAKE3 reads for a 65MB vault, tens of ms, paid only on
the path that ends in "this file contains nothing" — approximately
once per vault per lifetime.
Recovery-ladder hook (later, same decision point): valid tract blocks
under a dead spine are recoverable via VAULT.md full recovery (linear
tract scan, rebuild HAMT from hp-valid blocks); v0 logs what it found
and refuses format whenever anything valid exists.

No seed/stem/state/ledger regions — host vaults are vaults, not boot
devices. No privileged block of any kind: ring slots 0..255, then
tract, uniform rules everywhere.
```

---

## Spine Entry Format

Each spine entry is a complete commit object — parent pointer, content
root, geometry, metadata, sealed:

```
RÅ<hp{entry_hash}>                  SELF hash: BLAKE3 of body, padding
                                    included — sealed before trusted
  [d("custodes.spine")]             dialect; a wire break publishes a
                                    new schema name
  [gen(u{generation})]              full EWE, arbitrary, no ceiling
  [prev_hash(hp{hash})]             chain; genesis = hp([0u8;32])
  [ring(u{r})]                      N = 1<<r        r=8 host & kernel STEM
  [tract(u{blocks})]                tract length in blocks — full EWE,
                                    ARBITRARY (kernel tract = "rest of
                                    device", never a power of two)
  [hamt_root(h{hash} u{lba})]       CONTENT hash: Merkle root of the
                                    entire vault state + its location.
                                    lba is TRACT-RELATIVE
  [plow(u{lba})]                    tract write head, TRACT-RELATIVE;
                                    wraps at tract length (one compare
                                    per rotation — masks not needed here)
  [live(u{blocks})]                 live tract blocks — every COW edit
                                    knows its delta, so the counter is
                                    free; feeds the spin trigger
  [eagle_time(e{t})]                caller clock

~160 bytes of 4096. Kernel profile appends ledger_head / kernel_hash /
kernel_sig to the same format — EWE named fields, readers skip unknown
fields, one format both worlds.
```

**Exponent rule**: quantities that are power-of-two BY LAW are stored
as their log2 in a tiny EWE uint — u3{8} not u4{256}, 2 bytes flat
forever, invalid values UNREPRESENTABLE. Same trick EWE itself plays
one level down (its size characters are log2 of bit-widths). The ring
is the only such quantity: N's power-of-two-ness is load-bearing
(bisect + g & (N-1) placement on every access). The tract length is
ARBITRARY — the kernel tract is "whatever remains of the device"
(~230GB, never a power of two), and the plow wraps once per rotation
(a compare, not a hot mask). Generation, lbas, counts: full EWE.

**Tract-relative addressing**: every lba in spine entries, HAMT nodes,
and extent lists is 0-based WITHIN the tract. A tract pointer that
addresses the ring region is unrepresentable, not merely invalid.
Device offset = tract_base + lba (tract_base = N on host, G#C0000 on
ferros) — so entry/node/extent bytes carry no absolute device offsets
and are identical wherever the tract physically sits.

**Bootstrap, OS-free** (9 reads to full knowledge):
```
1. Read slot 0 → Valid? ring exponent r + dialect from it.   (1 read)
   Corrupt? walk forward to first Valid. All Empty? pre-genesis →
   profile defaults, format (anti-clobber rule applies).
2. head_search over N = 1<<r                                  (8 reads)
3. Head entry → tract length, plow, hamt_root
4. Cross-checks: gen & (N-1) == slot; plow < tract_blocks;
   host-only: fs_len ≥ ((1<<r) + tract_blocks) × 4096 → else loud
   truncation error. The fs is a witness, never the authority.
```

**Spin (proactive compaction)**: dead = used − live, where used =
tract length after first wrap (else plow). When dead exceeds 25% of
the tract, spin: one full proactive plow rotation — relocate live
forward, trample dead — leaving live data compacted behind the plow
and free space as one contiguous run ahead. Spinning IS ordinary plow
operation: relocations batch into ordinary spine commits, so power
loss mid-spin keeps committed progress and needs no special recovery.
Trigger evaluated after each commit, never on shutdown. The 25% floor
bounds write amplification at ~3x worst case.

**Rollback fence (k = 4)**: a relocated or dead block's old location
may not be overwritten until the spine head is ≥ k generations past
the commit that orphaned it. In the single-plow model the consumed
region and the written region of a generation are the same blocks, so
the rule reduces to plow positions alone: head(G) may not advance past
head(G−k) + one full lap — a complete tract rotation requires ≥ k
spine commits. Enforcement state is already durable: the last k spine
entries record their plow positions and survive power loss by
construction; crash mid-spin → reopen → fence rebuilt from the ring
itself. Theorem: the last k generations are ALWAYS fully restorable —
every block any of them references, old and new locations alike, is
physically intact. Spin satisfies the fence naturally (one commit per
relocation batch); steady-state writes only feel it on a pathologically
full tract, where it forces interleaved commits — correct anyway.

**Growth is a transaction**: fallocate any increment, THEN commit a
spine entry carrying the new tract length. Power loss between the two
→ unclaimed zeroed space, committed geometry still old, nothing
dangles. Geometry changes inherit the same killswitch semantics as
every other write — which a write-once superblock could never offer.

Differences from kernel profile, exhaustively:
- Tract capacity from file size instead of partition offsets.
- Spine N=256 not 65536 (host vaults commit less; head search 8 reads).
  256 commit generations of rollback depth + wear rotation; long version
  history is the ledger's job, not the spine's. Matches the kernel STEM
  ring exactly (256 entries, 1MB) — same geometry, same code.
- Tract is small and resizable instead of ~230GB fixed.
- DISCARD is a no-op (filesystem's problem).
- No caps; no access() sections in v0 — photon's per-key AEAD wraps
  object content above the engine, exactly as flat.rs does today.
- No seed, no trust chain: the OS booted us; app identity is the TOKEN
  APK signature + passless derivation. Host spine entries omit the
  kernel_hash/kernel_sig fields entirely (EWE VSF docs — readers don't
  miss absent fields; kernel-profile entries carry them, host's don't).

---

## Alignment & Durability (host)

The file offset grid IS the block grid. `pwrite(buf, 4096, lba * 4096)`
covers whole filesystem blocks: ext4/f2fs/APFS default to 4KB blocks,
file offsets map to fs blocks at that granularity, and modern partition
tools align partitions to 1MB — so a 4KB-aligned file write reaches the
device as whole-sector writes. No translation math, same property the
kernel profile gets from raw LBAs.

```
Format time:   fallocate (Linux/Android) / F_PREALLOCATE (macOS)
               full geometry preallocated → ENOSPC fires at format,
               never mid-commit; allocation contiguous-ish
Open time:     st_blksize sanity check; warn if > 4096 (RMW perf,
               never correctness)
```

Page cache vs the verify discipline: a buffered read-back verifies RAM,
not media — verification theater. FileDev therefore opens:

```
Linux/Android:  O_DIRECT, 4096-aligned buffers (Layout align = 4096)
macOS:          F_NOCACHE via fcntl (no O_DIRECT on Darwin)
Fallback:       buffered + fdatasync, verify after sync — for
                filesystems without O_DIRECT (tmpfs in CI). Weaker;
                FileDev reports which mode it's in.
```

The engine does its own caching of hot blocks (spine head, HAMT path)
in RAM it controls — it does not borrow the page cache.

Durability per commit: fdatasync (Linux/Android); F_FULLFSYNC on macOS
(plain fsync does not flush the drive cache on Darwin).

Torn writes: 4KB atomicity is never assumed on any platform. A torn
block reads as Corrupt (BLAKE3 fails) and the killswitch theorems
handle it — identical posture to the kernel profile.

---

## Encryption & Threat Model (host)

custodes stores only ciphertext + BLAKE3 hashes — it never sees plaintext.
Encryption is photon's layer above (per-key ChaCha20-Poly1305; keys derived
from handle_seed + device_secret). custodes' two structural guarantees:
never a block without a hash, never a body photon didn't already encrypt.
So the real analysis is photon's key derivation, which custodes inherits.

Open source = no security-through-obscurity: the attacker knows every
derivation step. Security rests entirely on which INPUTS are secret.

Secret-input inventory (v0):
```
handle         NOT secret. It's the network identity — anyone can resolve
               "zeno" on the DHT. handle_seed is computable by anyone who
               knows who you are.
device_secret  Platform-dependent secrecy — this is the crux:
  Android      per-app-signing-key fingerprint. A malicious app is signed
               by a different key → different inputs AND can't read photon's
               app-private files anyway. Sandbox + per-signer scoping: strong.
  Linux/macOS  /etc/machine-id (world-readable) / IOPlatformUUID (readable).
               NOT secret against a same-user process.
```

The hard truth, stated plainly: **against a malicious process running as the
same desktop user, passless derivation provides no cryptographic defense.**
That process shares your UID, your file access, your machine-id, and — since
the handle is public — your handle_seed. It can recompute every key you can.
This is not a custodes flaw; it is the Unix permission model. A same-UID
attacker is you. No file-based or derivation-based secret can hide from a
process that has identical access to all its inputs.

What the encryption DOES defend, precisely:
```
Other local USER (different UID):   file mode 0600. (Crypto doesn't help —
                                    machine-id is shared across users; perms do.)
Leaked vault FILES (backup/cloud):  ciphertext only. machine-id lives in /etc,
                                    not in the vault dir — a vault-dir backup
                                    can't derive the key. SAFE.
Full-disk image, known handle:      machine-id travels with the image →
                                    device_secret derivable → BROKEN. FDE is
                                    the only answer here.
Other apps, sandboxed OS (Android): app-private storage + per-signer ANDROID_ID.
                                    STRONG.
Same-user malware, desktop:         NOT defended in v0. See below.
```

Future hardening (named, NOT v0 — platform/sandbox work, not engine work):
```
Sandbox:    Flatpak/Snap give desktop apps Android-like isolation. Photon in
            a sandbox → same-user malware can't reach the files at all. This
            is the realest desktop fix and it's an packaging decision.
Hardware:   TPM 2.0 (Linux/Win) / Secure Enclave (macOS) seal a non-exportable
            factor into device_secret, gated by the OS. A "key" — but
            hardware-bound, not stored-by-us: lost on hardware change, which
            matches the "new device = new identity" model. Fits the device-
            identity philosophy better than a keyring entry (which wipes).
FDE:        covers the full-disk-image case.
```

custodes' role: it is the ciphertext custodian. It guarantees structure
(hashes, kill-safety, mirroring) and stores what photon hands it. It cannot
improve photon's key secrecy — that's layer-above + platform-sandbox. Stating
this so "the vault is encrypted" is never mistaken for "safe from local
malware." In v0 scope and cheap: **vault files are created mode 0600** (real
defense against other local users; the one crypto-independent win available).

---

## Resolved Questions

### 1. Head search (VAULT_ROOT.md Q2) — RESOLVED, with corruption analysis

Generation g lives at slot g % N. The ring is a rotated ascending run;
empty slots sort below every valid generation (None < Some(0)) and so
sit exactly where old-lap entries would. Bisect against the range anchor:

```
head_search(lo=0, hi=N-1) → newest valid slot:
  while gen(lo) is Corrupt: lo += 1          ← restore the anchor
  while lo != hi:
      mid = (lo + hi + 1) / 2                ← ceil, bias right
      match gen(mid):
        Valid(g) | Empty:
          if g > gen(lo): lo = mid           ← ascent continues → head right
          else:           hi = mid - 1       ← over the seam → head left
        Corrupt:
          return max_by_gen(                 ← no pruning decision possible:
            head_search(lo, mid - 1),        ← search BOTH halves
            head_search(mid, hi))
  return lo
```

Block classification is three-way and load-bearing:

```
Valid(g):  VSF magic present, BLAKE3 passes → Some(g)
Empty:     zeroed / no magic → None (expected state: sparse ring,
           zero-delete; participates normally — None < Some(0))
Corrupt:   magic present, BLAKE3 fails → AMBIGUOUS. Never compared.
```

Why Corrupt ≠ Empty: ranking a corrupt block oldest lets one bad slot
deflect the search away from the true head. N=8, slot 4 corrupted:

```
slot:  0   1   2   3   4   5   6   7
gen:   8   9  10  11   ✗  13  14   7      true head: slot 6, gen 14
naive: mid=4 reads ✗→0 → prune right half → returns gen 11. WRONG.
```

Branching on ambiguity makes every pruning decision a valid comparison,
where the rotation invariant holds — the true maximum among valid slots
is always found. Cost: +log2(N) reads per corrupt block encountered;
the killswitch theorem bounds crash damage to one partial entry per
device, so realistic worst case = 2·log2(N) ≈ 20 reads at N=1024.

Final validation of the winner:
  1. Must be Valid.
  2. Congruence check: g % N == slot. The traversal knows the expected
     residue before trusting the claim — a misplaced generation cannot
     pass (VAULT_ROOT: "the block cannot lie about its generation").
  3. A winner that fails deeper validation falls back via prev_hash
     chain per RING.md.

Genesis — RESOLVED (Nick's ruling: math straight across, no offsets,
no reserved generation): format preallocates the whole ring region
(zeroed); there is no genesis entry and no privileged slot. An all-Empty
ring IS the pre-genesis state. First commit: generation 0 → slot 0; the
first lap fills 0, 1, 2, ... N-1 in order. prev_hash of generation 0 =
hp([0u8;32]). RING.md amended to match.

Empty is a verification state, not a generation number. No magic + no
valid hp → fails verification → sorts below every valid entry. In code:
Option ordering, None < Some(0). A zeroed block could claim any
generation — it wouldn't verify. The number line starts at 0 and every
value on it is legal.

Generations — RESOLVED (Nick's ruling: Option A, full EWE generation
per entry): within one ring, seam-finding needs only lap parity (two
laps coexist) — but cross-MIRROR ordering is unbounded (restored backup
file, reinserted stale SD: both sides internally perfect, verification
cannot detect staleness) and unbounded divergence cannot be ordered by
bounded bits. EWE is the minimal sufficient encoding: 2 bytes for the
first 65536 commits, grows only when reality does, never overflows a
4KB block. The position-derivable low bits make the congruence check
free: ring entries are the only parentless blocks (nothing points at
them), so g & (N-1) == slot is the only placement attestation they can
ever have — hp covers content, not placement.

What the straight math locks in (deliberately):
  slot = g & (N-1)    placement is an AND mask (N power of two, already
                      spec law); works on EWE arbitrary-width generations
                      by masking the low bits
  congruence check    g & (N-1) == slot is the can't-lie integrity
                      invariant — known before the block is trusted
                      (also kills the one collision-looking case: a
                      valid gen 0 can only live at slot 0)
  spine N immutable   for the life of the vault. Resize touches TRACT
                      capacity only; changing N would re-place every
                      generation for zero benefit at N=256. A different
                      spine size = a new vault (verified_replicate
                      migrates content if ever needed).

### 2. Mirror resync (VAULT_ROOT.md Q3) — RESOLVED per Nick's ruling

**Never a file copy.** Filesystem-level copies are unverified bytes and
amplify I/O by the full device size regardless of how little diverged.
Resync is verified replication of committed state, block by block:

```
verified_replicate(src, dst):                ← the ONE primitive
  spine:  for each slot with Valid entry on src:
            read src block → BLAKE3 verify
            read dst block → identical hash? skip (already converged)
            else write-verify block to dst
  tract:  walk src's committed HAMT (head spine entry → hamt_root):
            for each live node/object/furrow block:
              read src → verify → compare dst at same lba → skip or
              write-verify to dst
  plow:   dst plow position = src plow (recorded in spine head);
          dst file preallocated to src's size before replication

Properties:
  I/O proportional to LIVE + DIVERGED data, not device size.
  Dead tract blocks never replicated — the plow tramples them anyway.
  Every block lands through write-verify; an unverified byte is not
  a written byte.
  Idempotent: re-running converges to no-op (hash-compare skip).
```

Three situations, one primitive:

```
Catch-up      (gen_A ≠ gen_B):        verified_replicate(winner, loser)
Fresh mirror  (file missing/corrupt): preallocate empty file, then same
Grow tract    (the common resize):    fallocate any increment, commit
                                      entry with new tract length — no
                                      replication (Spine Entry Format)
Shrink tract  (rare):                 new smaller file,
                                      verified_replicate(old, new),
                                      atomic rename into place
```

Degraded flag for the session whenever replication was needed at open.
Both mirrors unreadable → error: vault unrecoverable on this device.

### 3. Sizing defaults (VAULT_ROOT.md Q1, host) — proposed, awaiting veto

```
Spine N:        256 slots (1MB)  → 8-read head search (matches kernel STEM)
Tract:          16384 blocks (64MB) initial
Batch commits:  commit-per-write default — FlatStorage::write() returns
                durable, matching photon's current contract. Explicit
                batch API (begin_batch/commit) for bulk ops; buffer cap
                64 dirty HAMT paths, no timers on host.
Resize:         explicit op via verified_replicate (above). Rare by design.
```

### 4. Object addressing from photon — proposed, awaiting veto

Photon logical keys (strings) → provenance hashes via the existing
derivation: `hp = blake3::derive_key("photon.storage.entry.v0", key)`.
Engine sees only hp + opaque ciphertext bodies. Delete = fast delete
(zero magic both mirrors, O(1)); HAMT cleanup rides the plow per spec.

---

## Build Order

```
1. block.rs + host FileDev + Mirror      write-verify-then-mirror, kill-tests
2. ring.rs                                head_search (as resolved above),
                                          append, prev_hash walk; spine =
                                          instance (match working
                                          ferros_hal::ring semantics)
3. tract.rs                               plow, furrows, relocation, zero-delete
4. hamt.rs                                HAMT.md verbatim: v_u0/v_h/v_u nodes,
                                          lone/direct/chained leaves, COW paths
5. replicate.rs                           verified_replicate (resync/rebuild/
                                          resize — one primitive)
6. vault.rs                               VAULT.md write path steps 1-9,
                                          lookup, recovery ladder
7. photon flat.rs reskin                  public API unchanged (third backend
                                          swap; callers never know)
```

Kill-testing is the suite's spine: every stage gets process-kill-at-
random-byte tests (fork, kill -9 mid-write, reopen, assert last commit).
The 26 Layer-0 tests carry over in spirit; the append-log store.rs and
PVDB record format are deleted — furrow/entry formats per spec replace
them. No custom magic (see Host Profile): RÅ is the only magic in the file.

passless-key is untouched. vsf gains nothing new (engine uses d/l/u/h/v/m
types + EWE — no x, so no text features in the engine's dep).

---

## What This Is Not (v0)

```
No access() sections          photon AEAD above; kernel crypto later
No caps                       kernel concern
No ledger/stem/state rings    boot-device concerns
No HAMT range queries         HAMT.md forbids; vault asks one question
No network/sync               device-sync phase, unchanged
No queries/joins/indexes      vsf-db Layers 2-4 remain future, above this
```

---

*CUSTODES draft 1 — One engine. Two worlds. The guards verify each other.*
