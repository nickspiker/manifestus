//! The composition: genesis ladder, KV durability, cold resume, replication, spin, and the final-form kill -9 test — murder mid-commit, reopen, assert the committed prefix is exactly intact.

use manifestus::{verified_replicate, BlockDev, FileDev, Mirror, Vault, ZERO_BLOCK, HOST_RING_LOG2};
use tempfile::TempDir;

const RING: u64 = 1 << HOST_RING_LOG2;

fn key(i: u64) -> [u8; 32] {
    *blake3::hash(&i.to_le_bytes()).as_bytes()
}

fn val(i: u64) -> Vec<u8> {
    format!("value-{i}-{}", "x".repeat((i % 7) as usize * 100)).into_bytes()
}

fn paths(dir: &TempDir, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        dir.path().join(format!("{name}-a.vsf")),
        dir.path().join(format!("{name}-b.vsf")),
    )
}

fn open_vault(pa: &std::path::Path, pb: &std::path::Path, blocks: u64) -> Vault<FileDev, FileDev> {
    let a = FileDev::create(pa, blocks).unwrap();
    let b = FileDev::create(pb, blocks).unwrap();
    Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 1_000).unwrap()
}

#[test]
fn genesis_kv_and_resume() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "g");
    {
        let mut v = open_vault(&pa, &pb, RING + 128);
        assert_eq!(v.generation(), Some(0), "genesis is generation 0");
        v.put(&key(1), b"alpha", 1_001).unwrap();
        v.put(&key(2), b"beta", 1_002).unwrap();
        assert_eq!(v.generation(), Some(2), "commit-per-write");
        assert_eq!(v.get(&key(1)).unwrap(), Some(b"alpha".to_vec()));
        assert!(v.delete(&key(1), 1_003).unwrap());
        assert_eq!(v.get(&key(1)).unwrap(), None);
        assert!(!v.delete(&key(1), 1_004).unwrap(), "absent delete is a no-op, no commit");
        assert_eq!(v.generation(), Some(3));
    }
    // Cold resume: geometry/index/live from the head entry alone.
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 2_000).unwrap();
    assert_eq!(v.generation(), Some(3));
    assert_eq!(v.get(&key(2)).unwrap(), Some(b"beta".to_vec()));
    assert_eq!(v.get(&key(1)).unwrap(), None);
    assert!(v.live_blocks() > 0);
}

#[test]
fn open_ladder_genesis_over_trash_refuses_real() {
    let dir = TempDir::new().unwrap();

    // Pure trash everywhere: whole-file scan finds nothing sealed → zero ring → genesis.
    let (pa, pb) = paths(&dir, "trash");
    for p in [&pa, &pb] {
        let mut dev = FileDev::create(p, RING + 32).unwrap();
        let mut junk = ZERO_BLOCK;
        junk.fill(0x6B);
        for lba in 0..dev.block_count() {
            dev.write(lba, &junk).unwrap();
        }
        dev.flush().unwrap();
    }
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 1_000).unwrap();
    v.put(&key(9), b"reborn over trash", 1_001).unwrap();
    assert_eq!(v.get(&key(9)).unwrap(), Some(b"reborn over trash".to_vec()));
    drop(v);

    // One sealed block hiding in the tract area with an empty ring → REAL → refuse to format.
    let (pc, pd) = paths(&dir, "real");
    {
        let mut dev = FileDev::create(&pc, RING + 32).unwrap();
        // Steal a sealed block from the trash-vault we just built.
        let mut donor = FileDev::open(&pa).unwrap();
        let mut buf = ZERO_BLOCK;
        let mut found = None;
        for lba in RING..donor.block_count() {
            donor.read(lba, &mut buf).unwrap();
            if manifestus::sealed_hp(&buf).is_some() {
                found = Some(buf);
                break;
            }
        }
        dev.write(RING + 5, &found.expect("donor vault has sealed tract blocks")).unwrap();
        dev.flush().unwrap();
        FileDev::create(&pd, RING + 32).unwrap();
    }
    let c = FileDev::open(&pc).unwrap();
    let d = FileDev::open(&pd).unwrap();
    let err = Vault::open(Mirror::new(c, d), HOST_RING_LOG2, 1_000);
    assert!(err.is_err(), "sealed block anywhere = real vault = never format");
}

#[test]
fn many_keys_cold_resume_with_big_values() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "many");
    {
        let mut v = open_vault(&pa, &pb, RING + 2048);
        for i in 0..60 {
            v.put(&key(i), &val(i), 1_000 + i as i64).unwrap();
        }
        let big = vec![0xCD; 18_000]; // direct leaf + furrows
        v.put(&key(777), &big, 2_000).unwrap();
    }
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 3_000).unwrap();
    for i in 0..60 {
        assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "key {i}");
    }
    assert_eq!(v.get(&key(777)).unwrap(), Some(vec![0xCD; 18_000]));
}

#[test]
fn replication_converges_stale_mirror() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "repl");
    // Build in sync.
    {
        let mut v = open_vault(&pa, &pb, RING + 256);
        for i in 0..10 {
            v.put(&key(i), &val(i), 1_000 + i as i64).unwrap();
        }
    }
    // B goes stale: continue on A alone (degraded session).
    {
        let a = FileDev::open(&pa).unwrap();
        let mirror: Mirror<FileDev, FileDev> = Mirror::from_parts(Some(a), None).unwrap();
        let mut v = Vault::open(mirror, HOST_RING_LOG2, 2_000).unwrap();
        for i in 10..20 {
            v.put(&key(i), &val(i), 2_000 + i as i64).unwrap();
        }
    }
    // Converge B from A, block-level, verified, no file copy.
    let mut a = FileDev::open(&pa).unwrap();
    let mut b = FileDev::open(&pb).unwrap();
    let out = verified_replicate(&mut a, &mut b, HOST_RING_LOG2).unwrap();
    assert!(out.spine_copied > 0, "stale spine slots copied");
    assert!(out.tract_copied > 0, "diverged live blocks copied");

    // Idempotent: a second pass copies nothing.
    let out2 = verified_replicate(&mut a, &mut b, HOST_RING_LOG2).unwrap();
    assert_eq!((out2.spine_copied, out2.tract_copied), (0, 0));

    // The converged pair opens and serves everything.
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 3_000).unwrap();
    for i in 0..20 {
        assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "key {i} after replication");
    }
}

#[test]
fn churn_triggers_reap_and_reclaims() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "spin");
    let mut v = open_vault(&pa, &pb, RING + 64); // tiny tract: 64 blocks
    // Churn: every overwrite kills the old leaf + index path → dead piles up fast; the >25% trigger must spin and the tract must never report Full.
    for round in 0..30 {
        for k in 0..4u64 {
            v.put(&key(k), &val(round * 4 + k), 10_000 + round as i64).unwrap();
        }
    }
    for k in 0..4u64 {
        assert_eq!(v.get(&key(k)).unwrap(), Some(val(29 * 4 + k)), "latest value survives churn");
    }
    assert!(v.tract_blocks() == 64);
}

#[test]
fn grow_expands_full_tract_and_survives_resume() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "grow");
    let mut written: Vec<u64> = Vec::new();
    {
        // Tiny tract: fill with distinct keys until it refuses.
        let mut v = open_vault(&pa, &pb, RING + 24);
        let mut i = 0u64;
        loop {
            match v.put(&key(i), &val(i), 1_000 + i as i64) {
                Ok(()) => {
                    written.push(i);
                    i += 1;
                }
                // A saturated tract surfaces as TractFull, or as Fenced when even the heartbeat ladder can't slide the window.
                Err(manifestus::Error::TractFull) | Err(manifestus::Error::Fenced(_)) => break,
                Err(e) => panic!("unexpected error while filling: {e}"),
            }
            assert!(i < 10_000, "tiny tract never filled");
        }
        let old_len = v.tract_blocks();
        v.grow(old_len * 4, 5_000).unwrap();
        assert_eq!(v.tract_blocks(), old_len * 4);

        // Everything written before the grow is intact.
        for &j in &written {
            assert_eq!(v.get(&key(j)).unwrap(), Some(val(j)), "key {j} lost across grow");
        }
        // The key that hit the wall, plus fresh ones, now land.
        for j in i..i + 20 {
            v.put(&key(j), &val(j), 6_000 + j as i64).unwrap();
            written.push(j);
        }
    }
    // Cold resume adopts the grown geometry from the head entry alone.
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 9_000).unwrap();
    for &j in &written {
        assert_eq!(v.get(&key(j)).unwrap(), Some(val(j)), "key {j} lost across resume");
    }
}

#[test]
fn grow_mid_lap_after_churn_keeps_data() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "growlap");
    let mut v = open_vault(&pa, &pb, RING + 64);
    // Push the plow well past several laps so the monotone/wrapped distinction is live, then grow mid-lap.
    for round in 0..30 {
        for k in 0..4u64 {
            v.put(&key(k), &val(round * 4 + k), 10_000 + round as i64).unwrap();
        }
    }
    v.grow(64 * 3, 20_000).unwrap();
    assert_eq!(v.tract_blocks(), 192);
    for k in 0..4u64 {
        assert_eq!(v.get(&key(k)).unwrap(), Some(val(29 * 4 + k)), "value survives mid-lap grow");
    }
    // Keep writing into the enlarged tract, across the old wrap point.
    for round in 30..80 {
        for k in 0..8u64 {
            v.put(&key(k), &val(round * 8 + k), 20_000 + round as i64).unwrap();
        }
    }
    for k in 0..8u64 {
        assert_eq!(v.get(&key(k)).unwrap(), Some(val(79 * 8 + k)));
    }
}

#[test]
fn replication_grows_smaller_loser() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "growrepl");
    // Build in sync, then grow + advance on A alone (B absent = degraded session).
    {
        let mut v = open_vault(&pa, &pb, RING + 32);
        for i in 0..5 {
            v.put(&key(i), &val(i), 1_000 + i as i64).unwrap();
        }
    }
    {
        let a = FileDev::open(&pa).unwrap();
        let mirror: Mirror<FileDev, FileDev> = Mirror::from_parts(Some(a), None).unwrap();
        let mut v = Vault::open(mirror, HOST_RING_LOG2, 2_000).unwrap();
        v.grow(1024, 2_100).unwrap();
        for i in 5..40 {
            v.put(&key(i), &val(i), 2_200 + i as i64).unwrap();
        }
    }
    // B is both stale AND smaller than A's committed geometry; replication must extend it, then converge.
    let mut a = FileDev::open(&pa).unwrap();
    let mut b = FileDev::open(&pb).unwrap();
    assert!(b.block_count() < a.block_count(), "precondition: loser smaller");
    verified_replicate(&mut a, &mut b, HOST_RING_LOG2).unwrap();
    assert_eq!(b.block_count(), a.block_count(), "loser extended to winner's extent");

    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 3_000).unwrap();
    assert_eq!(v.tract_blocks(), 1024);
    for i in 0..40 {
        assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "key {i} after grow+replicate");
    }
}

#[test]
fn huge_value_survives_reap_laps() {
    // THE regression test for the v0 furrow-rot bug: a write-once multi-megabyte value must stay readable while churn drives the reap through multiple full migrations of its blocks. Under the old engine this value (a) exceeded the per-value cap and (b) would have rotted when relocation left its leaf pointing at trampled slots.
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "huge");
    let big: Vec<u8> = (0..3_000_000u32).map(|i| i.wrapping_mul(2654435761) as u8).collect();
    {
        let mut v = open_vault(&pa, &pb, RING + 2048); // 8MB tract
        v.put(&key(9000), &big, 1_000).unwrap();
        assert_eq!(v.get(&key(9000)).unwrap().as_deref(), Some(&big[..]), "fresh read");

        // Churn: overwrite a small working set until the plow has lapped several times — every big-value block is force-migrated by the reap at least once per lap.
        let lap = 2048u64;
        let start_lap = 0u64;
        let mut round = 0u64;
        while (v.tract_blocks_plowed() / lap) < start_lap + 3 {
            for k in 0..8u64 {
                v.put(&key(k), &val(round * 8 + k), 10_000 + round as i64).unwrap();
            }
            round += 1;
            assert!(round < 200_000, "never lapped — reap starved?");
        }
        assert_eq!(v.get(&key(9000)).unwrap().as_deref(), Some(&big[..]), "read after {round} churn rounds and 3+ laps");
        for k in 0..8u64 {
            assert_eq!(v.get(&key(k)).unwrap(), Some(val((round - 1) * 8 + k)));
        }
    }
    // Cold resume: extent leaves + migrated runs all reconstruct from the head alone.
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 99_000).unwrap();
    assert_eq!(v.get(&key(9000)).unwrap().as_deref(), Some(&big[..]), "read after cold resume");
}

#[test]
fn legacy_direct_value_migrates_thru_reap() {
    // A value written in the pre-extent per-lba format must stay readable, survive the reap (which rewrites it into extent form), and survive a cold resume after that.
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "legacy");
    let old: Vec<u8> = (0..60_000u32).map(|i| i.wrapping_mul(97) as u8).collect();
    {
        let mut v = open_vault(&pa, &pb, RING + 256);
        v.put_legacy_direct_for_tests(&key(7000), &old, 1_000).unwrap();
        assert_eq!(v.get(&key(7000)).unwrap().as_deref(), Some(&old[..]), "legacy decode");

        // Churn until the reap has passed the legacy blocks at least once.
        let mut round = 0u64;
        while v.tract_blocks_reaped() < 32 {
            for k in 0..4u64 {
                v.put(&key(k), &val(round * 4 + k), 10_000 + round as i64).unwrap();
            }
            round += 1;
            assert!(round < 100_000, "reap never advanced");
        }
        assert_eq!(v.get(&key(7000)).unwrap().as_deref(), Some(&old[..]), "readable after migration");
    }
    let a = FileDev::open(&pa).unwrap();
    let b = FileDev::open(&pb).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 99_000).unwrap();
    assert_eq!(v.get(&key(7000)).unwrap().as_deref(), Some(&old[..]), "readable after cold resume");
}

// ============================================================================ kill -9, final form =====================================================

/// Child: open (resume or genesis) and put sequential keys forever, one commit each.
#[test]
fn vault_kill_child_worker() {
    let Ok(base) = std::env::var("CUSTODES_VAULT_KILL") else {
        return;
    };
    let a = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
    let b = FileDev::open(std::path::Path::new(&format!("{base}-b.vsf"))).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 5_000).unwrap();
    // Resume the sequence where the committed history says we are.
    let mut i = v.generation().unwrap_or(0); // gen g = g puts committed (genesis is gen 0)
    loop {
        let _ = v.put(&key(i), &val(i), 5_000 + i as i64);
        i += 1;
    }
}

#[test]
fn vault_survives_kill_nine_with_exact_committed_prefix() {
    use std::time::Duration;
    use vsf::types::eagle_time::eagle_time_oscillations;
    let exe = std::env::current_exe().unwrap();
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("kill").to_str().unwrap().to_string();
    FileDev::create(std::path::Path::new(&format!("{base}-a.vsf")), RING + 4096).unwrap();
    FileDev::create(std::path::Path::new(&format!("{base}-b.vsf")), RING + 4096).unwrap();
    // Genesis once, cleanly, so the child only ever resumes.
    {
        let a = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
        let b = FileDev::open(std::path::Path::new(&format!("{base}-b.vsf"))).unwrap();
        Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 4_000).unwrap();
    }

    let mut last_gen = 0u64;
    for round in 0..3 {
        let mut child = std::process::Command::new(&exe)
            .args(["vault_kill_child_worker", "--exact", "--nocapture", "--test-threads=1"])
            .env("CUSTODES_VAULT_KILL", &base)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Pseudo-random kill delay 32..160ms from the eagle clock's low oscillation bits — no rand dep, no UNIX epoch.
        let jitter = eagle_time_oscillations() as u64 % (1 << 7);
        std::thread::sleep(Duration::from_millis((1 << 5) + jitter));
        child.kill().unwrap();
        child.wait().unwrap();

        // Reopen the whole stack cold. The committed generation G defines EXACTLY which puts are visible: keys 0..G present with correct values, key G absent (the in-flight put died provisional).
        let a = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
        let b = FileDev::open(std::path::Path::new(&format!("{base}-b.vsf"))).unwrap();
        let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 6_000).unwrap();
        let g = v.generation().expect("a committed head must survive");
        assert!(g >= last_gen, "round {round}: generations must be monotone");
        last_gen = g;

        for i in 0..g {
            assert_eq!(
                v.get(&key(i)).unwrap(),
                Some(val(i)),
                "round {round}: committed put {i} of {g} must be intact"
            );
        }
        assert_eq!(
            v.get(&key(g)).unwrap(),
            None,
            "round {round}: the in-flight put must be fully absent — never partially visible"
        );
    }
    assert!(last_gen > 0, "at least one put committed across the rounds");
}
