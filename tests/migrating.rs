//! Migrating rings (RING.md "Migrating Rings"): two-level bootstrap, fixed-residency hops, A/B crash fallback, replication across a migration.

use manifestus::{
    append_root, read_root, verified_replicate, FileDev, Mirror, RootEntry, Vault, ROOT_SLOTS,
};
use tempfile::TempDir;

// Tiny geometry so residencies expire fast: N = 16 slots, 3 residences, 2 rotations each → a hop every 32 generations.
const R_LOG2: u8 = 4;
const N: u64 = 1 << R_LOG2;
const RESIDENCES: u64 = 3;
const RESIDENCY: u64 = 2;
const BLOCKS: u64 = ROOT_SLOTS + RESIDENCES * N + 512;

fn key(i: u64) -> [u8; 32] {
    *blake3::hash(&i.to_le_bytes()).as_bytes()
}

fn val(i: u64) -> Vec<u8> {
    format!("value-{i}-{}", "y".repeat((i % 5) as usize * 80)).into_bytes()
}

fn paths(dir: &TempDir, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    (
        dir.path().join(format!("{name}-a.vsf")),
        dir.path().join(format!("{name}-b.vsf")),
    )
}

fn genesis(pa: &std::path::Path, pb: &std::path::Path) -> Vault<FileDev, FileDev> {
    let a = FileDev::create(pa, BLOCKS).unwrap();
    let b = FileDev::create(pb, BLOCKS).unwrap();
    Vault::open_migrating(Mirror::new(a, b), R_LOG2, RESIDENCES, RESIDENCY, 1_000).unwrap()
}

fn reopen(pa: &std::path::Path, pb: &std::path::Path) -> Vault<FileDev, FileDev> {
    let a = FileDev::open(pa).unwrap();
    let b = FileDev::open(pb).unwrap();
    // Plain open — the layout is self-describing; no migrating-specific entry point needed.
    Vault::open(Mirror::new(a, b), R_LOG2, 2_000).unwrap()
}

#[test]
fn migrating_genesis_and_plain_reopen() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "gen");
    {
        let mut v = genesis(&pa, &pb);
        v.put(&key(1), b"alpha", 1_001).unwrap();
        v.put(&key(2), b"beta", 1_002).unwrap();
        assert_eq!(v.get(&key(1)).unwrap(), Some(b"alpha".to_vec()));
    }
    let mut a = FileDev::open(&pa).unwrap();
    let root = read_root(&mut a).unwrap().expect("root entry present");
    assert_eq!(root.at, ROOT_SLOTS, "first residence");
    drop(a);

    let mut v = reopen(&pa, &pb);
    assert_eq!(v.get(&key(1)).unwrap(), Some(b"alpha".to_vec()));
    assert_eq!(v.get(&key(2)).unwrap(), Some(b"beta".to_vec()));
}

#[test]
fn spine_hops_residences_and_data_survives() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "hop");
    {
        let mut v = genesis(&pa, &pb);
        // ~200 commits → hops every 32 generations → several migrations, with wrap around the 3-residence band.
        let mut latest: [Vec<u8>; 7] = Default::default();
        for i in 0..100u64 {
            v.put(&key(i % 7), &val(i), 1_000 + i as i64).unwrap();
            latest[(i % 7) as usize] = val(i);
            v.put(&key(100 + i), &val(i), 1_000 + i as i64).unwrap();
        }
        for i in 0..7u64 {
            assert_eq!(
                v.get(&key(i)).unwrap().as_deref(),
                Some(&latest[i as usize][..]),
                "small-set key {i} readable"
            );
        }
    }
    let mut a = FileDev::open(&pa).unwrap();
    let root = read_root(&mut a).unwrap().expect("root entry present");
    assert!(root.gen >= 3, "multiple migrations happened (root gen {})", root.gen);
    assert!(root.at != root.was, "current and previous residences differ");
    drop(a);

    let mut v = reopen(&pa, &pb);
    for i in 0..100u64 {
        assert_eq!(v.get(&key(100 + i)).unwrap(), Some(val(i)), "key {} after reopen", 100 + i);
    }
}

#[test]
fn ab_fallback_when_migration_tore_before_first_commit() {
    // Crash-equivalent: the root entry advanced to a zeroed residence, but no spine commit ever landed there. Boot must fall back to `was`, serve everything, and keep committing (at the fallback base) without corruption.
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "torn");
    {
        let mut v = genesis(&pa, &pb);
        for i in 0..10u64 {
            v.put(&key(i), &val(i), 1_000 + i as i64).unwrap();
        }
    }
    // Hand-write the torn migration: root gen+1 pointing at the (zeroed) next residence.
    {
        let a = FileDev::open(&pa).unwrap();
        let b = FileDev::open(&pb).unwrap();
        let mut mirror = Mirror::new(a, b);
        let (da, _) = mirror.devices();
        let old = read_root(da.unwrap()).unwrap().unwrap();
        let next = ROOT_SLOTS + (((old.at - ROOT_SLOTS) / N + 1) % RESIDENCES) * N;
        // Zero the next residence on both mirrors (step 1 of the migration).
        for slot in 0..N {
            mirror
                .write_verified(next + slot, &manifestus::ZERO_BLOCK)
                .unwrap();
        }
        let torn = RootEntry {
            gen: old.gen + 1,
            prev_hash: old.body_hash(),
            at: next,
            was: old.at,
            since: 10_000, // far future — no immediate re-hop
            ..old
        };
        append_root(&mut mirror, &torn).unwrap();
        // Crash here: nothing ever committed at `next`.
    }
    let mut v = reopen(&pa, &pb);
    for i in 0..10u64 {
        assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "key {i} after fallback");
    }
    v.put(&key(99), b"post-fallback", 3_000).unwrap();
    assert_eq!(v.get(&key(99)).unwrap(), Some(b"post-fallback".to_vec()));
}

#[test]
fn replication_converges_migrating_pair() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "repl");
    {
        let mut v = genesis(&pa, &pb);
        for i in 0..10u64 {
            v.put(&key(i), &val(i), 1_000 + i as i64).unwrap();
        }
    }
    // B goes stale; A alone commits far enough to migrate at least once.
    {
        let a = FileDev::open(&pa).unwrap();
        let mirror: Mirror<FileDev, FileDev> = Mirror::from_parts(Some(a), None).unwrap();
        let mut v = Vault::open(mirror, R_LOG2, 2_000).unwrap();
        for i in 10..60u64 {
            v.put(&key(i), &val(i), 2_000 + i as i64).unwrap();
        }
    }
    let mut a = FileDev::open(&pa).unwrap();
    let mut b = FileDev::open(&pb).unwrap();
    verified_replicate(&mut a, &mut b, R_LOG2).unwrap();
    // Idempotent second pass.
    let out2 = verified_replicate(&mut a, &mut b, R_LOG2).unwrap();
    assert_eq!((out2.spine_copied, out2.tract_copied), (0, 0));

    let mut v = Vault::open(Mirror::new(a, b), R_LOG2, 3_000).unwrap();
    for i in 0..60u64 {
        assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "key {i} after replication");
    }
}

// ============================================================================ kill -9, migrating form ================================================

fn counter_key() -> [u8; 32] {
    *blake3::hash(b"kill-counter").as_bytes()
}

/// Child: resume and put sequential keys forever — two commits per step (payload, then counter), with reap windows and residence migrations firing constantly underneath (residency = 1 rotation → a hop every 16 spine generations).
#[test]
fn migrating_kill_child_worker() {
    let Ok(base) = std::env::var("CUSTODES_MIGRATING_KILL") else {
        return;
    };
    let a = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
    let b = FileDev::open(std::path::Path::new(&format!("{base}-b.vsf"))).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), R_LOG2, 5_000).unwrap();
    let mut i = match v.get(&counter_key()).unwrap() {
        Some(bytes) => u64::from_le_bytes(bytes.try_into().unwrap()),
        None => 0,
    };
    loop {
        if v.put(&key(i), &val(i), 5_000 + i as i64).is_err() {
            break; // tract genuinely full — park, never punch holes in the sequence
        }
        if v.put(&counter_key(), &(i + 1).to_le_bytes(), 5_000 + i as i64).is_err() {
            break;
        }
        i += 1;
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

#[test]
fn migrating_survives_kill_nine_with_exact_committed_prefix() {
    use std::time::Duration;
    use vsf::types::eagle_time::eagle_time_oscillations;
    let exe = std::env::current_exe().unwrap();
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("mkill").to_str().unwrap().to_string();
    let blocks = ROOT_SLOTS + RESIDENCES * N + 16384;
    FileDev::create(std::path::Path::new(&format!("{base}-a.vsf")), blocks).unwrap();
    FileDev::create(std::path::Path::new(&format!("{base}-b.vsf")), blocks).unwrap();
    // Genesis once, cleanly, with a 1-rotation residency: migrations every 16 commits, so kills land before, during, and after hops across the rounds.
    {
        let a = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
        let b = FileDev::open(std::path::Path::new(&format!("{base}-b.vsf"))).unwrap();
        Vault::open_migrating(Mirror::new(a, b), R_LOG2, RESIDENCES, 1, 4_000).unwrap();
    }

    let mut last_count = 0u64;
    let mut last_root_gen = 0u64;
    for round in 0..6 {
        let mut child = std::process::Command::new(&exe)
            .args(["migrating_kill_child_worker", "--exact", "--nocapture", "--test-threads=1"])
            .env("CUSTODES_MIGRATING_KILL", &base)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        // Pseudo-random kill delay 32..160ms from the eagle clock's low oscillation bits.
        let jitter = eagle_time_oscillations() as u64 % (1 << 7);
        std::thread::sleep(Duration::from_millis((1 << 5) + jitter));
        child.kill().unwrap();
        child.wait().unwrap();

        // Reopen cold thru the two-level bootstrap. The committed counter C defines the exact visible prefix: keys 0..C intact; key C either fully present (payload committed, counter in flight) or fully absent; key C+1 impossible.
        let a = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
        let b = FileDev::open(std::path::Path::new(&format!("{base}-b.vsf"))).unwrap();
        let mut v = Vault::open(Mirror::new(a, b), R_LOG2, 6_000).unwrap();
        let c = match v.get(&counter_key()).unwrap() {
            Some(bytes) => u64::from_le_bytes(bytes.try_into().unwrap()),
            None => 0,
        };
        assert!(c >= last_count, "round {round}: committed count must be monotone");
        last_count = c;

        for i in 0..c {
            assert_eq!(
                v.get(&key(i)).unwrap(),
                Some(val(i)),
                "round {round}: committed put {i} of {c} must be intact"
            );
        }
        match v.get(&key(c)).unwrap() {
            None => {}
            Some(got) => assert_eq!(got, val(c), "round {round}: in-flight put must be exact if visible"),
        }
        assert_eq!(
            v.get(&key(c + 1)).unwrap(),
            None,
            "round {round}: nothing beyond the in-flight put may exist"
        );

        // The root ring survived too, and migrations are actually happening under fire.
        let mut da = FileDev::open(std::path::Path::new(&format!("{base}-a.vsf"))).unwrap();
        let root = read_root(&mut da).unwrap().expect("root entry must survive kill -9");
        assert!(root.gen >= last_root_gen, "round {round}: root generations monotone");
        last_root_gen = root.gen;
    }
    assert!(last_count > 0, "at least one put committed across the rounds");
    assert!(last_root_gen > 0, "at least one migration happened under fire");
}
