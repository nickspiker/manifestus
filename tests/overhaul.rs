//! The 2026-10-22 write path: group commit, the verified head (a commit's run and entry under one flush), and the lazy second copy (the follower). Each test is a crash shape the new path must survive exactly.

use manifestus::{classify, verified_replicate, Classified, DeletePolicy, FileDev, Mirror, Vault, HOST_RING_LOG2, ZERO_BLOCK};
use tempfile::TempDir;

const RING: u64 = 1 << HOST_RING_LOG2;

fn key(i: u64) -> [u8; 32] {
    *blake3::hash(&i.to_le_bytes()).as_bytes()
}

fn val(i: u64) -> Vec<u8> {
    format!("value-{i}-{}", "x".repeat((i % 7) as usize * 100)).into_bytes()
}

fn paths(dir: &TempDir, name: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    (dir.path().join(format!("{name}-a.vsf")), dir.path().join(format!("{name}-b.vsf")))
}

fn open_pair(pa: &std::path::Path, pb: &std::path::Path) -> Vault<FileDev, FileDev> {
    let a = FileDev::open(pa).unwrap();
    let b = FileDev::open(pb).unwrap();
    Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 9_000, DeletePolicy::UnlinkOnly).unwrap()
}

/// One device alone, as a vault — what that device holds by itself.
fn open_solo(p: &std::path::Path) -> Vault<FileDev, FileDev> {
    let d = FileDev::open(p).unwrap();
    Vault::open(Mirror::from_parts(Some(d), None).unwrap(), HOST_RING_LOG2, 9_000, DeletePolicy::UnlinkOnly).unwrap()
}

/// The newest spine entry on a device file, read raw.
fn head_entry(p: &std::path::Path) -> manifestus::SpineEntry {
    use manifestus::BlockDev;
    let mut d = FileDev::open(p).unwrap();
    let mut best: Option<manifestus::SpineEntry> = None;
    let mut buf = ZERO_BLOCK;
    for slot in 0..RING {
        d.read(slot, &mut buf).unwrap();
        if let Classified::Valid(e) = classify(&buf, slot, Some(HOST_RING_LOG2)) {
            if best.as_ref().map_or(true, |b| e.gen > b.gen) {
                best = Some(e);
            }
        }
    }
    best.unwrap()
}

/// A commit whose entry landed while part of its run did not: the vault opens at the generation before it, every earlier value whole, and the next commit takes the torn entry's place.
#[test]
fn torn_head_opens_at_the_generation_before() {
    use manifestus::BlockDev;
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "torn");
    FileDev::create(&pa, RING + 1024).unwrap();
    FileDev::create(&pb, RING + 1024).unwrap();
    {
        let mut v = open_pair(&pa, &pb);
        v.put(&key(1), &val(1), 10).unwrap();
        v.put(&key(2), &val(2), 11).unwrap();
        assert_eq!(v.generation(), Some(2));
    }
    // Tear the last commit on both devices: its entry stays, one block of its run goes back to what an unwritten block holds.
    let head = head_entry(&pa);
    assert_eq!(head.gen, 2);
    let t = head.tail.expect("a small commit writes its run under its entry's flush");
    for p in [&pa, &pb] {
        let mut d = FileDev::open(p).unwrap();
        d.write(RING + (t.start + t.count - 1) % head.tract_blocks, &ZERO_BLOCK).unwrap();
        d.flush().unwrap();
    }
    let mut v = open_pair(&pa, &pb);
    assert_eq!(v.generation(), Some(1), "the torn generation is not the head");
    assert_eq!(v.get(&key(1)).unwrap(), Some(val(1)), "the generation before it is whole");
    assert_eq!(v.get(&key(2)).unwrap(), None, "the torn commit's value is absent, never half-there");
    v.put(&key(3), &val(3), 12).unwrap();
    assert_eq!(v.generation(), Some(2), "the next commit takes the torn entry's generation and slot");
    drop(v);
    let mut v = open_pair(&pa, &pb);
    assert_eq!(v.get(&key(1)).unwrap(), Some(val(1)));
    assert_eq!(v.get(&key(2)).unwrap(), None);
    assert_eq!(v.get(&key(3)).unwrap(), Some(val(3)));
}

/// A clean close with the follower on leaves both devices holding the same committed state.
#[test]
fn follower_drains_on_close() {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "drain");
    FileDev::create(&pa, RING + 1024).unwrap();
    FileDev::create(&pb, RING + 1024).unwrap();
    let big = vec![0x5Au8; 300_000];
    {
        let mut v = open_pair(&pa, &pb);
        v.follow();
        for i in 0..40 {
            v.put(&key(i), &val(i), 100 + i as i64).unwrap();
        }
        v.put(&key(1000), &big, 200).unwrap();
        assert!(!v.degraded(), "a healthy follower is not degradation");
    }
    for p in [&pa, &pb] {
        let mut v = open_solo(p);
        assert_eq!(v.generation(), Some(41), "{p:?}: every commit reached this device");
        for i in 0..40 {
            assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "{p:?}: value {i}");
        }
        assert_eq!(v.get(&key(1000)).unwrap().as_deref(), Some(big.as_slice()), "{p:?}: the large value");
    }
}

/// Child for the follower kill test: open, follow, put sequential keys forever.
#[test]
fn follower_kill_child_worker() {
    let Ok(base) = std::env::var("MANIFESTUS_FOLLOWER_KILL") else {
        return;
    };
    let pa = std::path::PathBuf::from(format!("{base}-a.vsf"));
    let pb = std::path::PathBuf::from(format!("{base}-b.vsf"));
    let _ = verified_replicate(&mut FileDev::open(&pa).unwrap(), &mut FileDev::open(&pb).unwrap(), HOST_RING_LOG2);
    let mut v = open_pair(&pa, &pb);
    v.follow();
    let mut i = v.generation().unwrap_or(0);
    loop {
        let _ = v.put(&key(i), &val(i), 5_000 + i as i64);
        i += 1;
    }
}

/// kill -9 with the follower on, many times: the primary always opens to the exact committed prefix, the second device by itself is always a valid OLDER prefix (never a mix), and the open-time replicate brings it level.
#[test]
fn follower_survives_kill_nine() {
    use std::time::Duration;
    use vsf::types::eagle_time::eagle_time_oscillations;
    let exe = std::env::current_exe().unwrap();
    let dir = TempDir::new().unwrap();
    let base = dir.path().join("fkill").to_str().unwrap().to_string();
    let pa = std::path::PathBuf::from(format!("{base}-a.vsf"));
    let pb = std::path::PathBuf::from(format!("{base}-b.vsf"));
    FileDev::create(&pa, RING + 4096).unwrap();
    FileDev::create(&pb, RING + 4096).unwrap();
    drop(open_pair(&pa, &pb));

    let mut last_gen = 0u64;
    for round in 0..6 {
        let mut child = std::process::Command::new(&exe)
            .args(["follower_kill_child_worker", "--exact", "--nocapture", "--test-threads=1"])
            .env("MANIFESTUS_FOLLOWER_KILL", &base)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let jitter = eagle_time_oscillations() as u64 % (1 << 8);
        std::thread::sleep(Duration::from_millis((1 << 6) + jitter));
        child.kill().unwrap();
        child.wait().unwrap();

        // The second device alone, before anything heals it: a valid vault at some generation no newer than the primary's, holding exactly its own prefix.
        let gb = {
            let mut vb = open_solo(&pb);
            let gb = vb.generation().expect("the second device is a vault by itself");
            for i in 0..gb {
                assert_eq!(vb.get(&key(i)).unwrap(), Some(val(i)), "round {round}: second device's committed put {i} of {gb}");
            }
            assert_eq!(vb.get(&key(gb)).unwrap(), None, "round {round}: nothing past the second device's own head");
            gb
        };

        let healed = verified_replicate(&mut FileDev::open(&pa).unwrap(), &mut FileDev::open(&pb).unwrap(), HOST_RING_LOG2).unwrap();
        let mut v = open_pair(&pa, &pb);
        let g = v.generation().unwrap();
        assert!(g >= gb, "round {round}: the primary is never behind the second device ({g} < {gb})");
        assert!(g >= last_gen, "round {round}: monotone");
        last_gen = g;
        for i in 0..g {
            assert_eq!(v.get(&key(i)).unwrap(), Some(val(i)), "round {round}: committed put {i} of {g}");
        }
        assert_eq!(v.get(&key(g)).unwrap(), None, "round {round}: the in-flight put is absent");
        drop(v);
        // After the heal the second device holds the primary's head.
        let mut vb = open_solo(&pb);
        assert_eq!(vb.generation(), Some(g), "round {round}: replicate brought the second device level ({healed:?})");
    }
    assert!(last_gen > 0, "commits happened");
}

/// Opening from the live map must know exactly what a walk of the index would: same positions, nothing more, nothing less — for an inline map (small tract) and a paged one (past `INLINE_MAX_BITS`), through churn long enough that the reap laps the tract and crosses the map's own pages.
fn map_matches_walk(blocks: u64, value_len: usize, laps: u64) {
    let dir = TempDir::new().unwrap();
    let (pa, pb) = paths(&dir, "map");
    FileDev::create(&pa, RING + blocks).unwrap();
    FileDev::create(&pb, RING + blocks).unwrap();
    let mut now = 100i64;
    let keys = 24u64;
    let value = |k: u64, round: u64| -> Vec<u8> {
        let mut v = vec![(k as u8) ^ (round as u8); value_len];
        v[..16].copy_from_slice(&blake3::hash(&[k.to_le_bytes(), round.to_le_bytes()].concat()).as_bytes()[..16]);
        v
    };
    let mut latest = vec![0u64; keys as usize];
    {
        let mut v = open_pair(&pa, &pb);
        let mut round = 0u64;
        while v.tract_blocks_plowed() < laps * v.tract_blocks() {
            round += 1;
            for k in 0..keys {
                now += 1;
                if (k + round) % 5 == 0 {
                    v.delete(&key(k), now).unwrap();
                    latest[k as usize] = u64::MAX;
                } else {
                    v.put(&key(k), &value(k, round), now).unwrap();
                    latest[k as usize] = round;
                }
            }
            if round % 7 == 0 {
                drop(v);
                v = open_pair(&pa, &pb);
                assert!(v.opened_from_map(), "round {round}: the reopen read the live map");
                let (unrouted, missing) = v.live_map_divergence().unwrap();
                assert!(unrouted.is_empty() && missing.is_empty(), "round {round}: map vs walk — unrouted {unrouted:?}, missing {missing:?}");
            }
        }
        let (unrouted, missing) = v.live_map_divergence().unwrap();
        assert!(unrouted.is_empty() && missing.is_empty(), "end: map vs walk — unrouted {unrouted:?}, missing {missing:?}");
    }
    let mut v = open_pair(&pa, &pb);
    assert!(v.opened_from_map(), "the final reopen read the live map");
    let (unrouted, missing) = v.live_map_divergence().unwrap();
    assert!(unrouted.is_empty() && missing.is_empty(), "reopened: map vs walk — unrouted {unrouted:?}, missing {missing:?}");
    for k in 0..keys {
        let want = match latest[k as usize] {
            u64::MAX => None,
            r => Some(value(k, r)),
        };
        assert_eq!(v.get(&key(k)).unwrap(), want, "key {k}");
    }
}

#[test]
fn inline_map_matches_walk_through_laps() {
    map_matches_walk(2048, 9_000, 3);
}

#[test]
fn paged_map_matches_walk_through_laps() {
    map_matches_walk(manifestus::livemap::INLINE_MAX_BITS + 8192, 60_000, 2);
}
