//! `vaultfix` stamps its repaired generation in Eagle Time: the spine's `time` field is eagle oscillations, the clock kete stamps every other commit with.
//! A UNIX-seconds stamp (the old behavior) reads as about one Eagle second after the epoch, so the window check below catches it.

use manifestus::inspect::{inspect, InspectOptions};
use manifestus::{DeletePolicy, FileDev, Mirror, Vault, HOST_RING_LOG2};
use tempfile::TempDir;
use vsf::types::eagle_time::eagle_time_oscillations;

const RING: u64 = 1 << HOST_RING_LOG2;
const TRACT: u64 = 1 << 6;

#[test]
fn vaultfix_stamps_eagle_time() {
    let dir = TempDir::new().unwrap();
    let pa = dir.path().join("a.vsf");
    let pb = dir.path().join("b.vsf");
    {
        let a = FileDev::create(&pa, RING + TRACT).unwrap();
        let b = FileDev::create(&pb, RING + TRACT).unwrap();
        let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 1, DeletePolicy::UnlinkOnly).unwrap();
        v.put(blake3::hash(b"k").as_bytes(), &[0x5Au8; 300], 2).unwrap();
    }

    let before = eagle_time_oscillations();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_vaultfix"))
        .arg(&pa)
        .arg(&pb)
        .output()
        .unwrap();
    let after = eagle_time_oscillations();
    assert!(out.status.success(), "vaultfix failed: {}", String::from_utf8_lossy(&out.stderr));

    let mut a = FileDev::open(&pa).unwrap();
    let report = inspect(&mut a, InspectOptions::default()).unwrap();
    let (_, head) = report.head.expect("repaired vault has a committed head");
    assert!(
        head.eagle_time >= before && head.eagle_time <= after,
        "repaired generation's time {} is outside the run's eagle window [{before}, {after}]",
        head.eagle_time
    );
}
