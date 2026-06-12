//! FileDev + Mirror behavior, including the kill -9 harness.

use custodes::{Block, BlockDev, FileDev, Mirror, BLOCK, ZERO_BLOCK};
use tempfile::TempDir;

fn pattern(lba: u64, seed: u8) -> Block {
    let mut b = [0u8; BLOCK];
    let v = (lba as u8) ^ seed;
    b.fill(v);
    b
}

#[test]
fn filedev_roundtrip() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("dev.bin");
    let mut dev = FileDev::create(&path, 64).unwrap();
    assert_eq!(dev.block_count(), 64);

    for lba in [0u64, 1, 31, 63] {
        let buf = pattern(lba, 0xA5);
        dev.write(lba, &buf).unwrap();
    }
    dev.flush().unwrap();
    for lba in [0u64, 1, 31, 63] {
        let mut out = ZERO_BLOCK;
        dev.read(lba, &mut out).unwrap();
        assert_eq!(out, pattern(lba, 0xA5), "lba {lba}");
    }
}

#[test]
fn filedev_unwritten_blocks_read_zero() {
    let dir = TempDir::new().unwrap();
    let mut dev = FileDev::create(&dir.path().join("z.bin"), 16).unwrap();
    let mut out = pattern(0, 0xFF);
    dev.read(7, &mut out).unwrap();
    assert_eq!(out, ZERO_BLOCK, "preallocated blocks must read as zeros (Empty)");
}

#[test]
fn filedev_bounds_checked() {
    let dir = TempDir::new().unwrap();
    let mut dev = FileDev::create(&dir.path().join("b.bin"), 8).unwrap();
    let mut buf = ZERO_BLOCK;
    assert!(dev.read(8, &mut buf).is_err());
    assert!(dev.write(8, &buf).is_err());
    assert!(dev.read(7, &mut buf).is_ok());
}

#[test]
fn filedev_persists_across_open() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("p.bin");
    {
        let mut dev = FileDev::create(&path, 8).unwrap();
        dev.write(3, &pattern(3, 0x11)).unwrap();
        dev.flush().unwrap();
    }
    let mut dev = FileDev::open(&path).unwrap();
    let mut out = ZERO_BLOCK;
    dev.read(3, &mut out).unwrap();
    assert_eq!(out, pattern(3, 0x11));
}

#[test]
fn filedev_create_refuses_existing() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("e.bin");
    FileDev::create(&path, 4).unwrap();
    assert!(FileDev::create(&path, 4).is_err(), "create over existing must refuse");
}

#[test]
fn filedev_rejects_unaligned_length() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("u.bin");
    std::fs::write(&path, vec![0u8; 1000]).unwrap();
    assert!(FileDev::open(&path).is_err(), "non-4KB-multiple file is not ours");
}

#[test]
fn filedev_grow() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("g.bin");
    let mut dev = FileDev::create(&path, 8).unwrap();
    dev.write(7, &pattern(7, 0x22)).unwrap();
    dev.grow(16).unwrap();
    assert_eq!(dev.block_count(), 16);
    // Old data intact, new space zeroed.
    let mut out = ZERO_BLOCK;
    dev.read(7, &mut out).unwrap();
    assert_eq!(out, pattern(7, 0x22));
    dev.read(15, &mut out).unwrap();
    assert_eq!(out, ZERO_BLOCK);
    assert!(dev.grow(8).is_err(), "grow cannot shrink");
}

#[test]
fn mirror_writes_both_devices() {
    let dir = TempDir::new().unwrap();
    let pa = dir.path().join("a.bin");
    let pb = dir.path().join("b.bin");
    let a = FileDev::create(&pa, 16).unwrap();
    let b = FileDev::create(&pb, 16).unwrap();
    let mut m = Mirror::new(a, b);

    m.write_verified(5, &pattern(5, 0x33)).unwrap();
    assert!(!m.degraded());
    drop(m);

    // Raw byte check on both files.
    for p in [&pa, &pb] {
        let bytes = std::fs::read(p).unwrap();
        let got = &bytes[5 * BLOCK..6 * BLOCK];
        assert_eq!(got, pattern(5, 0x33).as_slice(), "{p:?}");
    }
}

/// Test-local failing device: forwards to inner FileDev, fails writes after a fuse burns.
struct Flaky {
    inner: FileDev,
    writes_left: usize,
}

impl BlockDev for Flaky {
    fn block_count(&self) -> u64 {
        self.inner.block_count()
    }
    fn read(&mut self, lba: u64, buf: &mut Block) -> custodes::Result<()> {
        self.inner.read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &Block) -> custodes::Result<()> {
        if self.writes_left == 0 {
            return Err(custodes::Error::Verify(lba));
        }
        self.writes_left -= 1;
        self.inner.write(lba, buf)
    }
    fn flush(&mut self) -> custodes::Result<()> {
        self.inner.flush()
    }
}

#[test]
fn mirror_secondary_failure_degrades_but_succeeds() {
    let dir = TempDir::new().unwrap();
    let a = FileDev::create(&dir.path().join("a.bin"), 16).unwrap();
    let b = Flaky {
        inner: FileDev::create(&dir.path().join("b.bin"), 16).unwrap(),
        writes_left: 1,
    };
    let mut m: Mirror<FileDev, Flaky> = Mirror::new(a, b);

    m.write_verified(0, &pattern(0, 0x44)).unwrap(); // b's one write spent
    assert!(!m.degraded());
    m.write_verified(1, &pattern(1, 0x44)).unwrap(); // b fails → dropped
    assert!(m.degraded());
    assert!(!m.has_b());
    m.write_verified(2, &pattern(2, 0x44)).unwrap(); // solo-a keeps working

    let mut out = ZERO_BLOCK;
    m.read(2, &mut out).unwrap();
    assert_eq!(out, pattern(2, 0x44));
}

#[test]
fn mirror_primary_failure_is_hard_error_and_secondary_untouched() {
    let dir = TempDir::new().unwrap();
    let pb = dir.path().join("b.bin");
    let a = Flaky {
        inner: FileDev::create(&dir.path().join("a.bin"), 16).unwrap(),
        writes_left: 0,
    };
    let b = FileDev::create(&pb, 16).unwrap();
    let mut m: Mirror<Flaky, FileDev> = Mirror::new(a, b);

    assert!(m.write_verified(3, &pattern(3, 0x55)).is_err());

    // RING.md: "do not proceed" — b must not have the block.
    let bytes = std::fs::read(&pb).unwrap();
    assert_eq!(&bytes[3 * BLOCK..4 * BLOCK], ZERO_BLOCK.as_slice());
}

#[test]
fn mirror_solo_b_works() {
    let dir = TempDir::new().unwrap();
    let b = FileDev::create(&dir.path().join("b.bin"), 8).unwrap();
    let mut m: Mirror<FileDev, FileDev> = Mirror::from_parts(None, Some(b)).unwrap();
    assert!(m.degraded(), "missing mirror starts degraded");
    m.write_verified(1, &pattern(1, 0x66)).unwrap();
    let mut out = ZERO_BLOCK;
    m.read(1, &mut out).unwrap();
    assert_eq!(out, pattern(1, 0x66));
}

// ============================================================================ kill -9 harness ============================================================

/// Child worker: writes verified pattern blocks in a loop until killed. Invoked by `kill_nine_leaves_only_valid_or_empty_blocks` re-running this test binary with the env var set; returns immediately as a passing no-op otherwise.
#[test]
fn kill_child_worker() {
    let Ok(path) = std::env::var("CUSTODES_KILL_PATH") else {
        return;
    };
    let mut dev = FileDev::open(std::path::Path::new(&path)).unwrap();
    let n = dev.block_count();
    let mut lba = 0u64;
    loop {
        let buf = pattern(lba, 0x77);
        let _ = dev.write(lba, &buf);
        let _ = dev.flush();
        lba = (lba + 1) % n;
    }
}

#[test]
fn kill_nine_leaves_only_valid_or_empty_blocks() {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    let exe = std::env::current_exe().unwrap();
    let dir = TempDir::new().unwrap();

    for round in 0..4 {
        let path = dir.path().join(format!("kill{round}.bin"));
        FileDev::create(&path, 32).unwrap();

        let mut child = std::process::Command::new(&exe)
            .args(["kill_child_worker", "--exact", "--nocapture", "--test-threads=1"])
            .env("CUSTODES_KILL_PATH", &path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();

        // Pseudo-random kill delay 30..160ms without a rand dep.
        let jitter = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .subsec_nanos() as u64
            % 130;
        std::thread::sleep(Duration::from_millis(30 + jitter));
        child.kill().unwrap(); // SIGKILL — no cleanup, no flush, nothing
        child.wait().unwrap();

        // Invariant: every block is all-zeros (never written) or exactly its pattern (write completed). Process death must never manufacture garbage.
        let mut dev = FileDev::open(&path).unwrap();
        let mut buf = ZERO_BLOCK;
        for lba in 0..dev.block_count() {
            dev.read(lba, &mut buf).unwrap();
            let ok = buf == ZERO_BLOCK || buf == pattern(lba, 0x77);
            assert!(ok, "round {round} lba {lba}: block is neither Empty nor a completed write");
        }
    }
}

#[test]
fn filedev_o_direct_on_real_fs() {
    // TempDir defaults to /tmp (tmpfs) where O_DIRECT is refused and the buffered fallback engages. This test runs on the repo's real filesystem to exercise the O_DIRECT aligned-bounce path. If even this fs refuses O_DIRECT, the assert degrades to roundtrip-only.
    let dir = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
    let path = dir.path().join("direct.bin");
    let mut dev = FileDev::create(&path, 16).unwrap();

    #[cfg(any(target_os = "linux", target_os = "android"))]
    assert!(dev.direct(), "expected O_DIRECT on a real filesystem");

    dev.write(9, &pattern(9, 0x88)).unwrap();
    dev.flush().unwrap();
    let mut out = ZERO_BLOCK;
    dev.read(9, &mut out).unwrap();
    assert_eq!(out, pattern(9, 0x88));
}
