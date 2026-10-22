//! What the engine costs, phase by phase, on real files: cell-sized puts one at a time and in a batch, small puts, a cold reopen, and reads.
//! `cargo run --release --example bench -- <dir> [cells] [cell_kib]` — the dir must be on the disk being measured (not tmpfs).
use manifestus::{DeletePolicy, FileDev, Mirror, Vault, HOST_RING_LOG2};
use std::time::Instant;

const INITIAL_TRACT: u64 = 4096;

fn key(tag: u8, i: u32) -> [u8; 32] {
    *blake3::hash(&[&[tag][..], &i.to_le_bytes()].concat()).as_bytes()
}

fn value(i: u32, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut x = blake3::Hasher::new();
    x.update(&i.to_le_bytes());
    let mut r = x.finalize_xof();
    out.resize(len, 0);
    r.fill(&mut out);
    out
}

fn open(dir: &std::path::Path) -> Vault<FileDev, FileDev> {
    let blocks = (1u64 << HOST_RING_LOG2) + INITIAL_TRACT;
    let a = FileDev::create(&dir.join("bench.vsf"), blocks).unwrap();
    let b = FileDev::create(&dir.join("bench.shadow.vsf"), blocks).unwrap();
    manifestus::verified_replicate(&mut FileDev::open(&dir.join("bench.vsf")).unwrap(), &mut FileDev::open(&dir.join("bench.shadow.vsf")).unwrap(), HOST_RING_LOG2).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 1, DeletePolicy::UnlinkOnly).unwrap();
    if std::env::var_os("BENCH_SYNC").is_none() {
        v.follow();
    }
    v
}

fn ms(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = std::path::PathBuf::from(args.next().expect("dir"));
    let cells: u32 = args.next().map_or(300, |s| s.parse().unwrap());
    let cell_len = args.next().map_or(120, |s| s.parse::<usize>().unwrap()) * 1024;
    let _ = std::fs::remove_file(dir.join("bench.vsf"));
    let _ = std::fs::remove_file(dir.join("bench.shadow.vsf"));
    std::fs::create_dir_all(&dir).unwrap();

    let t = Instant::now();
    let mut v = open(&dir);
    println!("genesis                 {:>9.1} ms", ms(t));

    // Cells one at a time: what the old vault-backed cache paid per download.
    let half = cells / 2;
    let t = Instant::now();
    for i in 0..half {
        v.put(&key(1, i), &value(i, cell_len), 2 + i as i64).unwrap();
    }
    let e = ms(t);
    println!("put cell x{half:<5}         {:>9.1} ms  ({:.2} ms each, {:.1} MB/s)", e, e / half as f64, (half as f64 * cell_len as f64) / e / 1000.0);

    // The rest under one group commit.
    let rest: Vec<([u8; 32], Vec<u8>)> = (half..cells).map(|i| (key(1, i), value(i, cell_len))).collect();
    let items: Vec<(&[u8; 32], &[u8])> = rest.iter().map(|(k, v)| (k, v.as_slice())).collect();
    let t = Instant::now();
    v.put_batch(&items, 100_000).unwrap();
    let e = ms(t);
    println!("put_batch cell x{:<5}   {:>9.1} ms  ({:.2} ms each)", items.len(), e, e / items.len() as f64);

    // Small values one at a time: settings, session, an index entry.
    let small = 100u32;
    let t = Instant::now();
    for i in 0..small {
        v.put(&key(2, i), &value(i, 64), 200_000 + i as i64).unwrap();
    }
    let e = ms(t);
    println!("put small x{small:<5}        {:>9.1} ms  ({:.2} ms each)", e, e / small as f64);

    let t = Instant::now();
    v.sync_follower();
    println!("second copy catches up  {:>9.1} ms", ms(t));
    let stats = v.engine_stats();
    println!("tract {} blocks ({} MiB), {} live blocks, gen {}", stats.tract_blocks, stats.tract_blocks * 4 / 1024, stats.live_blocks, stats.generation);
    drop(v);

    // Cold reopen, the part a launch waits on.
    let t = Instant::now();
    let mut v = open(&dir);
    println!("reopen                  {:>9.1} ms", ms(t));

    let t = Instant::now();
    for i in 0..cells {
        let got = v.get(&key(1, i)).unwrap().unwrap();
        assert_eq!(got.len(), cell_len);
    }
    let e = ms(t);
    println!("get cell x{cells:<5}         {:>9.1} ms  ({:.2} ms each, {:.1} MB/s)", e, e / cells as f64, (cells as f64 * cell_len as f64) / e / 1000.0);

    let t = Instant::now();
    for i in 0..small {
        assert!(v.get(&key(2, i)).unwrap().is_some());
    }
    let e = ms(t);
    println!("get small x{small:<5}        {:>9.1} ms  ({:.3} ms each)", e, e / small as f64);
}
