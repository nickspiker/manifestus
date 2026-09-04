//! Raw block classifier — deliberately does NOT read the spine/head, so it works on a vault whose
//! structure is too broken for the normal inspector to open.
use manifestus::block::{Block, BlockDev, BLOCK, ZERO_BLOCK};
use manifestus::host::FileDev;

fn main() {
    let path = std::env::args().nth(1).expect("usage: corpses <vault.vsf>");
    let total: u64 = std::env::args().nth(2).map(|s| s.parse().unwrap()).unwrap_or(4608);
    let mut dev = FileDev::open(std::path::Path::new(&path)).expect("open");
    let (mut zero, mut ok, mut bad, mut ioerr) = (0u32, 0u32, 0u32, 0u32);
    let mut bad_lbas: Vec<u64> = Vec::new();
    let mut blk: Block = ZERO_BLOCK;
    for i in 0..total {
        if dev.read(i, &mut blk).is_err() { ioerr += 1; continue; }
        if blk.iter().all(|&b| b == 0) { zero += 1; continue; }
        match manifestus::inspect::decode_tract(&blk) {
            Ok(_) => ok += 1,
            Err(_) => { bad += 1; if bad_lbas.len() < 200 { bad_lbas.push(i); } }
        }
    }
    println!("{total} blocks: {zero} zero, {ok} decode-OK, {bad} decode-FAIL, {ioerr} io-err");
    println!("bad lbas (first 200): {bad_lbas:?}");
    for &i in bad_lbas.iter().take(8) {
        let _ = dev.read(i, &mut blk);
        let nz = blk.iter().filter(|&&b| b != 0).count();
        let tail0 = blk.iter().rev().take_while(|&&b| b == 0).count();
        println!("  lba {i}: {nz}/{BLOCK} nonzero, trailing-zero run {tail0}, head {:02x?}", &blk[..16]);
    }
}
