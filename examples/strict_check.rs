//! Strict-open check for a ring pair copy.
use manifestus::{FileDev, Mirror, Vault, HOST_RING_LOG2};
fn main() {
    let mut args = std::env::args().skip(1);
    let pa = args.next().expect("primary");
    let pb = args.next().expect("shadow");
    let a = FileDev::open(std::path::Path::new(&pa)).unwrap();
    let b = FileDev::open(std::path::Path::new(&pb)).unwrap();
    match Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 9_000_000_000_000) {
        Ok(v) => println!("strict open: CLEAN (tract {} blocks, {} live)", v.tract_blocks(), v.live_blocks()),
        Err(e) => println!("strict open: REFUSED ({e})"),
    }
}
