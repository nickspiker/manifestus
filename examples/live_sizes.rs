//! List live values by size (key hex + bytes), largest first — for hunting a growth disease.
use manifestus::{FileDev, Mirror, Vault, HOST_RING_LOG2};
fn main() {
    let mut args = std::env::args().skip(1);
    let pa = args.next().expect("primary");
    let pb = args.next().expect("shadow");
    let a = FileDev::open(std::path::Path::new(&pa)).unwrap();
    let b = FileDev::open(std::path::Path::new(&pb)).unwrap();
    let mut v = Vault::open(Mirror::new(a, b), HOST_RING_LOG2, 9_000_000_000_000).unwrap();
    let keys = v.live_keys().unwrap();
    let mut sized: Vec<([u8; 32], usize)> = keys
        .into_iter()
        .map(|k| {
            let len = v.get(&k).ok().flatten().map(|b| b.len()).unwrap_or(0);
            (k, len)
        })
        .collect();
    sized.sort_by_key(|(_, l)| std::cmp::Reverse(*l));
    let total: usize = sized.iter().map(|(_, l)| l).sum();
    println!("{} live values, {} bytes total", sized.len(), total);
    for (k, l) in sized.iter().take(12) {
        println!("{:>10} bytes  {}", l, k.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
}
