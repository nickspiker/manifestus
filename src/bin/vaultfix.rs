//! `vaultfix` — explicit salvage for a vault whose committed index carries dangling tombstone pointers (the pre-fix fast-delete bug: a deleted key's pointer surviving into a reap-recycled, plow-reused slot; strict open dies with Seal in walk_live).
//!
//! Opens the given ring file(s) via `Vault::open_repairing`: prunes every stale (zeroed-target) and dangling (reused/corrupt-target) pointer, commits the pruned index as a new generation, and prints exactly what was dropped. Values behind dangling pointers are gone by construction — this recovers everything else.
//!
//! OPERATE ON COPIES. This tool WRITES to the file(s) it is given.
//!
//! Exit: 0 repaired (or nothing to repair), 1 usage/open failure.

use std::env;
use std::process::ExitCode;

use manifestus::host::FileDev;
use manifestus::{Mirror, Vault, HOST_RING_LOG2};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() -> ExitCode {
    let files: Vec<String> = env::args().skip(1).collect();
    if files.is_empty() || files.len() > 2 || files.iter().any(|f| f.starts_with('-')) {
        eprintln!("usage: vaultfix FILE [FILE2]");
        eprintln!("  WRITES a repaired generation into the file(s). Run on copies first; verify with vaultinfo.");
        return ExitCode::from(1);
    }

    let mirror = match files.len() {
        1 => {
            let a = FileDev::open(std::path::Path::new(&files[0])).unwrap();
            Mirror::from_parts(Some(a), None).unwrap()
        }
        _ => {
            let a = FileDev::open(std::path::Path::new(&files[0])).unwrap();
            let b = FileDev::open(std::path::Path::new(&files[1])).unwrap();
            Mirror::new(a, b)
        }
    };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match Vault::open_repairing(mirror, HOST_RING_LOG2, now) {
        Err(e) => {
            eprintln!("vaultfix: repair open failed: {e}");
            ExitCode::from(1)
        }
        Ok((mut vault, report)) => {
            println!("repaired: now at gen {:?}, {} live block(s)", vault.generation(), vault.live_blocks());
            if report.stale.is_empty() && report.dangling.is_empty() {
                println!("nothing pruned — the index was already sound");
            }
            for s in &report.stale {
                println!(
                    "pruned STALE   pointer {}.. @tract {} (route {}..) — deleted key, no data behind it",
                    &hex(&s.hash)[..8],
                    s.lba,
                    &hex(&s.route)[..8]
                );
            }
            for d in &report.dangling {
                let keyinfo = match &d.key {
                    Some(k) => format!("key {}..", &hex(&k[..8])[..16]),
                    None => format!("key unknown (route prefix {}..)", &hex(&d.route)[..8]),
                };
                println!(
                    "pruned DANGLING pointer {}.. @tract {} — VALUE LOST — {} — {}",
                    &hex(&d.hash)[..8],
                    d.lba,
                    keyinfo,
                    d.reason
                );
            }
            let _ = vault.degraded();
            ExitCode::from(0)
        }
    }
}
