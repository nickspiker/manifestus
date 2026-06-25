//! `vaultinfo` — structural inspector for a manifestus vault, in the spirit of `vsfinfo`.
//!
//! Decodes one ring file (or both mirror sides) from raw bytes: the spine ring, the head's hash chain, the committed commit object, the HAMT tree, and a spec-compliance checklist. NO decryption — manifestus stores only ciphertext; to decrypt values use kete's `keteinfo` (it owns the key derivation + cipher).
//!
//! Exit code: 0 if all spec checks pass, 2 if any fail, 1 on usage/IO error.

use std::env;
use std::process::ExitCode;

use manifestus::host::FileDev;
use manifestus::inspect::{inspect, InspectOptions};

fn main() -> ExitCode {
    let argv: Vec<String> = env::args().skip(1).collect();
    if argv.iter().any(|a| a == "-h" || a == "--help") || argv.is_empty() {
        print_usage();
        return ExitCode::from(if argv.is_empty() { 1 } else { 0 });
    }

    let mut opts = InspectOptions::default();
    let mut files: Vec<String> = Vec::new();
    for arg in &argv {
        match arg.as_str() {
            "--scan" => opts.orphan_scan = true,
            "-v" | "--verbose" => opts.verbose_ring = true,
            "--ring-only" => opts.show_tree = false,
            "--tree-only" => opts.show_ring = false,
            s if s.starts_with('-') => {
                eprintln!("vaultinfo: unknown option {s}");
                print_usage();
                return ExitCode::from(1);
            }
            path => files.push(path.to_string()),
        }
    }

    if files.is_empty() {
        eprintln!("vaultinfo: no vault file given");
        print_usage();
        return ExitCode::from(1);
    }
    if files.len() > 2 {
        eprintln!("vaultinfo: at most two ring files (a mirror pair); got {}", files.len());
        return ExitCode::from(1);
    }

    // Inspect each given ring file independently.
    let mut all_pass = true;
    let mut heads: Vec<(String, Option<(u64, [u8; 32])>)> = Vec::new();
    for path in &files {
        let mut dev = match FileDev::open(std::path::Path::new(path)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("vaultinfo: cannot open {path}: {e}");
                return ExitCode::from(1);
            }
        };
        let report = match inspect(&mut dev, opts) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("vaultinfo: inspect {path} failed: {e}");
                return ExitCode::from(1);
            }
        };
        println!("### {path}");
        print!("{}", report.render(opts));
        println!();
        all_pass &= report.all_checks_pass();
        heads.push((
            path.clone(),
            report.head.as_ref().map(|(_, e)| (e.gen, e.hamt_hash)),
        ));
    }

    // Mirror convergence (two files given).
    if heads.len() == 2 {
        println!("--- mirror convergence ---");
        match (&heads[0].1, &heads[1].1) {
            (Some((ga, ha)), Some((gb, hb))) => {
                if ga == gb && ha == hb {
                    println!("  CONVERGED — both rings at gen {ga}, identical Merkle root");
                } else if ga == gb {
                    println!("  SAME GEN {ga} but DIFFERENT roots — divergence (verified_replicate would reconcile)");
                    all_pass = false;
                } else {
                    let (newer, older) = if ga > gb { (&heads[0].0, &heads[1].0) } else { (&heads[1].0, &heads[0].0) };
                    println!("  DIVERGED — {newer} is newer (gen {}) than {older} (gen {})", ga.max(gb), ga.min(gb));
                }
            }
            _ => {
                println!("  one side has no valid head — cannot compare");
                all_pass = false;
            }
        }
        println!();
    }

    if all_pass {
        ExitCode::from(0)
    } else {
        ExitCode::from(2)
    }
}

fn print_usage() {
    eprintln!("usage: vaultinfo [OPTIONS] FILE [FILE2]");
    eprintln!();
    eprintln!("  FILE       a vault ring file. FILE2 = the mirror sibling (compares heads).");
    eprintln!("  --scan     whole-tract orphan scan (slower; counts sealed-but-unreachable blocks)");
    eprintln!("  -v         per-slot ring detail (don't collapse empty runs)");
    eprintln!("  --ring-only / --tree-only   limit output to one section");
    eprintln!("  -h/--help");
    eprintln!();
    eprintln!("Values are shown as sizes only — manifestus holds ciphertext and never decrypts.");
    eprintln!("To decrypt values, use kete's `keteinfo` with the logical key(s) + vault seed + secret.");
    eprintln!();
    eprintln!("exit: 0 all spec checks pass, 2 a check failed, 1 usage/IO error.");
}
