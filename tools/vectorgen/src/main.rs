//! `vectorgen generate|check [--root DIR]`
//!
//! `generate` writes the generated vector files and `MANIFEST.json`.
//! `check` regenerates in memory and compares byte for byte with the files on
//! disk, then verifies `MANIFEST.json`. Both default to `--root vectors`.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

fn usage() -> ExitCode {
    eprintln!("usage: vectorgen generate|check [--root DIR]");
    ExitCode::from(2)
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        return usage();
    };
    let mut root = PathBuf::from("vectors");
    while let Some(arg) = args.next() {
        match (arg.as_str(), args.next()) {
            ("--root", Some(dir)) => root = PathBuf::from(dir),
            _ => return usage(),
        }
    }
    match command.as_str() {
        "generate" => match ferret_vectorgen::generate(&root) {
            Ok(()) => {
                println!("vectorgen: generated {}", root.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("vectorgen: {e}");
                ExitCode::FAILURE
            }
        },
        "check" => match ferret_vectorgen::check(&root) {
            Ok(()) => {
                println!("vectorgen: {} is up to date", root.display());
                ExitCode::SUCCESS
            }
            Err(problems) => {
                for problem in problems {
                    eprintln!("vectorgen: {problem}");
                }
                ExitCode::FAILURE
            }
        },
        _ => usage(),
    }
}
