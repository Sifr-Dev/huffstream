//! `sifr-inflate [--max-output BYTES] FILE.gz|- [OUTPUT|-]`

use sifr_inflate::{decompress_gzip, decompress_gzip_reader, DEFAULT_OUTPUT_LIMIT};
use std::fs;
use std::io::{self, Write};

fn main() {
    let mut args = std::env::args().skip(1);
    let mut limit = DEFAULT_OUTPUT_LIMIT;
    let mut input = None;
    let mut output = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--max-output" => {
                let Some(value) = args.next() else {
                    exit_usage();
                };
                limit = value.parse().unwrap_or_else(|_| {
                    eprintln!("sifr-inflate: --max-output needs a non-negative byte count");
                    std::process::exit(2);
                });
            }
            "-h" | "--help" => {
                println!("usage: sifr-inflate [--max-output BYTES] FILE.gz|- [OUTPUT|-]\n\nDecode exactly one gzip member (default output limit: {DEFAULT_OUTPUT_LIMIT} bytes).");
                return;
            }
            _ if argument.starts_with("--") => exit_usage(),
            _ if input.is_none() => input = Some(argument),
            _ if output.is_none() => output = Some(argument),
            _ => exit_usage(),
        }
    }
    let Some(input) = input else {
        exit_usage();
    };
    let decoded = if input == "-" {
        decompress_gzip_reader(io::stdin().lock(), limit, DEFAULT_OUTPUT_LIMIT)
    } else {
        fs::read(&input)
            .map_err(|error| format!("cannot read {input}: {error}"))
            .and_then(|data| decompress_gzip(&data, limit))
    }
    .unwrap_or_else(|error| {
        eprintln!("sifr-inflate: {error}");
        std::process::exit(1);
    });
    match output.as_deref() {
        Some("-") | None => write_stdout(&decoded),
        Some(path) => fs::write(path, &decoded).unwrap_or_else(|error| {
            eprintln!("sifr-inflate: cannot write {path}: {error}");
            std::process::exit(2);
        }),
    }
}

fn write_stdout(bytes: &[u8]) {
    let mut stdout = io::stdout().lock();
    let mut remaining = bytes;
    while !remaining.is_empty() {
        match stdout.write(remaining) {
            Ok(0) => break,
            Ok(count) => remaining = &remaining[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => return,
            Err(error) => {
                eprintln!("sifr-inflate: cannot write stdout: {error}");
                std::process::exit(2);
            }
        }
    }
}

fn exit_usage() -> ! {
    eprintln!("usage: sifr-inflate [--max-output BYTES] FILE.gz|- [OUTPUT|-]");
    std::process::exit(2);
}
