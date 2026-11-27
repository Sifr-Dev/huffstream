//! `sifr-inflate [--max-output BYTES] [--max-input BYTES] FILE.gz|- [OUTPUT|-]`

use sifr_inflate::{decompress_gzip_reader, DEFAULT_INPUT_LIMIT, DEFAULT_OUTPUT_LIMIT};
use std::fs::File;
use std::io::{self, Read, Write};

/// Names the input file in read errors; the decoder only sees a `Read`.
struct NamedFile {
    file: File,
    name: String,
}

impl Read for NamedFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file
            .read(buffer)
            .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", self.name)))
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let mut limit = DEFAULT_OUTPUT_LIMIT;
    let mut input_limit = DEFAULT_INPUT_LIMIT;
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
            "--max-input" => {
                let Some(value) = args.next() else {
                    exit_usage();
                };
                input_limit = value.parse().unwrap_or_else(|_| {
                    eprintln!("sifr-inflate: --max-input needs a non-negative byte count");
                    std::process::exit(2);
                });
            }
            "-h" | "--help" => {
                println!("usage: sifr-inflate [--max-output BYTES] [--max-input BYTES] FILE.gz|- [OUTPUT|-]\n\nDecode exactly one gzip member (default output limit: {DEFAULT_OUTPUT_LIMIT} bytes, default compressed-input limit: {DEFAULT_INPUT_LIMIT} bytes). The same input limit applies to files and standard input.");
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
    // Files and standard input go through the same bounded reader so one
    // compressed-input limit governs both paths.
    let reader: Box<dyn Read> = if input == "-" {
        Box::new(io::stdin().lock())
    } else {
        match File::open(&input) {
            Ok(file) if file.metadata().map(|meta| !meta.is_dir()).unwrap_or(false) => {
                Box::new(NamedFile {
                    file,
                    name: input.clone(),
                })
            }
            Ok(_) => {
                eprintln!("sifr-inflate: cannot read {input}: is a directory");
                std::process::exit(2);
            }
            Err(error) => {
                eprintln!("sifr-inflate: cannot read {input}: {error}");
                std::process::exit(2);
            }
        }
    };
    let decoded = decompress_gzip_reader(reader, limit, input_limit).unwrap_or_else(|error| {
        eprintln!("sifr-inflate: {error}");
        std::process::exit(1);
    });
    match output.as_deref() {
        Some("-") | None => write_stdout(&decoded),
        Some(path) => fs_write(path, &decoded),
    }
}

fn fs_write(path: &str, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap_or_else(|error| {
        eprintln!("sifr-inflate: cannot write {path}: {error}");
        std::process::exit(2);
    });
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
    eprintln!("usage: sifr-inflate [--max-output BYTES] [--max-input BYTES] FILE.gz|- [OUTPUT|-]");
    std::process::exit(2);
}
