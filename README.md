<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="sifr-inflate — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# sifr-inflate

Zero-dependency DEFLATE (RFC 1951) and gzip (RFC 1952) decoder in Rust. Stored,
fixed, and dynamic Huffman blocks are implemented from scratch; CRC-32, ISIZE,
and optional gzip header fields including FHCRC are verified. No zlib or
third-party crates are used at runtime or build time.

```sh
cargo build --release
./target/release/sifr-inflate file.gz              # stdout, 64 MiB output limit
./target/release/sifr-inflate file.gz out.bin
./target/release/sifr-inflate --max-output 1048576 file.gz -
cat file.gz | ./target/release/sifr-inflate -      # fragmented stdin supported
```

The CLI buffers complete input and output before writing. It is not an
incremental decoder. Exactly one gzip member is accepted: trailing bytes and
concatenated members are rejected. Raw zlib streams are not supported. See
[architecture](docs/architecture.md), [security and limits](SECURITY.md), and
[release changes](CHANGELOG.md) for the actual contract.

## Verification

Requires Rust and Python 3 (test oracle only):

```sh
cargo test --all-targets --locked
cargo build --locked
python3 tests/differential.py target/debug/sifr-inflate
cargo clippy --all-targets --locked -- -D warnings
cargo fmt -- --check
cargo test --test fuzz --locked -- 100000
```

The Python harness uses independent `zlib`/`gzip` compression to verify 93
stored/fixed/dynamic/random fixtures, six fragmented-pipe chunk sizes, optional
headers, truncations, corruption, output limits, trailing data, and 1000 seeded
mutations. The Rust harness performs deterministic arbitrary-input/mutation
fuzzing; it is not coverage-guided. CI additionally runs nightly ASan/MSan and Miri (Rust has no UBSan backend; Miri detects undefined behavior in Rust semantics).
See [the verification workflow](.github/workflows/verification.yml).

## License

MIT — see [LICENSE](LICENSE). Built from zero.
