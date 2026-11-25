# Architecture and format scope

`sifr-inflate` is a Rust library and CLI. It has **no third-party Rust or C
dependencies**; Python's standard-library `zlib`/`gzip` modules are test oracles,
not runtime dependencies.

## Decoder

`src/lib.rs` exposes:

- `decompress_gzip(&[u8], output_limit) -> Result<Vec<u8>, String>`
- `decompress_gzip_reader(Read, output_limit, input_limit)`
- `inflate_raw(&[u8], output_limit) -> Result<(Vec<u8>, usize), String>`

The decoder supports RFC 1951 stored, fixed-Huffman, and dynamic-Huffman blocks,
back-references including overlapping copies, RFC 1952 optional header fields,
FHCRC, CRC-32, and ISIZE. Canonical Huffman codes are read most-significant
code-bit first (DEFLATE's packing rule); length/distance extra fields are
least-significant-bit first.

Huffman trees reject oversubscribed and invalid incomplete trees, including an
empty literal tree or a literal tree without end-of-block. Unused distance
symbols 30/31 and literal/length symbols 286/287 are rejected when encountered.
The special RFC 1951 one-code incomplete distance tree is accepted.

The gzip parser uses the number of bytes consumed by the final DEFLATE block to
locate its trailer. It rejects truncation, trailing garbage, reserved flags, bad
header/trailer checksums, and **concatenated members**. Raw zlib containers are
not supported. No claim is made to process a sequence of gzip members.

## Streaming and resource limits

The reader API handles arbitrarily fragmented `Read` implementations and the CLI
supports fragmented stdin, but **it buffers the complete input and output**. It
is not an incremental DEFLATE decompressor and does not release output before a
member is fully verified. The CLI default output limit is 64 MiB and its buffered
stdin limit is 64 MiB; use `--max-output BYTES` to change the decompressed limit.
Every stored copy, literal, and match is checked against the limit before
allocation. Allocation failure is returned as an error. File input is limited by
available memory and filesystem size.

## Verification

`tests/differential.py` generates independent stored/fixed/dynamic fixtures with
Python `zlib`, random round trips, optional header cases, truncations, corruption,
concatenation/trailing data, output-limit cases, and fragmented OS-pipe writes.
Random mutations are compared to Python gzip: accepted data must be byte-exact,
while rejected data must exit cleanly without partial stdout. The test is not a
formal proof of RFC compliance.

`tests/fuzz.rs` is a deterministic, dependency-free arbitrary-input/mutation
harness. It is **not coverage-guided fuzzing**. GitHub Actions runs unit tests,
differential tests, mutation fuzzing, formatting/lints, and nightly
AddressSanitizer plus UndefinedBehaviorSanitizer with rebuilt standard library.
