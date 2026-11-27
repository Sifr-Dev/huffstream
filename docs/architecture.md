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

Incomplete codes follow RFC 1951 section 3.2.7 as zlib implements it: the only
tolerated incomplete literal/length or distance tree holds a single one-bit code,
and a distance tree may be entirely empty when the block has no back-references.
A single code longer than one bit, or a one-bit code beside an incomplete longer
tree, is rejected; a code-length tree must always be complete. This closes a gap
where such trees were accepted and a stream zlib rejects decoded successfully. A
code-length tree with no codes is also rejected.

The gzip parser uses the number of bytes consumed by the final DEFLATE block to
locate its trailer. It rejects truncation, trailing garbage, reserved flags, bad
header/trailer checksums, and **concatenated members**. Raw zlib containers are
not supported. No claim is made to process a sequence of gzip members.

## Streaming and resource limits

The reader API handles arbitrarily fragmented `Read` implementations and the CLI
supports fragmented stdin, but **it buffers the complete input and output**. It
is not an incremental DEFLATE decompressor and does not release output before a
member is fully verified.

The CLI default output limit is 64 MiB (`--max-output BYTES`) and its default
compressed-input limit is also 64 MiB (`--max-input BYTES`). One code path reads
both a named file and standard input, so a single input limit governs both; a
file is no longer unbounded while stdin is capped. The reader never asks for more
than one byte beyond the limit and stops there, so an oversized stream is refused
without being buffered in full. Every stored copy, literal, and match is checked
against the output limit before allocation, and allocation failure is returned as
an error. Both defaults are 64 MiB, so a member must fit inside 64 MiB compressed
and 64 MiB decompressed unless the caller raises both limits.

## Verification

`tests/differential.py` generates independent stored/fixed/dynamic fixtures with
Python `zlib`, random round trips, optional header cases, truncations, corruption,
concatenation/trailing data, output-limit cases, and fragmented OS-pipe writes.
Random mutations are compared to Python gzip: accepted data must be byte-exact,
while rejected data must exit cleanly without partial stdout. The test is not a
formal proof of RFC compliance.

`tests/differential.py` also builds incomplete and complete Huffman tree shapes
bit by bit, asks zlib for the verdict on each, and requires the CLI to agree.
`tests/fixtures` keeps the two regression members that the pre-fix decoder
accepted, the legal one-bit-distance counterpart, and a member whose exact size
exercises the compressed-input boundary for files and stdin alike.

`tests/fuzz.rs` is a deterministic, dependency-free arbitrary-input/mutation
harness. It is **not coverage-guided fuzzing**. GitHub Actions runs unit tests,
differential tests, mutation fuzzing, formatting/lints, and nightly
AddressSanitizer plus MemorySanitizer with rebuilt standard library, and a Miri
job for Rust-level undefined behavior.
