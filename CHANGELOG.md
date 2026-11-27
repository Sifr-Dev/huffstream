# Changes

## Unreleased — DEFLATE verification branch

### Added

- Public library API with explicit decompressed-output limits and bounded
  buffered reader input.
- Independent Python `zlib`/`gzip` differential fixtures across stored, fixed,
  dynamic, random, truncated, malformed, and corrupt streams.
- Fragmented stdin coverage, deterministic dependency-free mutation fuzzing, and
  stable/nightly sanitizer CI (ASan/MSan) and a nightly Miri job.

### Fixed

- Reject incomplete Huffman codes that were accepted before: a literal or
  distance tree holding one code longer than one bit, and a distance tree with
  one code next to an incomplete longer tree. Only a single one-bit code, or an
  unused all-zero distance tree, is now accepted, matching zlib. Committed
  fixtures in `tests/fixtures` reproduce both accepted-before shapes.
- Apply one compressed-input limit to files and standard input. The CLI file
  path previously had no compressed-input bound at all while stdin was capped at
  64 MiB; `--max-input BYTES` now sets the bound for both, and the defaults match
  the 64 MiB output limit. The reader stops reading at the limit instead of
  buffering the whole oversized stream first. A member larger than 64 MiB
  compressed now needs `--max-input` as well as a suitable `--max-output`.
- Report a missing or unreadable input file with exit status 2, as documented,
  instead of 1.
- Accept the all-zero distance alphabet that RFC 1951 allows in a literal-only
  dynamic block; such streams were previously rejected as an incomplete tree.
- Reject oversubscribed/invalid incomplete Huffman trees and missing end-of-block
  codes instead of allowing invalid compressed streams to run until EOF.
- Check gzip optional-field boundaries, reserved flags, and FHCRC.
- Locate trailers from actual DEFLATE consumption and reject trailing data and
  concatenated members rather than silently treating bytes as a trailer.
- Check output bounds before each allocation/copy and return allocation failures.
- Gracefully handle interrupted/partial stdout writes and closed pipes.

### Changed

- The CLI accepts `FILE.gz|- [OUTPUT|-]`, `--max-output BYTES` and
  `--max-input BYTES`; its default output limit and compressed-input limit are
  both 64 MiB, applied identically to files and stdin. gzip input is buffered,
  not incrementally decoded.
- Exactly one gzip member is accepted. Raw zlib streams and member concatenation
  remain outside the format contract.
