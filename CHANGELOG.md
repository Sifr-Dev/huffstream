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

- The CLI accepts `FILE.gz|- [OUTPUT|-]` and `--max-output BYTES`; its default
  output limit is 64 MiB. gzip input is buffered, not incrementally decoded.
- Exactly one gzip member is accepted. Raw zlib streams and member concatenation
  remain outside the format contract.
