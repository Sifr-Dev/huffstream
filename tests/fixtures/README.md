# Test fixtures

## Mutation seeds

`stored.gz` is an RFC 1952 stored-block member containing `hello`. `fixed.gz`
and `dynamic.gz` were generated independently with Python `zlib.compressobj`
using raw DEFLATE (`wbits=-15`), level 6, and respectively `Z_FIXED` and
`Z_DEFAULT_STRATEGY`. Their first raw block has BTYPE 1 and 2; Python gzip
trailer CRC-32 and ISIZE are appended by the generator. These inputs seed
mutation fuzzing and their unmodified round trips are asserted in `fuzz.rs`.

## Incomplete-Huffman regressions

Each `.raw` file is a bare DEFLATE stream; the matching `.gz` file is the same
stream inside one gzip member. They were built bit by bit rather than produced by
an encoder, because no encoder emits these shapes on purpose, and every
expectation below was confirmed against Python's `zlib`/`gzip`.

- `incomplete_litlen.gz` / `.raw`: dynamic block whose literal/length tree holds
  one two-bit code (end-of-block). RFC 1951 section 3.2.7 only permits an
  incomplete code as a single one-bit distance code, and zlib rejects this with
  `invalid literal/lengths set`. The decoder accepted it before the fix.
- `incomplete_distance.gz` / `.raw`: dynamic block with a complete literal tree
  and a distance tree holding one two-bit code, used by a real match. zlib
  rejects it with `invalid distances set`.
- `single_distance_code.gz`: the legal counterpart of the case above, with the
  lone distance code one bit wide. zlib and this decoder both return `AAAA`.

`tests/differential.py` re-derives the zlib verdict for each shape and adds a
wider crafted matrix, so the committed bytes and the oracle are checked
together.

## Compressed-input limit

`input_limit.gz` is a 4096-byte incompressible payload compressed with Python
`zlib` level 9; the member is 4119 bytes. Its exact size makes the boundary
testable: the file and stdin paths must both accept it at 4119 bytes and both
refuse it at 4118 bytes with the same error.
