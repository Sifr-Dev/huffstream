# Fuzz seeds

`stored.gz` is an RFC 1952 stored-block member containing `hello`. `fixed.gz`
and `dynamic.gz` were generated independently with Python `zlib.compressobj`
using raw DEFLATE (`wbits=-15`), level 6, and respectively `Z_FIXED` and
`Z_DEFAULT_STRATEGY`. Their first raw block has BTYPE 1 and 2; Python gzip
trailer CRC-32 and ISIZE are appended by the generator. These inputs seed
mutation fuzzing and their unmodified round trips are asserted in `fuzz.rs`.
