# Security notes

## Boundary and failure behavior

Malformed and truncated gzip/DEFLATE input is rejected with `Err` in the library
and exit status 1 in the CLI; usage and ordinary I/O errors use exit status 2.
The CLI buffers and validates a complete member before writing output. A closed
stdout pipe is treated as an early consumer exit rather than a Rust panic.

The decoder validates stored-block complement fields, Huffman-tree structure and
symbols, code-length repetitions, back-reference distances, optional header
boundaries and terminators, FHCRC, reserved gzip flags, CRC-32, ISIZE, exact
member length, and compressed-input/output limits where configured.

The CLI default decompressed-output limit is **64 MiB**, overridable with
`--max-output`. The compressed-input limit is also **64 MiB** by default,
overridable with `--max-input`, and it applies identically to a named file and to
standard input; both paths are read through the same bounded reader. The reader
stops one byte past the limit rather than buffering an oversized stream first.
Library callers must choose appropriate limits. Because both defaults are 64 MiB,
a member must fit inside 64 MiB compressed and 64 MiB decompressed; raise both
limits together for larger inputs. Whole-file reads and whole-output buffering can still
require substantial memory; no promise is made about a fixed memory ceiling,
constant-time execution, sandboxing, or protection against all CPU-exhaustion
inputs. Error strings contain format details but no compressed payload contents.

Concatenated gzip members are rejected deliberately; callers must not assume
support for `gzip.decompress`-style member concatenation. No encryption,
authentication, decompression authenticity, path traversal defense beyond normal
caller-selected file paths, or incremental output is provided.

Report vulnerabilities privately through GitHub Security Advisories for this
repository rather than publishing sensitive reproduction details in an issue.
