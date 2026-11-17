<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset=".github/banner-dark.svg">
    <img alt="sifr-inflate — built from zero" src=".github/banner-light.svg" width="100%">
  </picture>
</p>

# sifr-inflate

zero-dependency DEFLATE (RFC 1951) + gzip (RFC 1952) decompressor in Rust.
stored/fixed/dynamic Huffman from scratch, 32 KiB window, CRC-32 + ISIZE
verified — no zlib, no crates.

```sh
sifr-inflate file.gz           # decompress to stdout
sifr-inflate file.gz out.bin
```

## evidence (this machine, 2026-11-17)

byte-exact vs `zcat` on 21 fixtures: text/binary/empty/unicode/repetitive/large
(8 kB–160 kB), compression levels 1/6/9, plus a stored-block fixture built
with `Z_NO_COMPRESSION` —

```console
OK   18 × gzip -1/-6/-9 fixtures (cmp with zcat)
OK   large_stored.gz (stored blocks, 212 KB, byte-exact)
$ ./sifr-inflate corrupt_deflate_payload.gz   # → CRC mismatch exit 1
$ ./sifr-inflate corrupt_CRC_trailer.gz       # → CRC mismatch exit 1
$ ./sifr-inflate corrupt_ISIZE_trailer.gz     # → ISIZE mismatch exit 1
$ cargo test --release                        # 3 tests pass
```

## honest scope

decompression only (no deflate compressor yet). gzip container format
supported; raw zlib streams are not read (strip the zlib header/adler to use).

## build

```sh
cargo build --release && cargo test --release
```

## license

`MIT` — see `LICENSE`. built from zero.
