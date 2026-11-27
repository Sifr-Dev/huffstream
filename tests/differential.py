#!/usr/bin/env python3
"""Zero-dependency differential oracle for the sifr-inflate CLI (Python 3.8+).
Generates fixtures with the standard-library zlib/gzip implementations; no
compressed golden files or third-party test packages are used.
"""
import argparse
import gzip
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import zlib

SEED = 0x51F12


def raw_deflate(data, level=6, strategy=zlib.Z_DEFAULT_STRATEGY):
    compressor = zlib.compressobj(level, zlib.DEFLATED, -15, 8, strategy)
    return compressor.compress(data) + compressor.flush()


def gzip_with_raw(raw, expected, flags=0, optional=b""):
    header = struct.pack("<BBBBIBB", 0x1F, 0x8B, 8, flags, 0, 0, 3)
    return header + optional + raw + struct.pack("<II", zlib.crc32(expected), len(expected) & 0xFFFFFFFF)


CODE_LENGTH_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]


class BitWriter:
    """Least-significant-bit-first bit packing, as RFC 1951 requires."""

    def __init__(self):
        self.bits = []

    def field(self, value, count):
        for index in range(count):
            self.bits.append((value >> index) & 1)

    def code(self, value, count):
        # Canonical Huffman codes are packed most-significant code bit first.
        for index in range(count - 1, -1, -1):
            self.bits.append((value >> index) & 1)

    def finish(self):
        self.bits.extend([0] * (-len(self.bits) % 8))
        out = bytearray(len(self.bits) // 8)
        for index, bit in enumerate(self.bits):
            out[index // 8] |= bit << (index % 8)
        return bytes(out)


def canonical(lengths):
    counts = [0] * 16
    for length in lengths:
        counts[length] += 1
    counts[0] = 0
    code = 0
    next_code = [0] * 16
    for length in range(1, 16):
        code = (code + counts[length - 1]) << 1
        next_code[length] = code
    table = {}
    for symbol, length in enumerate(lengths):
        if length:
            table[symbol] = (next_code[length], length)
            next_code[length] += 1
    return table


def code_lengths_with(pairs):
    lengths = [0] * 259
    for symbol, length in pairs:
        lengths[symbol] = length
    return lengths


def dynamic_block(literal_lengths, distance_lengths, symbols):
    """Build one final dynamic block; symbols are ('literal', byte) or
    ('match', length_symbol, distance_symbol) without length/distance extras."""
    writer = BitWriter()
    writer.field(1, 1)  # BFINAL
    writer.field(2, 2)  # BTYPE 10: dynamic Huffman
    writer.field(len(literal_lengths) - 257, 5)
    writer.field(len(distance_lengths) - 1, 5)
    code_lengths = [4] * 16 + [0, 0, 0]
    highest = max(index for index, symbol in enumerate(CODE_LENGTH_ORDER) if code_lengths[symbol])
    writer.field(highest + 1 - 4, 4)
    for symbol in CODE_LENGTH_ORDER[:highest + 1]:
        writer.field(code_lengths[symbol], 3)
    code_table = canonical(code_lengths)
    for length in list(literal_lengths) + list(distance_lengths):
        writer.code(*code_table[length])
    literal_table = canonical(literal_lengths)
    distance_table = canonical(distance_lengths)
    for entry in symbols:
        writer.code(*literal_table[entry[1]])
        if entry[0] == "match":
            writer.code(*distance_table[entry[2]])
    if 256 in literal_table:
        writer.code(*literal_table[256])
    return writer.finish()


def crafted_huffman_cases():
    """Hand-built dynamic blocks around RFC 1951 section 3.2.7.

    zlib does not emit these tree shapes, so they are constructed here and then
    judged by zlib itself. Two of them are the regression cases: a literal tree
    with a single two-bit code and a distance tree with a single two-bit code.
    """
    literal_pair = code_lengths_with([(65, 1), (256, 1)])
    four_literal = code_lengths_with([(65, 2), (256, 2), (257, 2), (258, 2)])
    match = ("literal", 65), ("match", 257, 0)
    return [
        ("lit-single-1bit-eob", code_lengths_with([(256, 1)]), [1], []),
        ("lit-single-2bit-eob", code_lengths_with([(256, 2)]), [1], []),
        ("lit-single-15bit-eob", code_lengths_with([(256, 15)]), [1], []),
        ("lit-incomplete-1-2", code_lengths_with([(65, 1), (256, 2)]), [1], []),
        ("lit-complete-a-eob", literal_pair, [1], [("literal", 65)]),
        ("dist-single-1bit-unused", literal_pair, [1], [("literal", 65)]),
        ("dist-single-1bit-used", four_literal, [1], list(match)),
        ("dist-single-2bit-used", four_literal, [2], list(match)),
        ("dist-incomplete-1-2", literal_pair, [1, 2], []),
        ("dist-complete-1-1-unused", literal_pair, [1, 1], [("literal", 65)]),
        ("dist-complete-2-2-unused", literal_pair, [2, 2], [("literal", 65)]),
        ("empty-dist-literal-only", literal_pair, [0], [("literal", 65)]),
        ("empty-litlen", [0] * 257, [1], []),
        ("no-eob", code_lengths_with([(65, 1), (66, 1)]), [1], []),
        ("oversubscribed-litlen", code_lengths_with([(65, 1), (66, 1), (256, 1)]), [1], []),
    ]


def split_writes(binary, payload, expected, label):
    # Byte-at-a-time and awkward boundaries test the CLI's read loop through OS pipes.
    for chunk in (1, 2, 3, 7, 31, 4096):
        process = subprocess.Popen([binary, "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for pos in range(0, len(payload), chunk):
            process.stdin.write(payload[pos:pos + chunk])
        process.stdin.close()
        actual = process.stdout.read()
        errors = process.stderr.read()
        result = process.wait()
        assert result == 0, (label, chunk, errors.decode())
        assert actual == expected, (label, chunk, len(actual))


def run(binary):
    rng = random.Random(SEED)
    fixtures = []
    texts = [b"", b"a", b"hello world\n", "Sifr \u2603 \U0001f980\n".encode(),
             bytes(range(256)), bytes(range(256)) * 5, b"abc" * 25000]
    for index, data in enumerate(texts):
        for level in (0, 1, 6, 9):
            for strategy in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FIXED):
                fixtures.append((f"matrix-{index}-{level}-{strategy}", data,
                                 gzip_with_raw(raw_deflate(data, level, strategy), data)))
    # An explicit stored sequence plus mixed stored/fixed/dynamic blocks.
    stored_data = rng.randbytes(200000)
    compressor = zlib.compressobj(0, zlib.DEFLATED, -15)
    stored = compressor.compress(stored_data) + compressor.flush()
    fixtures.append(("stored-64k-boundaries", stored_data, gzip_with_raw(stored, stored_data)))
    mixed_data = b"prefix" * 30 + rng.randbytes(20000) + b"fixed suffix" * 100
    co = zlib.compressobj(6, zlib.DEFLATED, -15)
    mixed = co.compress(mixed_data[:180]) + co.flush(zlib.Z_FULL_FLUSH)
    mixed += co.compress(mixed_data[180:20180]) + co.flush(zlib.Z_FULL_FLUSH)
    mixed += co.compress(mixed_data[20180:]) + co.flush()
    # Full-flush boundaries produce real multi-block streams. The separate
    # fixed/dynamic matrix covers each Huffman encoding independently.
    assert zlib.decompress(mixed, -15) == mixed_data
    fixtures.append(("mixed-content", mixed_data, gzip_with_raw(mixed, mixed_data)))

    # A dynamic block whose distance alphabet is entirely zero-length is legal
    # when the block contains no back-references (RFC 1951 section 3.2.7).
    # zlib's encoder does not currently emit this shape, so the bytes are fixed
    # here rather than generated. The assertion below is zlib itself accepting
    # the stream, which keeps the case honest if the oracle ever disagrees.
    literal_only = bytes.fromhex(
        "05800104000000400000000000000000000000001c"
        "00000000000000000000000000000000000000c206")
    assert zlib.decompress(literal_only, -15) == b"abc"
    fixtures.append(("literal-only-empty-distance-tree", b"abc",
                     gzip_with_raw(literal_only, b"abc")))

    # Fixed streams from tests/fixtures carry the regression cases and the
    # legal one-code counterpart; their committed bytes are also decoded here.
    fixture_dir = Path(__file__).resolve().parent / "fixtures"
    incomplete = []
    for name, minimum in (("incomplete_litlen.gz", 1), ("incomplete_distance.gz", 1)):
        payload = (fixture_dir / name).read_bytes()
        try:
            gzip.decompress(payload)
        except (OSError, EOFError, zlib.error):
            pass
        else:
            raise AssertionError("python gzip oracle accepted " + name)
        incomplete.append((name, payload))
    legal = (fixture_dir / "single_distance_code.gz").read_bytes()
    assert gzip.decompress(legal) == b"AAAA"
    fixtures.append(("single-one-bit-distance-code", b"AAAA", legal))

    for index in range(35):
        size = rng.randrange(0, 140000)
        data = rng.randbytes(size) if index % 2 else bytes(rng.randrange(256) for _ in range(size))
        level = rng.choice([0, 1, 6, 9])
        fixtures.append((f"random-{index}", data, gzip_with_raw(raw_deflate(data, level), data)))

    with tempfile.TemporaryDirectory(prefix="sifr-inflate-test-") as temporary:
        directory = Path(temporary)
        for label, expected, payload in fixtures:
            path = directory / (label + ".gz")
            path.write_bytes(payload)
            actual = directory / "actual"
            subprocess.run([binary, "--max-output", str(max(1, len(expected))), str(path), str(actual)], check=True, capture_output=True)
            assert actual.read_bytes() == expected, label
            if zlib.decompress(raw_deflate(expected), -15) != expected:
                raise AssertionError("zlib oracle failed: " + label)
        print(f"PASS {len(fixtures)} zlib/gzip stored/fixed/dynamic fixtures (seed {SEED})")

        # Every crafted block must agree with the zlib oracle: accepted input
        # must decode to the same bytes, rejected input must fail cleanly.
        for label, literal_lengths, distance_lengths, symbols in crafted_huffman_cases():
            raw = dynamic_block(literal_lengths, distance_lengths, symbols)
            try:
                expected = zlib.decompress(raw, -15)
            except zlib.error:
                expect_failure(binary, gzip_with_raw(raw, b""), directory, "huffman-" + label)
            else:
                path = directory / ("huffman-" + label + ".gz")
                payload = gzip_with_raw(raw, expected)
                path.write_bytes(payload)
                result = subprocess.run([binary, "--max-output", str(max(1, len(expected))), str(path)], capture_output=True)
                assert result.returncode == 0, (label, result.stderr)
                assert result.stdout == expected, (label, result.stdout, expected)
        print(f"PASS {len(crafted_huffman_cases())} crafted incomplete/complete Huffman blocks agree with zlib")

        for name, payload in incomplete:
            expect_failure(binary, payload, directory, "fixture-" + name)
        print("PASS committed incomplete-Huffman fixtures are rejected by CLI and Python gzip")

        # Same compressed-input limit for a file and for stdin, including the
        # exact boundary: the CLI must refuse both paths identically.
        limited = (fixture_dir / "input_limit.gz").read_bytes()
        exact = str(len(limited))
        for extra, label in ((0, "one-under-limit"), (1, "exactly-at-limit")):
            limit = str(len(limited) - 1 + extra)
            limited_path = directory / ("input-limit-" + label + ".gz")
            limited_path.write_bytes(limited)
            for source in ("file", "stdin"):
                if source == "file":
                    result = subprocess.run([binary, "--max-input", limit, str(limited_path)], capture_output=True)
                else:
                    result = subprocess.run([binary, "--max-input", limit, "-"], input=limited, capture_output=True)
                if extra == 0:
                    assert result.returncode == 1, (label, source, result.returncode)
                    assert result.stdout == b""
                    assert b"compressed input exceeds limit of " + limit.encode() in result.stderr, (label, source, result.stderr)
                else:
                    assert result.returncode == 0, (label, source, result.returncode, result.stderr)
                    assert result.stdout == gzip.decompress(limited)
        print("PASS identical compressed-input limits for file and stdin around the boundary")

        split_writes(binary, fixtures[7][2], fixtures[7][1], "fragmented")
        print("PASS fragmented stdin at 1/2/3/7/31/4096-byte boundaries")

        # Valid optional fields, including the RFC 1952 low-16-bit header CRC.
        optional = struct.pack("<H", 5) + b"extra" + b"name.bin\0" + b"comment\0"
        without_crc = gzip_with_raw(raw_deflate(b"header"), b"header", 4 | 8 | 16, optional)
        crc = zlib.crc32(without_crc[:10 + len(optional)]) & 0xFFFF
        with_crc = without_crc[:10 + len(optional)] + struct.pack("<H", crc) + without_crc[10 + len(optional):]
        # Set FHCRC only after computing the original optional-field header.
        base = bytearray(with_crc)
        base[3] |= 2
        base[10 + len(optional):12 + len(optional)] = struct.pack("<H", zlib.crc32(base[:10 + len(optional)]) & 0xFFFF)
        header_path = directory / "header.gz"
        header_path.write_bytes(base)
        subprocess.run([binary, str(header_path)], check=True, capture_output=True)
        bad_header = bytearray(base)
        bad_header[10 + len(optional)] ^= 1
        expect_failure(binary, bytes(bad_header), directory, "bad FHCRC")

        baseline = gzip_with_raw(raw_deflate(b"payload"), b"payload")
        malformed = [
            b"", b"not gzip", baseline[:9], baseline[:-1], baseline + b"junk",
            baseline + gzip.compress(b"second", mtime=0),
            bytes([0x1F, 0x8B, 8, 0xE0]) + baseline[4:],
            bytes([0x1F, 0x8B, 8, 4]) + baseline[4:10] + b"\xff",
            bytes([0x1F, 0x8B, 8, 8]) + baseline[4:10] + b"unterminated",
            b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ]
        for index in range(1, len(baseline)):
            malformed.append(baseline[:index])
        known_invalid = len(malformed)
        for index, payload in enumerate(malformed):
            expect_failure(binary, payload, directory, f"invalid-{index}")
        mutations = 0
        for index in range(1000):
            data = bytearray(baseline)
            for _ in range(rng.randrange(1, 5)):
                data[rng.randrange(len(data))] ^= rng.randrange(1, 256)
            if rng.random() < 0.25:
                del data[rng.randrange(len(data)):]
            path = directory / f"mutation-{index}.gz"
            path.write_bytes(data)
            result = subprocess.run([binary, str(path)], capture_output=True)
            assert result.returncode in (0, 1), (index, result.returncode, result.stderr)
            assert b"panicked" not in result.stderr, (index, result.stderr)
            # A header-only mutation can remain a valid member. Any accepted
            # mutation must exactly match the independent Python gzip oracle.
            if result.returncode == 0:
                assert result.stdout == gzip.decompress(data), index
            else:
                assert result.stdout == b"", (index, "partial output")
            mutations += 1
        print(f"PASS {known_invalid} malformed/truncated cases; {mutations} mutations safe and oracle-consistent")

        # Exceeding a small limit fails before producing any stdout output.
        large_path = directory / "output-limit.gz"
        large_path.write_bytes(gzip_with_raw(raw_deflate(b"0123456789"), b"0123456789"))
        result = subprocess.run([binary, "--max-output", "6", str(large_path)], capture_output=True)
        assert result.returncode == 1 and b"output exceeds limit" in result.stderr
        print("PASS output limit and single-member/no-trailing-data behavior")


def expect_failure(binary, payload, directory, label):
    path = directory / (label + ".gz")
    path.write_bytes(payload)
    result = subprocess.run([binary, str(path)], capture_output=True)
    assert result.returncode == 1, (label, result.returncode, result.stderr)
    assert result.stdout == b"", (label, "partial output")
    assert b"panicked" not in result.stderr, (label, result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    arguments = parser.parse_args()
    run(os.path.abspath(arguments.binary))
