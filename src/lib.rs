//! Zero-dependency, bounded DEFLATE (RFC 1951) and gzip (RFC 1952) decoding.
//! The API accepts one complete member; it does not concatenate members or
//! provide incremental output. Every declared output limit is enforced.

use std::io::Read;

pub const DEFAULT_OUTPUT_LIMIT: usize = 64 * 1024 * 1024;

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl BitReader<'_> {
    fn bit(&mut self) -> Result<u8, String> {
        let byte = *self
            .data
            .get(self.pos / 8)
            .ok_or("unexpected end of data")?;
        let bit = (byte >> (self.pos % 8)) & 1;
        self.pos += 1;
        Ok(bit)
    }

    fn bits(&mut self, n: usize) -> Result<u32, String> {
        let mut value = 0;
        for shift in 0..n {
            value |= u32::from(self.bit()?) << shift;
        }
        Ok(value)
    }

    fn align_byte(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }

    fn consumed_bytes(&self) -> usize {
        self.pos.div_ceil(8)
    }
}

#[derive(Clone)]
struct Huffman {
    // Canonical codes arrive MSB-first, unlike the other DEFLATE bit fields.
    codes: Vec<(u32, u8, u16)>,
}

impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Self, String> {
        let mut counts = [0u16; 16];
        for &length in lengths {
            if length > 15 {
                return Err("code length > 15".into());
            }
            counts[usize::from(length)] += 1;
        }
        counts[0] = 0;
        let mut left = 1i32;
        for count in counts.iter().skip(1) {
            left = left * 2 - i32::from(*count);
            if left < 0 {
                return Err("over-subscribed Huffman tree".into());
            }
        }
        if left > 0 && lengths.iter().filter(|&&length| length != 0).count() != 1 {
            return Err("incomplete Huffman tree".into());
        }

        let mut next = [0u32; 16];
        let mut code = 0u32;
        for length in 1..16 {
            code = (code + u32::from(counts[length - 1])) << 1;
            next[length] = code;
        }
        let mut codes = Vec::new();
        for (symbol, &length) in lengths.iter().enumerate() {
            if length != 0 {
                codes.push((next[usize::from(length)], length, symbol as u16));
                next[usize::from(length)] += 1;
            }
        }
        Ok(Self { codes })
    }

    fn decode(&self, reader: &mut BitReader<'_>) -> Result<u16, String> {
        let mut code = 0u32;
        for length in 1..=15u8 {
            code = (code << 1) | u32::from(reader.bit()?);
            if let Some(&(_, _, symbol)) = self
                .codes
                .iter()
                .find(|&&(candidate, bits, _)| bits == length && candidate == code)
            {
                return Ok(symbol);
            }
        }
        Err("invalid Huffman code".into())
    }
}

fn fixed_literal_lengths() -> [u8; 288] {
    let mut lengths = [0u8; 288];
    for (symbol, length) in lengths.iter_mut().enumerate() {
        *length = match symbol {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    lengths
}

const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const DIST_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DIST_EXTRA: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (index, entry) in table.iter_mut().enumerate() {
        let mut value = index as u32;
        for _ in 0..8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0xEDB8_8320
            } else {
                value >> 1
            };
        }
        *entry = value;
    }
    let mut crc = u32::MAX;
    for &byte in data {
        crc = table[((crc ^ u32::from(byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc ^ u32::MAX
}

fn reserve_output(out: &mut Vec<u8>, additional: usize, limit: usize) -> Result<(), String> {
    let required = out
        .len()
        .checked_add(additional)
        .ok_or("output size overflow")?;
    if required > limit {
        return Err(format!("output exceeds limit of {limit} bytes"));
    }
    out.try_reserve(additional)
        .map_err(|_| "unable to allocate bounded output".to_string())
}

/// Inflate one raw DEFLATE stream and return output plus compressed bytes used.
/// Bits remaining in the final byte are padding, not additional input.
pub fn inflate_raw(data: &[u8], limit: usize) -> Result<(Vec<u8>, usize), String> {
    let mut reader = BitReader { data, pos: 0 };
    let mut out = Vec::new();
    loop {
        let final_block = reader.bit()?;
        let block_type = reader.bits(2)?;
        match block_type {
            0 => {
                reader.align_byte();
                let start = reader.pos / 8;
                let header = reader
                    .data
                    .get(start..start + 4)
                    .ok_or("stored block truncated")?;
                let len = usize::from(u16::from_le_bytes([header[0], header[1]]));
                let nlen = u16::from_le_bytes([header[2], header[3]]);
                if header[..2] != (!nlen).to_le_bytes() {
                    return Err("stored block LEN/NLEN mismatch".into());
                }
                let end = start
                    .checked_add(4 + len)
                    .ok_or("stored block size overflow")?;
                let stored = reader
                    .data
                    .get(start + 4..end)
                    .ok_or("stored block data truncated")?;
                reserve_output(&mut out, len, limit)?;
                out.extend_from_slice(stored);
                reader.pos = end * 8;
            }
            1 | 2 => {
                let (literal, distance) = if block_type == 1 {
                    (
                        Huffman::from_lengths(&fixed_literal_lengths())?,
                        Huffman::from_lengths(&[5u8; 32])?,
                    )
                } else {
                    dynamic_trees(&mut reader)?
                };
                loop {
                    let symbol = literal.decode(&mut reader)?;
                    match symbol {
                        0..=255 => {
                            reserve_output(&mut out, 1, limit)?;
                            out.push(symbol as u8);
                        }
                        256 => break,
                        257..=285 => {
                            let index = usize::from(symbol - 257);
                            let len = usize::from(LENGTH_BASE[index])
                                + reader.bits(usize::from(LENGTH_EXTRA[index]))? as usize;
                            let distance_symbol = usize::from(distance.decode(&mut reader)?);
                            let base = *DIST_BASE
                                .get(distance_symbol)
                                .ok_or("invalid distance code")?;
                            let back = usize::from(base)
                                + reader.bits(usize::from(DIST_EXTRA[distance_symbol]))? as usize;
                            if back > out.len() {
                                return Err("distance too far back".into());
                            }
                            reserve_output(&mut out, len, limit)?;
                            let start = out.len() - back;
                            for offset in 0..len {
                                let byte = out[start + offset];
                                out.push(byte);
                            }
                        }
                        _ => return Err("invalid literal/length code".into()),
                    }
                }
            }
            _ => return Err("reserved BTYPE".into()),
        }
        if final_block == 1 {
            return Ok((out, reader.consumed_bytes()));
        }
    }
}

fn dynamic_trees(reader: &mut BitReader<'_>) -> Result<(Huffman, Huffman), String> {
    let literal_count = reader.bits(5)? as usize + 257;
    let distance_count = reader.bits(5)? as usize + 1;
    let code_count = reader.bits(4)? as usize + 4;
    if literal_count > 286 || distance_count > 32 {
        return Err("too many code lengths".into());
    }
    let mut code_lengths = [0u8; 19];
    for &symbol in &CODE_LENGTH_ORDER[..code_count] {
        code_lengths[symbol] = reader.bits(3)? as u8;
    }
    let code_tree = Huffman::from_lengths(&code_lengths)?;
    if code_tree.codes.is_empty() {
        return Err("empty code-length tree".into());
    }
    let mut lengths = vec![0u8; literal_count + distance_count];
    let mut index = 0;
    while index < lengths.len() {
        let symbol = code_tree.decode(reader)?;
        match symbol {
            0..=15 => {
                lengths[index] = symbol as u8;
                index += 1;
            }
            16 => {
                let previous = *lengths
                    .get(index.wrapping_sub(1))
                    .filter(|_| index != 0)
                    .ok_or("repeat with no previous length")?;
                let count = 3 + reader.bits(2)? as usize;
                let end = index.checked_add(count).ok_or("repeat overflow")?;
                let destination = lengths.get_mut(index..end).ok_or("repeat overflow")?;
                destination.fill(previous);
                index = end;
            }
            17 | 18 => {
                let count = if symbol == 17 {
                    3 + reader.bits(3)? as usize
                } else {
                    11 + reader.bits(7)? as usize
                };
                let end = index.checked_add(count).ok_or("repeat overflow")?;
                let destination = lengths.get_mut(index..end).ok_or("repeat overflow")?;
                destination.fill(0);
                index = end;
            }
            _ => return Err("invalid code-length symbol".into()),
        }
    }
    let literal = Huffman::from_lengths(&lengths[..literal_count])?;
    if lengths.get(256).copied().unwrap_or(0) == 0 {
        return Err("literal tree has no end-of-block code".into());
    }
    let distance = Huffman::from_lengths(&lengths[literal_count..])?;
    Ok((literal, distance))
}

fn take_zero_terminated(data: &[u8], pos: &mut usize, field: &str) -> Result<(), String> {
    let tail = data.get(*pos..).ok_or("truncated gzip header")?;
    let length = tail
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| format!("unterminated gzip {field}"))?;
    *pos += length + 1;
    Ok(())
}

/// Decode exactly one gzip member, enforcing the output limit and all header,
/// trailer, and container invariants. Concatenated members are rejected.
pub fn decompress_gzip(data: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    if data.len() < 10 || data[..2] != [0x1f, 0x8b] || data[2] != 8 {
        return Err("not a gzip stream (bad magic/method)".into());
    }
    let flags = data[3];
    if flags & 0xe0 != 0 {
        return Err("reserved gzip flags".into());
    }
    let mut pos = 10usize;
    if flags & 4 != 0 {
        let bytes = data.get(pos..pos + 2).ok_or("truncated FEXTRA length")?;
        let length = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
        pos = pos.checked_add(2 + length).ok_or("FEXTRA overflow")?;
        if pos > data.len() {
            return Err("truncated FEXTRA".into());
        }
    }
    if flags & 8 != 0 {
        take_zero_terminated(data, &mut pos, "filename")?;
    }
    if flags & 16 != 0 {
        take_zero_terminated(data, &mut pos, "comment")?;
    }
    if flags & 2 != 0 {
        let bytes = data.get(pos..pos + 2).ok_or("truncated FHCRC")?;
        let expected = u16::from_le_bytes([bytes[0], bytes[1]]);
        let actual = (crc32(&data[..pos]) & 0xffff) as u16;
        if expected != actual {
            return Err("gzip header CRC mismatch".into());
        }
        pos += 2;
    }
    let (out, used) = inflate_raw(data.get(pos..).ok_or("truncated gzip payload")?, limit)?;
    let trailer = pos.checked_add(used).ok_or("gzip size overflow")?;
    let trailer_end = trailer.checked_add(8).ok_or("gzip size overflow")?;
    let bytes = data
        .get(trailer..trailer_end)
        .ok_or("truncated gzip trailer")?;
    if data.len() != trailer_end {
        return Err("trailing data or concatenated gzip member".into());
    }
    let expected_crc = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let expected_size = u32::from_le_bytes(bytes[4..].try_into().unwrap());
    let actual_crc = crc32(&out);
    if expected_crc != actual_crc {
        return Err(format!(
            "CRC mismatch: stored {expected_crc:08x}, computed {actual_crc:08x}"
        ));
    }
    if out.len() as u32 != expected_size {
        return Err("ISIZE mismatch".into());
    }
    Ok(out)
}

/// Read an entire gzip member from short or arbitrarily divided reads, then
/// decode it. This is buffered input, not incremental DEFLATE decompression.
pub fn decompress_gzip_reader(
    mut reader: impl Read,
    limit: usize,
    input_limit: usize,
) -> Result<Vec<u8>, String> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read gzip input: {error}"))?;
        if count == 0 {
            break;
        }
        let size = data
            .len()
            .checked_add(count)
            .ok_or("compressed input size overflow")?;
        if size > input_limit {
            return Err(format!(
                "compressed input exceeds limit of {input_limit} bytes"
            ));
        }
        data.try_reserve(count)
            .map_err(|_| "unable to allocate bounded input".to_string())?;
        data.extend_from_slice(&buffer[..count]);
    }
    decompress_gzip(&data, limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn crc_known_vectors() {
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn rejects_invalid_huffman_trees() {
        assert!(Huffman::from_lengths(&[1, 1, 1]).is_err());
        assert!(Huffman::from_lengths(&[2, 2]).is_err());
        assert!(Huffman::from_lengths(&[1]).is_ok());
        assert!(Huffman::from_lengths(&[1, 1]).is_ok());
    }

    #[test]
    fn stored_blocks_and_output_limits() {
        let stored = b"\x01\x05\x00\xfa\xffhello";
        assert_eq!(inflate_raw(stored, 5).unwrap().0, b"hello");
        assert!(inflate_raw(stored, 4).is_err());
        assert!(inflate_raw(b"\x01\x05\x00\x00\x00hello", 10).is_err());
        for end in 0..stored.len() {
            assert!(inflate_raw(&stored[..end], 100).is_err());
        }
    }

    #[test]
    fn fragmented_reader_matches_whole_buffer() {
        let data = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\x01\x05\x00\xfa\xffhello\x86\xa6\x10\x36\x05\x00\x00\x00";
        for split in 0..=data.len() {
            struct Fragments<'a>(&'a [u8], usize);
            impl Read for Fragments<'_> {
                fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
                    if self.1 == self.0.len() {
                        return Ok(0);
                    }
                    let count = buffer.len().min(1);
                    buffer[..count].copy_from_slice(&self.0[self.1..self.1 + count]);
                    self.1 += count;
                    Ok(count)
                }
            }
            assert_eq!(
                decompress_gzip_reader(Fragments(data, 0), 100, 100).unwrap(),
                b"hello"
            );
            assert_eq!(
                decompress_gzip_reader(Fragments(data, split), 100, 100).is_err(),
                split != 0
            );
        }
    }
}
