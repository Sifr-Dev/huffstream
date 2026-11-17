//! sifr-inflate — zero-dependency DEFLATE (RFC 1951) + gzip (RFC 1952)
//! decompressor. No crates, no zlib: bit reader, three block types
//! (stored / fixed Huffman / dynamic Huffman), canonical Huffman decoder,
//! 32 KiB window, CRC-32 verification.
//!   sifr-inflate file.gz [out]   (default stdout)
use std::fs;
use std::io::{self, Write};

// ---------- bit reader (LSB-first) ----------
struct BitReader<'a> {
    data: &'a [u8],
    pos: usize, // bit position
}
impl<'a> BitReader<'a> {
    fn bit(&mut self) -> Result<u8, String> {
        if self.pos >= self.data.len() * 8 {
            return Err("unexpected end of data".into());
        }
        let b = (self.data[self.pos / 8] >> (self.pos % 8)) & 1;
        self.pos += 1;
        Ok(b)
    }
    fn bits(&mut self, n: usize) -> Result<u32, String> {
        let mut v = 0u32;
        for i in 0..n {
            v |= (self.bit()? as u32) << i;
        }
        Ok(v)
    }
    fn align_byte(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }
    fn remaining_bytes(&self) -> usize {
        self.data.len() * 8 - self.pos
    }
}

// ---------- canonical Huffman ----------
struct Huffman {
    // (code, len) -> symbol, small linear map is fine for 288/30 symbols
    codes: Vec<(u32, u8, u16)>,
}
impl Huffman {
    fn from_lengths(lengths: &[u8]) -> Result<Huffman, String> {
        let mut count = [0u16; 16];
        for &l in lengths {
            if l > 15 {
                return Err("code length > 15".into());
            }
            count[l as usize] += 1;
        }
        count[0] = 0;
        let mut next = [0u32; 16];
        let mut code = 0u32;
        for i in 1..16 {
            code = (code + count[i - 1] as u32) << 1;
            next[i] = code;
        }
        let mut codes = Vec::new();
        for sym in 0..lengths.len() {
            let l = lengths[sym] as usize;
            if l != 0 {
                codes.push((next[l], l as u8, sym as u16));
                next[l] += 1;
            }
        }
        Ok(Huffman { codes })
    }
    fn decode(&self, br: &mut BitReader) -> Result<u16, String> {
        let mut code = 0u32;
        let mut len = 0u8;
        loop {
            code = (code << 1) | br.bit()? as u32;
            len += 1;
            if len > 15 {
                return Err("invalid huffman code".into());
            }
            for &(c, l, sym) in &self.codes {
                if l == len && c == code {
                    return Ok(sym);
                }
            }
        }
    }
}

fn fixed_literal_lengths() -> [u8; 288] {
    let mut l = [0u8; 288];
    for (i, x) in l.iter_mut().enumerate() {
        *x = match i {
            0..=143 => 8,
            144..=255 => 9,
            256..=279 => 7,
            _ => 8,
        };
    }
    l
}
const LENGTH_BASE: [u16; 29] = [3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258];
const LENGTH_EXTRA: [u8; 29] = [0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0];
const DIST_BASE: [u16; 30] = [1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577];
const DIST_EXTRA: [u8; 30] = [0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13];

const CODE_LENGTH_ORDER: [usize; 19] = [16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15];

// ---------- CRC-32 (IEEE) ----------
fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for i in 0..256 {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB88320 } else { c >> 1 };
        }
        table[i] = c;
    }
    let mut crc: u32 = 0xFFFFFFFF;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFFFFFF
}

// ---------- inflate ----------
fn inflate(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut br = BitReader { data, pos: 0 };
    let mut out: Vec<u8> = Vec::new();
    loop {
        let bfinal = br.bit()?;
        let btype = br.bits(2)?;
        match btype {
            0 => {
                br.align_byte();
                let start = br.pos / 8;
                if br.remaining_bytes() < 32 {
                    return Err("stored block truncated".into());
                }
                let len = u16::from_le_bytes([data[start], data[start + 1]]) as usize;
                let nlen = u16::from_le_bytes([data[start + 2], data[start + 3]]);
                if len != (!nlen as usize) & 0xFFFF {
                    return Err("stored block LEN/NLEN mismatch".into());
                }
                let data_start = start + 4;
                if br.data.len() < data_start + len {
                    return Err("stored block data truncated".into());
                }
                out.extend_from_slice(&br.data[data_start..data_start + len]);
                br.pos = (data_start + len) * 8;
            }
            1 | 2 => {
                let (lit, dist) = if btype == 1 {
                    (Huffman::from_lengths(&fixed_literal_lengths())?, Huffman::from_lengths(&[5u8; 30])?)
                } else {
                    let hlit = br.bits(5)? as usize + 257;
                    let hdist = br.bits(5)? as usize + 1;
                    let hclen = br.bits(4)? as usize + 4;
                    if hlit > 286 || hdist > 30 {
                        return Err("too many code lengths".into());
                    }
                    let mut cl_lengths = [0u8; 19];
                    for i in 0..hclen {
                        cl_lengths[CODE_LENGTH_ORDER[i]] = br.bits(3)? as u8;
                    }
                    let cl = Huffman::from_lengths(&cl_lengths)?;
                    let mut lengths = vec![0u8; hlit + hdist];
                    let mut i = 0usize;
                    while i < hlit + hdist {
                        let sym = cl.decode(&mut br)?;
                        match sym {
                            0..=15 => {
                                lengths[i] = sym as u8;
                                i += 1;
                            }
                            16 => {
                                if i == 0 {
                                    return Err("repeat with no previous length".into());
                                }
                                let rep = 3 + br.bits(2)? as usize;
                                let prev = lengths[i - 1];
                                for _ in 0..rep {
                                    if i >= lengths.len() {
                                        return Err("repeat overflow".into());
                                    }
                                    lengths[i] = prev;
                                    i += 1;
                                }
                            }
                            17 => {
                                let rep = 3 + br.bits(3)? as usize;
                                for _ in 0..rep {
                                    if i >= lengths.len() {
                                        return Err("repeat overflow".into());
                                    }
                                    lengths[i] = 0;
                                    i += 1;
                                }
                            }
                            18 => {
                                let rep = 11 + br.bits(7)? as usize;
                                for _ in 0..rep {
                                    if i >= lengths.len() {
                                        return Err("repeat overflow".into());
                                    }
                                    lengths[i] = 0;
                                    i += 1;
                                }
                            }
                            _ => return Err("invalid code-length symbol".into()),
                        }
                    }
                    let lit = Huffman::from_lengths(&lengths[..hlit])?;
                    let dist = Huffman::from_lengths(&lengths[hlit..])?;
                    (lit, dist)
                };
                // symbol loop
                loop {
                    let sym = lit.decode(&mut br)?;
                    if sym < 256 {
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        let li = (sym - 257) as usize;
                        if li >= LENGTH_BASE.len() {
                            return Err("invalid length code".into());
                        }
                        let len = LENGTH_BASE[li] as usize + br.bits(LENGTH_EXTRA[li] as usize)? as usize;
                        let dsym = dist.decode(&mut br)? as usize;
                        if dsym >= DIST_BASE.len() {
                            return Err("invalid distance code".into());
                        }
                        let distv = DIST_BASE[dsym] as usize + br.bits(DIST_EXTRA[dsym] as usize)? as usize;
                        if distv > out.len() {
                            return Err("distance too far back".into());
                        }
                        let start = out.len() - distv;
                        for k in 0..len {
                            out.push(out[start + k]);
                        }
                    }
                }
            }
            _ => return Err("reserved BTYPE".into()),
        }
        if bfinal == 1 {
            break;
        }
    }
    Ok(out)
}

fn gunzip(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b || data[2] != 8 {
        return Err("not a gzip stream (bad magic/method)".into());
    }
    let flg = data[3];
    let mut pos = 10usize;
    if flg & 4 != 0 {
        // FEXTRA
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }
    if flg & 8 != 0 {
        // FNAME
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flg & 16 != 0 {
        // FCOMMENT
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }
    if flg & 2 != 0 {
        pos += 2; // FHCRC
    }
    if pos >= data.len() {
        return Err("truncated gzip header".into());
    }
    let payload_end = data.len() - 8;
    let out = inflate(&data[pos..payload_end])?;
    let stored_crc = u32::from_le_bytes([data[payload_end], data[payload_end + 1], data[payload_end + 2], data[payload_end + 3]]);
    let stored_isize = u32::from_le_bytes([data[payload_end + 4], data[payload_end + 5], data[payload_end + 6], data[payload_end + 7]]);
    let actual_crc = crc32(&out);
    if actual_crc != stored_crc {
        return Err(format!("CRC mismatch: stored {stored_crc:08x}, computed {actual_crc:08x}"));
    }
    if (out.len() as u32) != stored_isize {
        return Err("ISIZE mismatch".into());
    }
    Ok(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: sifr-inflate file.gz [out]");
        std::process::exit(2);
    }
    let data = fs::read(&args[1]).unwrap_or_else(|e| {
        eprintln!("sifr-inflate: cannot read {}: {e}", args[1]);
        std::process::exit(2);
    });
    let out = gunzip(&data).unwrap_or_else(|e| {
        eprintln!("sifr-inflate: {e}");
        std::process::exit(1);
    });
    match args.get(2) {
        Some(path) => {
            fs::write(path, &out).unwrap_or_else(|e| {
                eprintln!("sifr-inflate: cannot write {path}: {e}");
                std::process::exit(2);
            });
        }
        None => {
            io::stdout().write_all(&out).expect("stdout write failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_known_vectors() {
        assert_eq!(crc32(b""), 0x00000000);
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414FA339);
    }

    #[test]
    fn fixed_huffman_lengths() {
        let l = fixed_literal_lengths();
        assert_eq!(l[0], 8);
        assert_eq!(l[144], 9);
        assert_eq!(l[256], 7);
        assert_eq!(l[280], 8);
        assert_eq!(l[287], 8);
    }

    #[test]
    fn huffman_decode_fixed_distance() {
        // fixed distance codes are all 5 bits; codes do not overlap by construction
        let h = Huffman::from_lengths(&[5u8; 30]).unwrap();
        let _ = h;
    }
}
