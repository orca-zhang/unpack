//! Bounds-checked aPLib bitstream decoding and AP32 size/CRC validation.
//! Raw streams have no signature; only AP32 containers participate in automatic detection.
use crate::{Error, Result, pe::u32le};

const HEADER_SIZE: usize = 24;

pub struct Header {
    pub header_size: usize,
    pub packed_size: usize,
    pub unpacked_size: usize,
    packed_crc: u32,
    unpacked_crc: u32,
}

impl Header {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.get(..4) != Some(b"AP32") {
            return Err(Error::invalid("missing AP32 signature"));
        }
        let header = Self {
            header_size: u32le(data, 4)? as usize,
            packed_size: u32le(data, 8)? as usize,
            packed_crc: u32le(data, 12)?,
            unpacked_size: u32le(data, 16)? as usize,
            unpacked_crc: u32le(data, 20)?,
        };
        if header.header_size < HEADER_SIZE || header.packed_size == 0 || header.unpacked_size == 0
        {
            return Err(Error::invalid("invalid AP32 sizes"));
        }
        let end = header
            .header_size
            .checked_add(header.packed_size)
            .ok_or_else(|| Error::invalid("AP32 size overflow"))?;
        if end != data.len() {
            return Err(Error::invalid("AP32 packed size does not match container"));
        }
        Ok(header)
    }
}

pub fn unpack(data: &[u8], max_size: usize) -> Result<Vec<u8>> {
    let header = Header::parse(data)?;
    if header.unpacked_size > max_size {
        return Err(Error::limit("AP32 output exceeds size limit"));
    }
    let packed = &data[header.header_size..];
    if crc32(packed) != header.packed_crc {
        return Err(Error::invalid("AP32 packed CRC mismatch"));
    }
    let output = decompress(packed, header.unpacked_size)?;
    if output.len() != header.unpacked_size {
        return Err(Error::invalid("AP32 unpacked size mismatch"));
    }
    if crc32(&output) != header.unpacked_crc {
        return Err(Error::invalid("AP32 unpacked CRC mismatch"));
    }
    Ok(output)
}

struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
    tag: u8,
    left: u8,
}
impl Bits<'_> {
    fn byte(&mut self) -> Result<u8> {
        let value = *self
            .data
            .get(self.pos)
            .ok_or_else(|| Error::invalid("truncated aPLib stream"))?;
        self.pos += 1;
        Ok(value)
    }
    fn bit(&mut self) -> Result<u8> {
        if self.left == 0 {
            self.tag = self.byte()?;
            self.left = 8;
        }
        self.left -= 1;
        Ok((self.tag >> self.left) & 1)
    }
    fn gamma(&mut self) -> Result<usize> {
        let mut value = 1usize;
        loop {
            value = value
                .checked_mul(2)
                .and_then(|v| v.checked_add(self.bit().ok()? as usize))
                .ok_or_else(|| Error::invalid("invalid aPLib gamma code"))?;
            if self.bit()? == 0 {
                return Ok(value);
            }
        }
    }
}

fn copy_match(output: &mut Vec<u8>, offset: usize, length: usize, limit: usize) -> Result<()> {
    if offset == 0 || offset > output.len() {
        return Err(Error::invalid("invalid aPLib match offset"));
    }
    if length > limit.saturating_sub(output.len()) {
        return Err(Error::limit("aPLib output exceeds size limit"));
    }
    for _ in 0..length {
        output.push(output[output.len() - offset]);
    }
    Ok(())
}

/// Decode a raw aPLib stream, requiring an explicit end marker and rejecting trailing bytes.
/// `max_size` bounds every literal and overlapping match before writing to the output.
pub fn decompress(data: &[u8], max_size: usize) -> Result<Vec<u8>> {
    if max_size == 0 || max_size > 1024 * 1024 * 1024 {
        return Err(Error::limit("invalid aPLib output limit"));
    }
    let mut bits = Bits {
        data,
        pos: 0,
        tag: 0,
        left: 0,
    };
    let mut output = Vec::with_capacity(max_size.min(65536));
    output.push(bits.byte()?);
    let (mut last_offset, mut was_match) = (0usize, false);
    loop {
        if bits.bit()? == 0 {
            if output.len() >= max_size {
                return Err(Error::limit("aPLib output exceeds size limit"));
            }
            output.push(bits.byte()?);
            was_match = false;
        } else if bits.bit()? == 0 {
            let high = bits.gamma()?;
            let (offset, length) = if !was_match && high == 2 {
                (last_offset, bits.gamma()?)
            } else {
                let high = high
                    .checked_sub(if was_match { 2 } else { 3 })
                    .ok_or_else(|| Error::invalid("invalid aPLib match code"))?;
                let offset = high
                    .checked_mul(256)
                    .and_then(|v| v.checked_add(bits.byte().ok()? as usize))
                    .ok_or_else(|| Error::invalid("aPLib offset overflow"))?;
                let adjustment = usize::from(offset >= 32000)
                    + usize::from(offset >= 1280)
                    + if offset < 128 { 2 } else { 0 };
                let length = bits
                    .gamma()?
                    .checked_add(adjustment)
                    .ok_or_else(|| Error::invalid("aPLib match length overflow"))?;
                last_offset = offset;
                (offset, length)
            };
            copy_match(&mut output, offset, length, max_size)?;
            was_match = true;
        } else if bits.bit()? == 0 {
            let code = bits.byte()?;
            let offset = (code >> 1) as usize;
            if offset == 0 {
                if bits.pos != data.len() {
                    return Err(Error::invalid("trailing aPLib data"));
                }
                return Ok(output);
            }
            copy_match(&mut output, offset, 2 + (code & 1) as usize, max_size)?;
            last_offset = offset;
            was_match = true;
        } else {
            let mut offset = 0;
            for _ in 0..4 {
                offset = offset * 2 + bits.bit()? as usize;
            }
            if offset == 0 {
                if output.len() >= max_size {
                    return Err(Error::limit("aPLib output exceeds size limit"));
                }
                output.push(0);
            } else {
                copy_match(&mut output, offset, 1, max_size)?;
            }
            was_match = false;
        }
    }
}

pub fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}
