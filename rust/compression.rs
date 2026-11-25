//! Native payload decoding. Unframed DEFLATE and LZMA streams are never guessed.
use crate::{Error, Result};
use flate2::bufread::{MultiGzDecoder, ZlibDecoder};
use lzma_rust2::{LzmaReader, XzReader};
use std::io::{self, Read};

const MEMORY_LIMIT_KIB: u32 = 64 * 1024;
pub const NAMES: &[&str] = &["GZIP", "ZLIB", "XZ", "LZMA"];

pub fn identify(data: &[u8], requested: Option<&str>) -> Result<Option<&'static str>> {
    let name = if data.starts_with(b"\x1f\x8b") {
        if data.len() < 10 || data[2] != 8 || data[3] & 0xe0 != 0 {
            return Err(Error::invalid("invalid GZIP header"));
        }
        Some("GZIP")
    } else if data.starts_with(b"\xfd7zXZ\0") {
        if data.len() < 12
            || data[6] != 0
            || data[7] & 0xf0 != 0
            || crc32fast::hash(&data[6..8]) != u32::from_le_bytes(data[8..12].try_into().unwrap())
        {
            return Err(Error::invalid("invalid XZ stream header"));
        }
        Some("XZ")
    } else if data.len() >= 2
        && data[0] & 15 == 8
        && data[0] >> 4 <= 7
        && u16::from_be_bytes([data[0], data[1]]) % 31 == 0
    {
        Some("ZLIB")
    } else if requested == Some("LZMA") {
        validate_lzma_header(data)?;
        Some("LZMA")
    } else {
        None
    };
    Ok(name)
}

fn validate_lzma_header(data: &[u8]) -> Result<()> {
    if data.len() < 14 || data[0] >= 225 || data[13] != 0 {
        return Err(Error::invalid("invalid LZMA-Alone header"));
    }
    Ok(())
}

fn codec_error(error: io::Error) -> Error {
    if error.kind() == io::ErrorKind::OutOfMemory {
        Error::limit("LZMA/XZ decoder exceeds 64 MiB memory limit")
    } else if error.kind() == io::ErrorKind::Unsupported {
        Error::unsupported(format!("unsupported compressed payload: {error}"))
    } else {
        Error::invalid(format!("invalid compressed payload: {error}"))
    }
}

fn read_bounded(reader: &mut impl Read, max_size: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(max_size as u64 + 1)
        .read_to_end(&mut output)
        .map_err(codec_error)?;
    if output.len() > max_size {
        return Err(Error::limit("decoded payload exceeds size limit"));
    }
    Ok(output)
}

pub fn unpack(data: &[u8], format: &str, max_size: usize) -> Result<Vec<u8>> {
    if max_size == 0 || max_size > 1024 * 1024 * 1024 {
        return Err(Error::limit("invalid payload size limit"));
    }
    let (output, trailing) = match format {
        "GZIP" => {
            let mut decoder = MultiGzDecoder::new(data);
            let output = read_bounded(&mut decoder, max_size)?;
            (output, !decoder.into_inner().is_empty())
        }
        "ZLIB" => {
            if data.get(1).is_some_and(|flags| flags & 0x20 != 0) {
                return Err(Error::unsupported(
                    "preset-dictionary ZLIB requires an external dictionary",
                ));
            }
            let mut decoder = ZlibDecoder::new(data);
            let output = read_bounded(&mut decoder, max_size)?;
            (output, !decoder.into_inner().is_empty())
        }
        "XZ" => {
            let mut decoder = XzReader::new_mem_limit(data, true, MEMORY_LIMIT_KIB);
            let output = read_bounded(&mut decoder, max_size)?;
            (output, !decoder.into_inner().is_empty())
        }
        "LZMA" => {
            validate_lzma_header(data)?;
            let size = u64::from_le_bytes(data[5..13].try_into().unwrap());
            if size != u64::MAX && size > max_size as u64 {
                return Err(Error::limit("LZMA declared size exceeds output limit"));
            }
            let mut decoder =
                LzmaReader::new_mem_limit(data, MEMORY_LIMIT_KIB, None).map_err(codec_error)?;
            decoder.set_relaxed_end_condition(false);
            let output = read_bounded(&mut decoder, max_size)?;
            let (rest, buffered) = decoder.into_parts();
            (output, !rest.is_empty() || !buffered.is_empty())
        }
        _ => {
            return Err(Error::unsupported(format!(
                "unknown compression codec: {format}"
            )));
        }
    };
    if trailing {
        return Err(Error::invalid("trailing data after compressed payload"));
    }
    Ok(output)
}
