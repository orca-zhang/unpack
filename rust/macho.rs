//! Structural validation for Mach-O load commands and universal containers.
use crate::{Error, Result, pe::bytes};

pub fn has_magic(data: &[u8]) -> bool {
    // Java class files share CAFEBABE; their version field is not a plausible fat-slice count.
    if data.starts_with(b"\xca\xfe\xba\xbe")
        && data.len() >= 8
        && u32::from_be_bytes(data[4..8].try_into().unwrap()) > 32
    {
        return false;
    }
    matches!(
        data.get(..4),
        Some(
            b"\xce\xfa\xed\xfe"
                | b"\xcf\xfa\xed\xfe"
                | b"\xfe\xed\xfa\xce"
                | b"\xfe\xed\xfa\xcf"
                | b"\xca\xfe\xba\xbe"
                | b"\xbe\xba\xfe\xca"
                | b"\xca\xfe\xba\xbf"
                | b"\xbf\xba\xfe\xca"
        )
    )
}

struct Reader<'a> {
    data: &'a [u8],
    little: bool,
}
impl Reader<'_> {
    fn u32(&self, offset: usize) -> Result<u32> {
        let value = bytes(self.data, offset, 4)?.try_into().unwrap();
        Ok(if self.little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        })
    }
    fn u64(&self, offset: usize) -> Result<u64> {
        let value = bytes(self.data, offset, 8)?.try_into().unwrap();
        Ok(if self.little {
            u64::from_le_bytes(value)
        } else {
            u64::from_be_bytes(value)
        })
    }
}

pub fn validate(data: &[u8]) -> Result<()> {
    match bytes(data, 0, 4)? {
        b"\xca\xfe\xba\xbe" | b"\xbe\xba\xfe\xca" | b"\xca\xfe\xba\xbf" | b"\xbf\xba\xfe\xca" => {
            validate_fat(data)
        }
        _ => validate_thin(data).map(|_| ()),
    }
}

fn validate_thin(data: &[u8]) -> Result<u32> {
    let (little, is64) = match bytes(data, 0, 4)? {
        b"\xce\xfa\xed\xfe" => (true, false),
        b"\xcf\xfa\xed\xfe" => (true, true),
        b"\xfe\xed\xfa\xce" => (false, false),
        b"\xfe\xed\xfa\xcf" => (false, true),
        _ => return Err(Error::invalid("invalid thin Mach-O signature")),
    };
    let reader = Reader { data, little };
    let header = if is64 { 32 } else { 28 };
    bytes(data, 0, header)?;
    if !matches!(reader.u32(12)?, 2 | 6 | 8) {
        return Err(Error::invalid("Mach-O is not executable, dylib or bundle"));
    }
    let count = reader.u32(16)? as usize;
    let size = reader.u32(20)? as usize;
    if count == 0 || count > 4096 || size < count * 8 {
        return Err(Error::invalid("invalid Mach-O load command count"));
    }
    bytes(data, header, size)?;
    let end = header + size;
    let mut command = header;
    for _ in 0..count {
        let kind = reader.u32(command)?;
        let size = reader.u32(command + 4)? as usize;
        if size < 8 || size % if is64 { 8 } else { 4 } != 0 || size > end - command {
            return Err(Error::invalid("invalid Mach-O load command size"));
        }
        let segment = match kind {
            1 => Some((56, 68, 48)),
            0x19 => Some((72, 80, 64)),
            _ => None,
        };
        if (kind == 1 && is64) || (kind == 0x19 && !is64) {
            return Err(Error::invalid("Mach-O segment bitness mismatch"));
        }
        if let Some((base, section_size, sections_field)) = segment {
            if size < base {
                return Err(Error::invalid("short Mach-O segment command"));
            }
            let sections = reader.u32(command + sections_field)? as usize;
            if sections > (size - base) / section_size {
                return Err(Error::invalid("Mach-O sections exceed segment command"));
            }
            let (offset, length) = if kind == 1 {
                (
                    u64::from(reader.u32(command + 32)?),
                    u64::from(reader.u32(command + 36)?),
                )
            } else {
                (reader.u64(command + 40)?, reader.u64(command + 48)?)
            };
            if length != 0 {
                checked_slice(data, offset, length)?;
            }
        }
        command += size;
    }
    if command != end {
        return Err(Error::invalid("Mach-O load command size mismatch"));
    }
    reader.u32(4)
}

fn checked_slice(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    let offset = usize::try_from(offset).map_err(|_| Error::invalid("Mach-O offset overflow"))?;
    let size = usize::try_from(size).map_err(|_| Error::invalid("Mach-O size overflow"))?;
    bytes(data, offset, size)
}

fn validate_fat(data: &[u8]) -> Result<()> {
    let little = matches!(
        data.get(..4),
        Some(b"\xbe\xba\xfe\xca" | b"\xbf\xba\xfe\xca")
    );
    let is64 = matches!(
        data.get(..4),
        Some(b"\xca\xfe\xba\xbf" | b"\xbf\xba\xfe\xca")
    );
    let reader = Reader { data, little };
    let count = reader.u32(4)? as usize;
    if count == 0 || count > 32 {
        return Err(Error::invalid(
            "invalid universal Mach-O architecture count",
        ));
    }
    let entry_size = if is64 { 32 } else { 20 };
    let header_size = 8 + count * entry_size;
    bytes(data, 0, header_size)?;
    let mut ranges = Vec::with_capacity(count);
    for i in 0..count {
        let entry = 8 + i * entry_size;
        let (offset, size, align) = if is64 {
            (
                reader.u64(entry + 8)?,
                reader.u64(entry + 16)?,
                reader.u32(entry + 24)?,
            )
        } else {
            (
                u64::from(reader.u32(entry + 8)?),
                u64::from(reader.u32(entry + 12)?),
                reader.u32(entry + 16)?,
            )
        };
        let end = offset
            .checked_add(size)
            .ok_or_else(|| Error::invalid("universal Mach-O size overflow"))?;
        if size == 0
            || offset < header_size as u64
            || align > 31
            || offset % (1u64 << align) != 0
            || ranges.iter().any(|&(a, b)| offset < b && a < end)
        {
            return Err(Error::invalid(
                "invalid or overlapping universal Mach-O slices",
            ));
        }
        let slice = checked_slice(data, offset, size)?;
        if validate_thin(slice)? != reader.u32(entry)? {
            return Err(Error::invalid("universal Mach-O CPU type mismatch"));
        }
        ranges.push((offset, end));
    }
    Ok(())
}
