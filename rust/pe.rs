use crate::{Error, Result};

pub fn bytes(data: &[u8], offset: usize, size: usize) -> Result<&[u8]> {
    offset
        .checked_add(size)
        .and_then(|end| data.get(offset..end))
        .ok_or_else(|| Error::invalid("truncated executable"))
}

pub fn u16le(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        bytes(data, offset, 2)?.try_into().unwrap(),
    ))
}

pub fn u32le(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(data, offset, 4)?.try_into().unwrap(),
    ))
}

pub fn put32(data: &mut [u8], offset: usize, value: u32) -> Result<()> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::invalid("offset overflow"))?;
    data.get_mut(offset..end)
        .ok_or_else(|| Error::invalid("truncated PE field"))?
        .copy_from_slice(&value.to_le_bytes());
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    pub virtual_size: u32,
    pub rva: u32,
    pub size: u32,
    pub offset: u32,
    pub flags: u32,
    pub header: usize,
}

#[derive(Debug, Clone)]
pub struct Pe {
    pub optional: usize,
    pub entry: u32,
    pub image_base: u64,
    pub headers_size: u32,
    pub directories: usize,
    pub directory_count: usize,
    pub is_64: bool,
    pub sections: Vec<Section>,
}

impl Pe {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if bytes(data, 0, 2)? != b"MZ" {
            return Err(Error::invalid("missing DOS signature"));
        }
        let pe = u32le(data, 0x3c)? as usize;
        if bytes(data, pe, 24)?.get(..4) != Some(b"PE\0\0") {
            return Err(Error::invalid("missing PE signature"));
        }
        let count = u16le(data, pe + 6)? as usize;
        if count == 0 || count > 96 {
            return Err(Error::invalid("invalid PE section count"));
        }
        let optional_size = u16le(data, pe + 20)? as usize;
        let optional = pe + 24;
        bytes(data, optional, optional_size)?;
        let is_64 = match u16le(data, optional)? {
            0x10b => false,
            0x20b => true,
            _ => return Err(Error::invalid("unsupported PE optional header")),
        };
        let base_size = if is_64 { 112 } else { 96 };
        if optional_size < base_size {
            return Err(Error::invalid("short PE optional header"));
        }
        let directory_count = u32le(data, optional + base_size - 4)? as usize;
        if directory_count > (optional_size - base_size) / 8 {
            return Err(Error::invalid("PE directories exceed optional header"));
        }
        let image_base = if is_64 {
            u64::from_le_bytes(bytes(data, optional + 24, 8)?.try_into().unwrap())
        } else {
            u32le(data, optional + 28)? as u64
        };
        let mut sections = Vec::with_capacity(count);
        let table = optional + optional_size;
        bytes(data, table, count * 40)?;
        for i in 0..count {
            let header = table + i * 40;
            let name = bytes(data, header, 8)?;
            let name =
                String::from_utf8_lossy(&name[..name.iter().position(|b| *b == 0).unwrap_or(8)])
                    .into_owned();
            let section = Section {
                name,
                virtual_size: u32le(data, header + 8)?,
                rva: u32le(data, header + 12)?,
                size: u32le(data, header + 16)?,
                offset: u32le(data, header + 20)?,
                flags: u32le(data, header + 36)?,
                header,
            };
            section
                .rva
                .checked_add(section.virtual_size.max(section.size))
                .ok_or_else(|| Error::invalid("PE section RVA overflow"))?;
            // Packed sections may have zero raw size, but present raw data must be in the file.
            if section.size != 0 {
                bytes(data, section.offset as usize, section.size as usize)?;
            }
            sections.push(section);
        }
        let headers_size = u32le(data, optional + 60)?;
        if (headers_size as usize) < table + count * 40 || headers_size as usize > data.len() {
            return Err(Error::invalid("invalid PE header size"));
        }
        Ok(Self {
            optional,
            entry: u32le(data, optional + 16)?,
            image_base,
            headers_size,
            directories: optional + base_size,
            directory_count,
            is_64,
            sections,
        })
    }

    pub fn section_at(&self, rva: u32) -> Option<&Section> {
        self.sections
            .iter()
            .find(|s| rva >= s.rva && rva - s.rva < s.virtual_size.max(s.size))
    }

    pub fn offset(&self, rva: u32) -> Result<usize> {
        if rva < self.headers_size {
            return Ok(rva as usize);
        }
        let s = self
            .section_at(rva)
            .ok_or_else(|| Error::invalid("RVA outside PE sections"))?;
        let delta = rva - s.rva;
        if delta >= s.size {
            return Err(Error::invalid("RVA has no file-backed data"));
        }
        Ok(s.offset as usize + delta as usize)
    }

    pub fn entry_code<'a>(&self, data: &'a [u8]) -> Result<&'a [u8]> {
        let offset = self.offset(self.entry)?;
        let section = self
            .section_at(self.entry)
            .ok_or_else(|| Error::invalid("entry point outside sections"))?;
        let end = (section.offset as usize + section.size as usize).min(offset + 8192);
        data.get(offset..end)
            .ok_or_else(|| Error::invalid("invalid entry point"))
    }

    pub fn valid_oep(&self, value: u32) -> bool {
        value != self.entry
            && self.section_at(value).is_some_and(|s| {
                // Static repair cannot establish an OEP inside the stub or known packed storage.
                self.section_at(self.entry)
                    .is_none_or(|stub| stub.header != s.header)
                    && !crate::FORMATS
                        .iter()
                        .any(|format| format.sections.contains(&s.name.as_str()))
                    && (s.flags & 0x2000_0020 != 0
                        || s.name.eq_ignore_ascii_case("code")
                        || s.name == ".text")
            })
            && self.offset(value).is_ok()
    }
}
