use crate::{Error, Result, pe::Pe};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Support {
    Unpack,
    Recovery,
    DetectOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    pub name: String,
    // Compatibility IDs match the original Go constants; these are not vendor version numbers.
    pub version: u32,
    pub support: Support,
    pub evidence: String,
}

#[derive(Debug, Serialize)]
pub struct Format {
    pub name: &'static str,
    pub support: Support,
    pub sections: &'static [&'static str],
    pub signatures: &'static [&'static str],
}

pub const FORMATS: &[Format] = &[
    Format {
        name: "GZIP",
        support: Support::Unpack,
        sections: &[],
        signatures: &[],
    },
    Format {
        name: "ZLIB",
        support: Support::Unpack,
        sections: &[],
        signatures: &[],
    },
    Format {
        name: "XZ",
        support: Support::Unpack,
        sections: &[],
        signatures: &[],
    },
    Format {
        name: "LZMA",
        support: Support::Unpack,
        sections: &[],
        signatures: &[],
    },
    Format {
        name: "AP32",
        support: Support::Unpack,
        sections: &[],
        signatures: &["AP32"],
    },
    Format {
        name: "UPX",
        support: Support::Unpack,
        sections: &["UPX0", "UPX1"],
        signatures: &["UPX!"],
    },
    Format {
        name: "ASPack",
        support: Support::Recovery,
        sections: &[".aspack"],
        signatures: &[],
    },
    Format {
        name: "FSG",
        support: Support::Recovery,
        sections: &[],
        signatures: &["FSG!", "FSG2"],
    },
    Format {
        name: "WinUpack",
        support: Support::Recovery,
        sections: &[".upx0", ".upx1"],
        signatures: &["WinUpack", "UPack", "WinUpack!"],
    },
    Format {
        name: "Petite",
        support: Support::Recovery,
        sections: &[".petite", "petite", "PETITE"],
        signatures: &["Petite", "petite", "PETITE"],
    },
    Format {
        name: "PESpin",
        support: Support::Recovery,
        sections: &[".pespin", "pespin", "PESpin", "PESPIN"],
        signatures: &["PESpin", "PESPIN"],
    },
    Format {
        name: "Armadillo",
        support: Support::Recovery,
        sections: &[".armadil", ".EPACK", "EPACK"],
        signatures: &["Armadillo", "ARMADILLO", "armadillo"],
    },
    Format {
        name: "Themida",
        support: Support::Recovery,
        sections: &[".themida", "Themida", "THEMIDA"],
        signatures: &["Themida", "THEMIDA", "themida"],
    },
    Format {
        name: "PECompact",
        support: Support::Recovery,
        sections: &[".pec", ".PEC", "PEC", ".pec2", ".PEC2"],
        signatures: &["PECompact", "PEC2", "PEC1"],
    },
    Format {
        name: "NSPack",
        support: Support::Recovery,
        sections: &[".nsp0", ".nsp1", ".NSP0", ".NSP1", "NSP0", "NSP1"],
        signatures: &["NSPack", "NSPACK", "nspack"],
    },
    Format {
        name: "MPRESS",
        support: Support::Recovery,
        sections: &[".MPRESS", ".mpress", "MPRESS", ".MPRESS1", ".MPRESS2"],
        signatures: &["MPRESS", "MPRESS1", "MPRESS2"],
    },
    Format {
        name: "VMProtect",
        support: Support::DetectOnly,
        sections: &[".vmp0", ".vmp1", ".vmp2", ".vmp"],
        signatures: &["VMProtect"],
    },
    Format {
        name: "Enigma",
        support: Support::DetectOnly,
        sections: &[".enigma1", ".enigma2"],
        signatures: &["Enigma Protector", "The Enigma Protector"],
    },
    Format {
        name: "MEW",
        support: Support::DetectOnly,
        sections: &["MEW"],
        signatures: &["MEW11", "MEW 11"],
    },
    Format {
        name: "PELock",
        support: Support::DetectOnly,
        sections: &[".pelock", "PELOCKnt"],
        signatures: &["PELock", "PELOCK"],
    },
    Format {
        name: "PEBundle",
        support: Support::DetectOnly,
        sections: &[".pebundl"],
        signatures: &["PEBundle"],
    },
    Format {
        name: "Yoda",
        support: Support::DetectOnly,
        sections: &[".yP", ".yC"],
        signatures: &["yoda's Protector", "yoda's Crypter"],
    },
];

fn contains(data: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && memchr::memmem::find(data, needle).is_some()
}

pub fn detect(data: &[u8]) -> Result<Option<Detection>> {
    detect_format(data, None)
}

pub fn detect_format(data: &[u8], format: Option<&str>) -> Result<Option<Detection>> {
    detect_filtered(data, format, None)
}

pub fn detect_filtered(
    data: &[u8],
    format: Option<&str>,
    allowed: Option<&[String]>,
) -> Result<Option<Detection>> {
    if let Some(name) = format {
        find_format(name)?;
    }
    if let Some(names) = allowed {
        for name in names {
            find_format(name)?;
        }
    }
    if let Some(name) = crate::compression::identify(data, format)? {
        if format.is_none_or(|requested| requested == name)
            && allowed.is_none_or(|names| names.iter().any(|n| n == name))
        {
            return Ok(Some(Detection {
                name: name.into(),
                version: 1,
                support: Support::Unpack,
                evidence: format!("{name} payload header"),
            }));
        }
        return Ok(None);
    }
    if data.starts_with(b"AP32") {
        crate::aplib::Header::parse(data)?;
        if format.is_none_or(|name| name == "AP32")
            && allowed.is_none_or(|names| names.iter().any(|n| n == "AP32"))
        {
            return Ok(Some(Detection {
                name: "AP32".into(),
                version: 1,
                support: Support::Unpack,
                evidence: "AP32 container header".into(),
            }));
        }
        return Ok(None);
    }
    let pe = if data.starts_with(b"MZ") {
        Some(Pe::parse(data)?)
    } else {
        None
    };
    let other_executable = if data.starts_with(b"\x7fELF") {
        validate_elf(data)?;
        true
    } else if crate::macho::has_magic(data) {
        crate::macho::validate(data)?;
        true
    } else {
        false
    };
    if pe.is_none() && !other_executable {
        return Ok(None);
    }
    let head = &data[..data.len().min(65536)];
    let tail = &data[data.len().saturating_sub(1024)..];
    // Strong section evidence is checked before string evidence, in stable priority order.
    for sections in [true, false] {
        for f in FORMATS {
            if f.name == "AP32"
                || crate::compression::NAMES.contains(&f.name)
                || format.is_some_and(|name| name != f.name)
                || allowed.is_some_and(|names| !names.iter().any(|n| n == f.name))
                || (pe.is_none() && f.name != "UPX")
            {
                continue;
            }
            if sections {
                if let Some(pe) = &pe {
                    if let Some(s) = pe
                        .sections
                        .iter()
                        .find(|s| f.sections.contains(&s.name.as_str()))
                    {
                        let version = if f.name == "ASPack" {
                            crate::aspack::identify(pe.entry_code(data).unwrap_or(&[]))?
                                .map_or(0, |layout| layout.id)
                        } else {
                            1
                        };
                        if version != 0 {
                            return Ok(Some(Detection {
                                name: f.name.into(),
                                version,
                                support: f.support,
                                evidence: format!("section {}", s.name),
                            }));
                        }
                    }
                }
            } else {
                for (i, sig) in f.signatures.iter().enumerate() {
                    if contains(head, sig.as_bytes()) || contains(tail, sig.as_bytes()) {
                        return Ok(Some(Detection {
                            name: f.name.into(),
                            version: (i + 1) as u32,
                            support: f.support,
                            evidence: format!("signature {sig}"),
                        }));
                    }
                }
            }
        }
    }
    Ok(None)
}

pub fn find_format(name: &str) -> Result<&'static Format> {
    FORMATS
        .iter()
        .find(|f| f.name == name)
        .ok_or_else(|| Error::invalid(format!("unknown packer: {name}")))
}

fn validate_elf(data: &[u8]) -> Result<()> {
    use crate::pe::bytes;
    let identity = bytes(data, 0, 16)?;
    let is64 = match identity[4] {
        1 => false,
        2 => true,
        _ => return Err(Error::invalid("invalid ELF class")),
    };
    let little = match identity[5] {
        1 => true,
        2 => false,
        _ => return Err(Error::invalid("invalid ELF encoding")),
    };
    if identity[6] != 1 {
        return Err(Error::invalid("invalid ELF version"));
    }
    let header = if is64 { 64 } else { 52 };
    bytes(data, 0, header)?;
    let read16 = |offset| -> Result<u16> {
        let value = bytes(data, offset, 2)?.try_into().unwrap();
        Ok(if little {
            u16::from_le_bytes(value)
        } else {
            u16::from_be_bytes(value)
        })
    };
    let size_offset = if is64 { 52 } else { 40 };
    if read16(size_offset)? as usize != header {
        return Err(Error::invalid("invalid ELF header size"));
    }
    let offset = if is64 {
        let value = bytes(data, 32, 8)?.try_into().unwrap();
        if little {
            u64::from_le_bytes(value)
        } else {
            u64::from_be_bytes(value)
        }
    } else {
        let value = bytes(data, 28, 4)?.try_into().unwrap();
        u64::from(if little {
            u32::from_le_bytes(value)
        } else {
            u32::from_be_bytes(value)
        })
    };
    let offset = usize::try_from(offset).map_err(|_| Error::invalid("ELF offset overflow"))?;
    let count = read16(size_offset + 4)? as usize;
    let entry_size = read16(size_offset + 2)? as usize;
    if count == 0 || count > 4096 || entry_size != if is64 { 56 } else { 32 } {
        return Err(Error::invalid("invalid ELF program headers"));
    }
    bytes(data, offset, count * entry_size)?;
    Ok(())
}
