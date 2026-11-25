//! Ports the old Go SDK's static PE repair mode. This is not a VM or a general decompressor.
use crate::{
    Detection, Error, Result,
    pe::{Pe, put32, u32le},
};

pub fn recover(data: &[u8], detection: &Detection, max_size: usize) -> Result<Vec<u8>> {
    let pe = Pe::parse(data)?;
    let code = pe.entry_code(data)?;
    let oep = if detection.name == "ASPack" {
        let offset = crate::aspack::layout(detection.version)?.oep;
        u32le(code, offset).ok().filter(|oep| pe.valid_oep(*oep))
    } else {
        find_oep(code, &pe)
    }
    .ok_or_else(|| {
        Error::unsupported(format!(
            "{}: no verifiable original entry point",
            detection.name
        ))
    })?;
    let mut output = data.to_vec();
    if detection.name == "ASPack" {
        recover_aspack_blocks(data, &mut output, &pe, code, detection.version, max_size)?;
    }
    put32(&mut output, pe.optional + 16, oep)?;
    repair_imports(&mut output, &pe)?;
    for s in &pe.sections {
        let flags = if s.name.eq_ignore_ascii_case("code") || s.name == ".text" {
            s.flags | 0x6000_0020
        } else {
            s.flags | 0x4000_0000
        };
        put32(&mut output, s.header + 36, flags)?;
    }
    // The old checksum is invalid after any repair; a zero checksum is legal for user PE files.
    put32(&mut output, pe.optional + 64, 0)?;
    Pe::parse(&output)?;
    Ok(output)
}

fn find_oep(code: &[u8], pe: &Pe) -> Option<u32> {
    for i in 0..code.len().saturating_sub(4) {
        let immediate = u32le(code, i + 1).ok()?;
        if code[i] == 0x68 && code.get(i + 5) == Some(&0xc3) {
            let rva = u64::from(immediate)
                .checked_sub(pe.image_base)
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(immediate);
            if pe.valid_oep(rva) {
                return Some(rva);
            }
        }
        // Follow an actual relative tail jump, rather than treating its displacement as an RVA.
        if code[i] == 0xe9 {
            let target = i64::from(pe.entry) + i as i64 + 5 + i64::from(immediate as i32);
            if let Ok(rva) = u32::try_from(target) {
                if pe.valid_oep(rva) {
                    return Some(rva);
                }
            }
        }
    }
    None
}

fn recover_aspack_blocks(
    data: &[u8],
    output: &mut Vec<u8>,
    pe: &Pe,
    code: &[u8],
    version: u32,
    max_size: usize,
) -> Result<()> {
    let layout = crate::aspack::layout(version)?;
    let Some(table) = layout.blocks else {
        return Ok(());
    };
    let section = pe
        .sections
        .iter()
        .find(|s| s.name == ".aspack")
        .ok_or_else(|| Error::invalid("missing ASPack section"))?;
    let compressed =
        &data[section.offset as usize..section.offset as usize + section.size as usize];
    let count = u32le(code, table)? as usize;
    // shortcut: only the legacy block table layout is recovered; other ASPack layouts need a native codec.
    if count == 0 {
        return Ok(());
    }
    if count > 1000 {
        return Err(Error::unsupported(format!(
            "ASPack {}: unsupported block table count",
            layout.name
        )));
    }
    crate::pe::bytes(code, table + 4, count * 16)?;
    let mut decoded_total = 0usize;
    for i in 0..count {
        let p = table + 4 + i * 16;
        let destination = u32le(code, p)?;
        let size = u32le(code, p + 4)? as usize;
        let unpacked_size = u32le(code, p + 8)? as usize;
        let source = u32le(code, p + 12)?;
        if unpacked_size == 0 || unpacked_size > max_size {
            return Err(Error::limit("ASPack block size exceeds limit"));
        }
        decoded_total = decoded_total
            .checked_add(unpacked_size)
            .filter(|v| *v <= max_size)
            .ok_or_else(|| Error::limit("ASPack total decompression exceeds limit"))?;
        let target = pe
            .section_at(destination)
            .ok_or_else(|| Error::invalid("ASPack block destination outside sections"))?;
        let delta = destination - target.rva;
        if delta >= target.size || unpacked_size > (target.size - delta) as usize {
            return Err(Error::invalid(
                "ASPack block exceeds file-backed destination section",
            ));
        }
        let source = source.checked_sub(section.rva).unwrap_or(source) as usize;
        let input = crate::pe::bytes(compressed, source, size)?;
        let unpacked = legacy_lz(input, unpacked_size)?;
        let offset = pe.offset(destination)?;
        let end = offset
            .checked_add(unpacked.len())
            .filter(|v| *v <= max_size)
            .ok_or_else(|| Error::limit("ASPack output exceeds limit"))?;
        if output.len() < end {
            output.resize(end, 0);
        }
        output[offset..end].copy_from_slice(&unpacked);
    }
    Ok(())
}

// Exact legacy literal/back-reference layout; malformed streams are errors instead of zero-filled success.
pub fn legacy_lz(input: &[u8], expected: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(expected.min(65536));
    let (mut pos, mut bits, mut remaining) = (0, 0u8, 0);
    fn bit(input: &[u8], pos: &mut usize, bits: &mut u8, remaining: &mut u8) -> Result<u8> {
        if *remaining == 0 {
            *bits = *input
                .get(*pos)
                .ok_or_else(|| Error::invalid("truncated compressed bitstream"))?;
            *pos += 1;
            *remaining = 8;
        }
        *remaining -= 1;
        Ok((*bits >> *remaining) & 1)
    }
    while output.len() < expected {
        if bit(input, &mut pos, &mut bits, &mut remaining)? == 1 {
            output.push(
                *input
                    .get(pos)
                    .ok_or_else(|| Error::invalid("truncated compressed literal"))?,
            );
            pos += 1;
        } else {
            let raw = crate::pe::u16le(input, pos)? as i16;
            pos += 2;
            let distance = -i32::from(raw);
            let length = (bit(input, &mut pos, &mut bits, &mut remaining)? as usize) * 2
                + bit(input, &mut pos, &mut bits, &mut remaining)? as usize
                + 2;
            if distance <= 0 || distance as usize > output.len() || length > expected - output.len()
            {
                return Err(Error::invalid("invalid compressed back-reference"));
            }
            for _ in 0..length {
                output.push(output[output.len() - distance as usize]);
            }
        }
    }
    Ok(output)
}

fn repair_imports(data: &mut [u8], pe: &Pe) -> Result<()> {
    if pe.directory_count <= 1 {
        return Ok(());
    }
    let current = u32le(data, pe.directories + 8)?;
    if current != 0 && valid_imports(data, pe, current).is_some() {
        return Ok(());
    }
    for s in &pe.sections {
        for delta in (0..(s.size as usize).saturating_sub(39)).step_by(4) {
            let rva = s.rva + delta as u32;
            if let Some(size) = valid_imports(data, pe, rva) {
                put32(data, pe.directories + 8, rva)?;
                put32(data, pe.directories + 12, size)?;
                return Ok(());
            }
        }
    }
    Ok(())
}

fn valid_imports(data: &[u8], pe: &Pe, rva: u32) -> Option<u32> {
    let start = pe.offset(rva).ok()?;
    for i in 0..256 {
        let p = start + i * 20;
        let descriptor = data.get(p..p + 20)?;
        if descriptor.iter().all(|b| *b == 0) {
            return (i > 0).then_some(((i + 1) * 20) as u32);
        }
        let name = pe.offset(u32le(data, p + 12).ok()?).ok()?;
        let suffix = data.get(name..)?;
        let end = suffix.iter().take(256).position(|b| *b == 0)?;
        let name = suffix.get(..end)?;
        if name.len() < 5
            || !name.is_ascii()
            || !name[name.len() - 4..].eq_ignore_ascii_case(b".dll")
        {
            return None;
        }
        pe.offset(u32le(data, p + 16).ok()?).ok()?;
    }
    None
}
