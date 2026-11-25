//! ASPack layouts used by the legacy static recovery path, not a complete ASPack codec.
use crate::{Error, Result};

#[derive(Debug)]
pub struct Layout {
    pub id: u32,
    pub name: &'static str,
    pub signature: usize,
    pub oep: usize,
    pub blocks: Option<usize>,
}

pub const LAYOUTS: &[Layout] = &[
    // In 2.1 the RET at 0x502 overlaps the old guessed 0x500 table. It is not a block count.
    Layout {
        id: 1,
        name: "2.1 layout",
        signature: 0x4fd,
        oep: 0x4f4,
        blocks: None,
    },
    Layout {
        id: 2,
        name: "2.12 layout",
        signature: 0x3b9,
        oep: 0x748,
        blocks: Some(0x57c),
    },
    Layout {
        id: 3,
        name: "OTHER (0x41f) layout",
        signature: 0x41f,
        oep: 0x7a4,
        blocks: Some(0x5d8),
    },
    Layout {
        id: 4,
        name: "2.42 layout",
        signature: 0x42b,
        oep: 0x7b0,
        blocks: Some(0x5e4),
    },
];

pub fn identify(code: &[u8]) -> Result<Option<&'static Layout>> {
    let mut candidates = LAYOUTS.iter().filter(|layout| {
        code.get(layout.signature..layout.signature + 6) == Some(b"\x68\0\0\0\0\xc3")
    });
    let found = candidates.next();
    if candidates.next().is_some() {
        return Err(Error::invalid("ambiguous ASPack version markers"));
    }
    Ok(found)
}

pub fn layout(id: u32) -> Result<&'static Layout> {
    LAYOUTS
        .iter()
        .find(|layout| layout.id == id)
        .ok_or_else(|| Error::unsupported("unknown ASPack recovery layout"))
}
