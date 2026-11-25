use unpack::{detect, macho};

fn write32(data: &mut [u8], offset: usize, value: u32, little: bool) {
    data[offset..offset + 4].copy_from_slice(&if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
}
fn write64(data: &mut [u8], offset: usize, value: u64, little: bool) {
    data[offset..offset + 8].copy_from_slice(&if little {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    });
}

// Structural fixtures only. Real UPX Mach-O round trips are tested from the manifest in core.rs.
fn thin(little: bool, is64: bool) -> Vec<u8> {
    let mut data = vec![0; 256];
    let header = if is64 { 32 } else { 28 };
    let segment = if is64 { 72 } else { 56 };
    write32(
        &mut data,
        0,
        if is64 { 0xfeedfacf } else { 0xfeedface },
        little,
    );
    write32(&mut data, 4, if is64 { 0x01000007 } else { 7 }, little);
    write32(&mut data, 12, 2, little);
    write32(&mut data, 16, 1, little);
    write32(&mut data, 20, segment, little);
    write32(&mut data, header, if is64 { 0x19 } else { 1 }, little);
    write32(&mut data, header + 4, segment, little);
    data[240..244].copy_from_slice(b"UPX!");
    data
}

fn fat(little: bool, is64: bool) -> Vec<u8> {
    let first = thin(true, true);
    let second = thin(false, false);
    let mut data = vec![0; 8192 + second.len()];
    write32(
        &mut data,
        0,
        if is64 { 0xcafebabf } else { 0xcafebabe },
        little,
    );
    write32(&mut data, 4, 2, little);
    let size = if is64 { 32 } else { 20 };
    for (i, offset, cpu, slice) in [(0, 4096, 0x01000007, first), (1, 8192, 7, second)] {
        let entry = 8 + i * size;
        write32(&mut data, entry, cpu, little);
        if is64 {
            write64(&mut data, entry + 8, offset as u64, little);
            write64(&mut data, entry + 16, slice.len() as u64, little);
            write32(&mut data, entry + 24, 12, little);
        } else {
            write32(&mut data, entry + 8, offset as u32, little);
            write32(&mut data, entry + 12, slice.len() as u32, little);
            write32(&mut data, entry + 16, 12, little);
        }
        data[offset..offset + slice.len()].copy_from_slice(&slice);
    }
    data
}

#[test]
fn thin_and_universal_headers_cover_both_bitnesses_and_byte_orders() {
    for little in [false, true] {
        for is64 in [false, true] {
            for data in [thin(little, is64), fat(little, is64)] {
                assert!(macho::has_magic(&data));
                macho::validate(&data).unwrap();
                assert_eq!(detect(&data).unwrap().unwrap().name, "UPX");
            }
        }
    }
}

#[test]
fn malformed_macho_bounds_and_universal_slices_are_rejected() {
    let valid = thin(true, true);
    for end in 0..104 {
        assert!(macho::validate(&valid[..end]).is_err());
    }
    for offset in [16, 20, 36, 80] {
        let mut invalid = valid.clone();
        write32(&mut invalid, offset, u32::MAX, true);
        assert!(macho::validate(&invalid).is_err(), "offset {offset}");
    }
    let mut invalid_segment = valid.clone();
    write64(&mut invalid_segment, 72, u64::MAX, true);
    write64(&mut invalid_segment, 80, 1, true);
    assert!(macho::validate(&invalid_segment).is_err());
    for (offset, value) in [(4, 33), (16, 0), (20, 0), (24, 32), (8, 7)] {
        let mut invalid = fat(false, false);
        write32(&mut invalid, offset, value, false);
        assert!(macho::validate(&invalid).is_err(), "fat field {offset}");
    }
    let mut overlapping = fat(false, false);
    write32(&mut overlapping, 36, 4096, false);
    assert!(macho::validate(&overlapping).is_err());
}

#[test]
fn java_class_magic_is_not_misclassified_as_universal_macho() {
    let class = b"\xca\xfe\xba\xbe\x00\x00\x00\x34\x00\x01";
    assert!(!macho::has_magic(class));
    assert!(detect(class).unwrap().is_none());
}
