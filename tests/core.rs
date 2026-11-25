use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use unpack::{
    Options, Support, detect,
    pe::{Pe, put32},
    unpack,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn fixture(name: &str) -> Vec<u8> {
    fs::read(root().join("testdata/upx").join(name)).unwrap()
}

fn synthetic(section: &str, marker: &str) -> Vec<u8> {
    let mut data = fixture("pe32.original");
    let pe = Pe::parse(&data).unwrap();
    let stub = pe.sections.last().unwrap();
    data[stub.header..stub.header + 8].fill(0);
    data[stub.header..stub.header + section.len()].copy_from_slice(section.as_bytes());
    put32(&mut data, pe.optional + 16, stub.rva).unwrap();
    put32(&mut data, stub.header + 36, 0xe0000060).unwrap();
    let p = stub.offset as usize;
    data[p] = 0xe9;
    put32(
        &mut data,
        p + 1,
        (i64::from(pe.entry) - i64::from(stub.rva) - 5) as u32,
    )
    .unwrap();
    if section == ".aspack" {
        data[p + 0x4fd..p + 0x503].copy_from_slice(b"\x68\0\0\0\0\xc3");
        put32(&mut data, p + 0x4f4, pe.entry).unwrap();
    }
    let end = data.len();
    data[end - marker.len()..].copy_from_slice(marker.as_bytes());
    data
}

#[test]
fn real_upx_samples_match_official_decoder_and_manifest() {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root().join("testdata/upx/manifest.json")).unwrap())
            .unwrap();
    let samples = manifest["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 8);
    assert_eq!(
        samples.iter().find(|s| s["name"] == "pe32-lzma").unwrap()["method"],
        14
    );
    assert_eq!(
        samples.iter().find(|s| s["name"] == "pe32-filter").unwrap()["filter"],
        "0x16"
    );
    for sample in samples {
        let input = fixture(sample["packed"].as_str().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(&input)),
            sample["packed_sha256"].as_str().unwrap()
        );
        let detection = detect(&input).unwrap().unwrap();
        assert_eq!(detection.name, "UPX");
        assert_eq!(detection.support, Support::Unpack);
        let result = unpack(&input, &Options::default()).unwrap();
        let golden = fixture(sample["unpacked"].as_str().unwrap());
        assert_eq!(result.data, golden, "{}", sample["name"]);
        assert_eq!(
            format!("{:x}", Sha256::digest(&result.data)),
            sample["unpacked_sha256"].as_str().unwrap()
        );
        assert_eq!(result.history.len(), 1);
        assert_eq!(result.history[0].packer_name, "UPX");
        assert!(result.warnings.is_empty());
        assert!(detect(&result.data).unwrap().is_none());
        let original = fixture(sample["original"].as_str().unwrap());
        assert!(detect(&original).unwrap().is_none());
        assert_eq!(
            unpack(&original, &Options::default()).unwrap().data,
            original
        );
    }
}

#[test]
fn all_legacy_recovery_paths_are_explicit_and_preserve_code() {
    for (name, section, marker) in [
        ("ASPack", ".aspack", ""),
        ("FSG", ".packed", "FSG!"),
        ("WinUpack", ".upx0", ""),
        ("Petite", ".petite", ""),
        ("PESpin", ".pespin", ""),
        ("Armadillo", ".EPACK", ""),
        ("Themida", ".themida", ""),
        ("PECompact", ".pec", ""),
        ("NSPack", ".nsp0", ""),
        ("MPRESS", ".MPRESS1", ""),
    ] {
        let input = synthetic(section, marker);
        let detection = detect(&input).unwrap().unwrap();
        assert_eq!(detection.name, name);
        assert_eq!(detection.support, Support::Recovery);
        assert_eq!(
            unpack(&input, &Options::default()).unwrap_err().code,
            "unsupported"
        );
        let result = unpack(
            &input,
            &Options {
                allow_recovery: true,
                ..Options::default()
            },
        )
        .unwrap();
        let output = Pe::parse(&result.data).unwrap();
        assert_eq!(
            output.entry,
            Pe::parse(&fixture("pe32.original")).unwrap().entry
        );
        assert_eq!(result.history.len(), 1);
        assert_eq!(result.warnings.len(), 1);
        let code = &output.sections[0];
        let range = code.offset as usize..(code.offset + code.size) as usize;
        assert_eq!(&input[range.clone()], &result.data[range]);
    }
}

#[test]
fn new_protectors_are_identified_without_claiming_unpacking() {
    for (name, section) in [
        ("VMProtect", ".vmp0"),
        ("Enigma", ".enigma1"),
        ("MEW", "MEW"),
        ("PELock", ".pelock"),
        ("PEBundle", ".pebundl"),
        ("Yoda", ".yP"),
    ] {
        let input = synthetic(section, "");
        let found = detect(&input).unwrap().unwrap();
        assert_eq!(found.name, name);
        assert_eq!(found.support, Support::DetectOnly);
        for recover in [false, true] {
            let error = unpack(
                &input,
                &Options {
                    allow_recovery: recover,
                    ..Options::default()
                },
            )
            .unwrap_err();
            assert_eq!(error.code, "unsupported");
        }
    }
}

#[test]
fn existing_aspack_sample_remains_available_as_limited_recovery() {
    let input = fs::read(root().join("aspack/testdata/aspack_test.exe")).unwrap();
    let found = detect(&input).unwrap().unwrap();
    assert_eq!(found.name, "ASPack");
    assert_eq!(found.version, 1);
    let result = unpack(
        &input,
        &Options {
            allow_recovery: true,
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(Pe::parse(&result.data).unwrap().entry, 0x1b808);
    assert!(!result.warnings.is_empty());
}

#[test]
fn malformed_executables_fail_without_panics_or_large_allocations() {
    let original = fixture("pe32.original");
    for length in 0..1024 {
        let _ = detect(&original[..length]);
    }
    let pe = Pe::parse(&original).unwrap();
    for offset in [
        0x3c,
        pe.optional + 60,
        pe.sections[0].header + 12,
        pe.sections[0].header + 16,
        pe.sections[0].header + 20,
    ] {
        let mut corrupt = original.clone();
        put32(&mut corrupt, offset, u32::MAX).unwrap();
        assert!(detect(&corrupt).is_err(), "offset {offset:x}");
    }
    assert!(detect(b"UPX!").unwrap().is_none());
    assert!(detect(b"\x7fELFUPX!").is_err());
    assert!(detect(b"MZUPX!").is_err());
    let mut bad_elf = fixture("elf64.packed");
    bad_elf[32..40].fill(0xff);
    assert!(detect(&bad_elf).is_err());
    assert!(
        unpack(
            &original,
            &Options {
                max_size: 32,
                ..Options::default()
            }
        )
        .is_err()
    );
}

#[test]
fn recovery_rejects_missing_or_unbacked_oep() {
    let mut input = synthetic(".packed", "FSG!");
    let pe = Pe::parse(&input).unwrap();
    let stub = pe.offset(pe.entry).unwrap();
    input[stub..stub + 8].fill(0);
    let error = unpack(
        &input,
        &Options {
            allow_recovery: true,
            ..Options::default()
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "unsupported");
}

#[test]
fn registered_format_filter_controls_detection_and_unpacking() {
    let input = fixture("pe32.packed");
    let none = Options {
        formats: Some(vec![]),
        ..Options::default()
    };
    let result = unpack(&input, &none).unwrap();
    assert!(result.history.is_empty());
    assert_eq!(result.data, input);
    assert!(
        unpack::detect_filtered(&input, None, Some(&["FSG".into()]))
            .unwrap()
            .is_none()
    );
    assert!(unpack::detect_format(&input, Some("unknown")).is_err());
}

#[test]
fn owned_input_reuses_its_allocation_for_unpacked_files() {
    let input = fixture("pe32.original");
    let address = input.as_ptr();
    let result = unpack::unpack_owned(input, &Options::default()).unwrap();
    assert_eq!(result.data.as_ptr(), address);
    assert!(result.history.is_empty());
}

#[test]
fn recovery_rejects_jumps_into_stub_and_known_packed_storage() {
    for packed_storage in [false, true] {
        let mut input = synthetic(".MPRESS2", "");
        let pe = Pe::parse(&input).unwrap();
        if packed_storage {
            let code = &pe.sections[0];
            input[code.header..code.header + 8].copy_from_slice(b".MPRESS1");
        } else {
            let stub = pe.offset(pe.entry).unwrap();
            put32(&mut input, stub + 1, 27).unwrap(); // E9 targets the same stub section.
        }
        assert_eq!(
            unpack(
                &input,
                &Options {
                    allow_recovery: true,
                    ..Options::default()
                }
            )
            .unwrap_err()
            .code,
            "unsupported"
        );
    }
}
