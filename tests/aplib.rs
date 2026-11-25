use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use unpack::{Options, aplib, detect, unpack, unpack_format};

fn fixture(name: &str) -> Vec<u8> {
    fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/aplib")
            .join(name),
    )
    .unwrap()
}

#[test]
fn independent_aplib_vectors_and_crc_checks() {
    let manifest: serde_json::Value = serde_json::from_slice(&fixture("manifest.json")).unwrap();
    let samples = manifest["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 5);
    for sample in samples {
        let input = fixture(sample["packed"].as_str().unwrap());
        let expected = fixture(sample["unpacked"].as_str().unwrap());
        assert_eq!(
            format!("{:x}", Sha256::digest(&input)),
            sample["packed_sha256"].as_str().unwrap()
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&expected)),
            sample["unpacked_sha256"].as_str().unwrap()
        );
        let raw = fixture(sample["raw"].as_str().unwrap());
        assert_eq!(aplib::decompress(&raw, expected.len()).unwrap(), expected);
        assert_eq!(aplib::unpack(&input, expected.len()).unwrap(), expected);
        assert_eq!(detect(&input).unwrap().unwrap().name, "AP32");
        let named = unpack_format(&input, &Options::default(), Some("AP32")).unwrap();
        assert_eq!(named.data, expected);
        assert_eq!(named.history.len(), 1);
        assert!(named.warnings.is_empty());
        assert!(aplib::unpack(&input, expected.len() - 1).is_err());
    }
    assert_eq!(aplib::crc32(b"123456789"), 0xcbf43926);
}

#[test]
fn genuine_container_chain_reaches_real_upx_output() {
    let input = fixture("upx.ap32");
    let result = unpack(&input, &Options::default()).unwrap();
    let expected =
        fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/upx/pe32.unpacked"))
            .unwrap();
    assert_eq!(result.data, expected);
    assert_eq!(
        result
            .history
            .iter()
            .map(|l| l.packer_name.as_str())
            .collect::<Vec<_>>(),
        ["AP32", "UPX"]
    );
    let one = unpack(
        &input,
        &Options {
            max_depth: 1,
            ..Options::default()
        },
    )
    .unwrap();
    assert_eq!(one.data, fixture("upx.unpacked"));
    assert_eq!(one.history.len(), 1);
    let native = unpack(&fixture("nested.ap32"), &Options::default()).unwrap();
    assert_eq!(native.data, fixture("tokens.unpacked"));
    assert_eq!(native.history.len(), 2);
}

#[test]
fn malformed_aplib_and_ap32_are_bounded_errors() {
    let valid = fixture("tokens.ap32");
    for end in 0..valid.len() {
        assert!(aplib::unpack(&valid[..end], 1024).is_err());
    }
    for offset in [4, 8, 12, 16, 20, valid.len() - 1] {
        let mut corrupt = valid.clone();
        corrupt[offset] ^= 0x80;
        assert!(aplib::unpack(&corrupt, 1024).is_err(), "offset {offset}");
    }
    for input in [
        vec![],
        vec![b'A'],
        vec![b'A', 0xc0, 0xfe],
        vec![b'A', 0xff, 0xff],
        vec![b'A', 0x80, 0xff],
    ] {
        assert!(aplib::decompress(&input, 64).is_err());
    }
    let mut trailing = fixture("tokens.aplib");
    trailing.push(0);
    assert!(aplib::decompress(&trailing, 1024).is_err());
    assert!(aplib::decompress(&fixture("tokens.aplib"), 0).is_err());
    assert!(aplib::decompress(&fixture("tokens.aplib"), usize::MAX).is_err());
}

#[test]
fn an_ap32_string_inside_a_pe_is_not_a_container() {
    let mut input =
        fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/upx/pe32.original"))
            .unwrap();
    input.extend_from_slice(b"AP32");
    assert!(detect(&input).unwrap().is_none());
}
