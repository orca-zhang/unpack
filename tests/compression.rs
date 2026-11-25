use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use unpack::{Options, compression, detect, unpack, unpack_format};

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/payloads")
}
fn fixture(name: &str) -> Vec<u8> {
    fs::read(directory().join(name)).unwrap()
}

#[test]
fn independently_encoded_payloads_and_real_chains() {
    let manifest: serde_json::Value = serde_json::from_slice(&fixture("manifest.json")).unwrap();
    let samples = manifest["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 20);
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
        let format = sample["format"].as_str().unwrap();
        let explicit = sample["explicit"].as_bool().unwrap();
        if explicit {
            assert!(detect(&input).unwrap().is_none());
        } else {
            assert_eq!(detect(&input).unwrap().unwrap().name, format);
        }
        let result = if explicit {
            unpack_format(&input, &Options::default(), Some(format))
        } else {
            unpack(&input, &Options::default())
        };
        let result = result.unwrap_or_else(|e| panic!("{}: {e}", sample["name"]));
        assert_eq!(result.data, expected, "{}", sample["name"]);
        let history = result
            .history
            .iter()
            .map(|l| l.packer_name.as_str())
            .collect::<Vec<_>>();
        let expected_history = sample["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(history, expected_history, "{}", sample["name"]);
        assert!(result.warnings.is_empty());
    }
}

#[test]
fn corrupt_truncated_trailing_and_bomb_payloads_are_rejected() {
    for (format, name) in [
        ("GZIP", "text-gzip"),
        ("ZLIB", "text-zlib"),
        ("XZ", "text-xz"),
        ("LZMA", "text-lzma"),
    ] {
        let input = fixture(&format!("{name}.packed"));
        for cut in [0, 1, 2, input.len() / 2, input.len() - 1] {
            assert!(
                compression::unpack(&input[..cut], format, 1 << 20).is_err(),
                "{format} cut {cut}"
            );
        }
        let mut trailing = input.clone();
        trailing.extend_from_slice(b"junk");
        assert!(
            compression::unpack(&trailing, format, 1 << 20).is_err(),
            "{format} trailing"
        );
        assert_eq!(
            compression::unpack(&input, format, 32).unwrap_err().code,
            "limit",
            "{format}"
        );
        if format != "LZMA" {
            let mut corrupt = input.clone();
            let end = corrupt.len() - 1;
            corrupt[end] ^= 0x40;
            assert!(
                compression::unpack(&corrupt, format, 1 << 20).is_err(),
                "{format} checksum"
            );
        }
        assert!(compression::unpack(&input, format, 0).is_err());
    }
}

#[test]
fn dictionary_memory_is_bounded_before_allocation() {
    let mut lzma = fixture("text-lzma.packed");
    lzma[1..5].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(compression::unpack(&lzma, "LZMA", 1 << 20).is_err());
    let mut xz = fixture("text-xz.packed");
    let header_size = (xz[12] as usize + 1) * 4;
    assert_eq!(&xz[14..16], &[0x21, 1]);
    xz[16] = 40;
    let crc = crc32fast::hash(&xz[12..12 + header_size - 4]);
    xz[12 + header_size - 4..12 + header_size].copy_from_slice(&crc.to_le_bytes());
    let error = compression::unpack(&xz, "XZ", 1 << 20).unwrap_err();
    assert_eq!(error.code, "limit");
}

#[test]
fn named_layers_depth_and_filters_are_respected() {
    let input = fixture("gzip-xz-upx.packed");
    let options = Options {
        max_depth: 1,
        ..Options::default()
    };
    let first = unpack(&input, &options).unwrap();
    assert_eq!(first.history.len(), 1);
    assert!(first.data.starts_with(b"\xfd7zXZ\0"));
    let named = unpack_format(&input, &Options::default(), Some("GZIP")).unwrap();
    assert_eq!(named.history.len(), 1);
    let no_formats = Options {
        formats: Some(vec![]),
        ..Options::default()
    };
    assert_eq!(unpack(&input, &no_formats).unwrap().data, input);
    let lzma = fixture("text-lzma.packed");
    assert_eq!(unpack(&lzma, &Options::default()).unwrap().data, lzma);
    assert!(
        unpack_format(
            &fixture("text-gzip.packed"),
            &Options::default(),
            Some("LZMA")
        )
        .is_err()
    );
}

#[test]
fn explicit_payload_decoding_does_not_require_a_valid_inner_executable() {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"MZ").unwrap();
    let compressed = encoder.finish().unwrap();
    let output = unpack_format(&compressed, &Options::default(), Some("GZIP")).unwrap();
    assert_eq!(output.data, b"MZ");
    assert_eq!(output.history.len(), 1);
    assert!(unpack(&compressed, &Options::default()).is_err());
}
