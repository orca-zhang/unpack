use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use unpack::{
    Options, Support, detect,
    pe::{Pe, u32le},
    unpack,
};

#[derive(Deserialize)]
struct Case {
    name: String,
    family: String,
    version: u32,
    profile: String,
    input: String,
    input_sha256: String,
    detected: bool,
    detect_error: Option<String>,
    recovery_error: Option<String>,
    expected_oep: Option<u32>,
    pe64: bool,
    output: Option<String>,
    output_sha256: Option<String>,
    tags: Vec<String>,
}
#[derive(Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

fn verify(c: &Case) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/pe-versions");
    let input = fs::read(root.join(&c.input)).unwrap();
    assert_eq!(
        format!("{:x}", Sha256::digest(&input)),
        c.input_sha256,
        "{}",
        c.name
    );
    let detection = detect(&input);
    if let Some(code) = &c.detect_error {
        assert_eq!(&detection.unwrap_err().code, code, "{} detection", c.name);
    } else {
        let found = detection.unwrap();
        assert_eq!(found.is_some(), c.detected, "{} detection", c.name);
        if let Some(found) = found {
            assert_eq!(found.name, c.family, "{} family", c.name);
            assert_eq!(found.version, c.version, "{} version", c.name);
        }
    }
    let options = Options {
        allow_recovery: true,
        ..Options::default()
    };
    let result = unpack(&input, &options);
    if let Some(code) = &c.recovery_error {
        assert_eq!(&result.unwrap_err().code, code, "{} recovery", c.name);
        return;
    }
    let result = result.unwrap_or_else(|e| panic!("{}: {e}", c.name));
    if !c.detected {
        assert_eq!(result.data, input, "{} unchanged", c.name);
        assert!(result.history.is_empty());
        assert!(unpack::unpack_format(&input, &options, Some(&c.family)).is_err());
        return;
    }
    assert_eq!(
        unpack(&input, &Options::default()).unwrap_err().code,
        "unsupported"
    );
    assert_eq!(result.history.len(), 1);
    assert_eq!(result.history[0].version, c.version);
    assert_eq!(result.history[0].support, Support::Recovery);
    assert_eq!(result.warnings.len(), 1);
    let golden = fs::read(root.join(c.output.as_ref().unwrap())).unwrap();
    assert_eq!(result.data, golden, "{} golden", c.name);
    assert_eq!(
        format!("{:x}", Sha256::digest(&result.data)),
        *c.output_sha256.as_ref().unwrap()
    );
    let before = Pe::parse(&input).unwrap();
    let after = Pe::parse(&result.data).unwrap();
    assert_eq!(after.entry, c.expected_oep.unwrap());
    assert_eq!(after.is_64, c.pe64);
    assert_eq!(u32le(&result.data, after.optional + 64).unwrap(), 0);
    for section in &after.sections {
        if section.name == ".text" {
            assert_eq!(section.flags & 0x60000020, 0x60000020);
        }
    }
    let imports = u32le(&result.data, after.directories + 8).unwrap();
    if c.tags.iter().any(|tag| tag == "no-imports") {
        assert_eq!(imports, 0);
    } else {
        assert_eq!(imports, 0x3000, "{} imports", c.name);
        assert_eq!(u32le(&result.data, after.directories + 12).unwrap(), 40);
    }
    assert_eq!(before.sections.len(), after.sections.len());
}

fn group(family: &str, profile: Option<&str>, count: usize) {
    let manifest: Manifest =
        serde_json::from_slice(include_bytes!("../testdata/pe-versions/manifest.json")).unwrap();
    let cases: Vec<_> = manifest
        .cases
        .iter()
        .filter(|c| c.family == family && profile.is_none_or(|v| c.profile == v))
        .collect();
    assert_eq!(cases.len(), count);
    for c in cases {
        verify(c);
    }
}

#[test]
fn aspack_21_layout() {
    group("ASPack", Some("2.1"), 12);
}
#[test]
fn aspack_212_layout() {
    group("ASPack", Some("2.12"), 23);
}
#[test]
fn aspack_other_layout() {
    group("ASPack", Some("other-0x41f"), 23);
}
#[test]
fn aspack_242_layout() {
    group("ASPack", Some("2.42"), 23);
}
#[test]
fn fsg_versions() {
    group("FSG", None, 4);
}
#[test]
fn winupack_versions() {
    group("WinUpack", None, 4);
}
#[test]
fn mpress_pe32_and_pe64() {
    group("MPRESS", None, 4);
}
#[test]
fn other_pe_families() {
    let manifest: Manifest =
        serde_json::from_slice(include_bytes!("../testdata/pe-versions/manifest.json")).unwrap();
    assert_eq!(manifest.cases.len(), 105);
    for c in &manifest.cases {
        if !["ASPack", "FSG", "WinUpack", "MPRESS"].contains(&c.family.as_str()) {
            verify(c);
        }
    }
}
