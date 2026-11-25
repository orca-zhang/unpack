use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs, path::PathBuf};
use unpack::{Options, Support, detect, pe::Pe, unpack};

#[test]
fn real_packer_versions_are_recognized_and_unsupported_recovery_is_explicit() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("testdata/retdec");
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let samples = manifest["samples"].as_array().unwrap();
    assert_eq!(samples.len(), 16);
    let mut versions = BTreeSet::new();
    for sample in samples {
        let name = sample["input"].as_str().unwrap();
        let input = fs::read(root.join(name)).unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&input)), sample["sha256"]);
        let found = detect(&input).unwrap().unwrap();
        assert_eq!(found.name, sample["family"], "{name}");
        assert_eq!(
            found.version,
            sample["compatibility_id"].as_u64().unwrap() as u32,
            "{name}"
        );
        assert_eq!(found.support, Support::Recovery);
        for recovery in [false, true] {
            let error = unpack(
                &input,
                &Options {
                    allow_recovery: recovery,
                    ..Options::default()
                },
            )
            .unwrap_err();
            assert_eq!(error.code, "unsupported", "{name}: {error}");
            if recovery {
                assert!(
                    error.message.contains("no verifiable original entry point"),
                    "{name}: {error}"
                );
            }
        }
        versions.insert((
            found.name,
            sample["vendor_version"].as_str().unwrap().to_string(),
        ));
    }
    assert_eq!(versions.len(), 6); // ASPack 2.12, FSG 1.33, MPRESS 1.05/1.27/2.05/2.19.
    let original = &manifest["original"];
    let input = fs::read(root.join(original["path"].as_str().unwrap())).unwrap();
    assert_eq!(format!("{:x}", Sha256::digest(&input)), original["sha256"]);
    assert_eq!(Pe::parse(&input).unwrap().entry, 0x3000);
}
