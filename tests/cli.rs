use std::{
    fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_unpack")
}
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn rpc(request: serde_json::Value) -> serde_json::Value {
    let mut child = Command::new(binary())
        .arg("rpc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn protocol_errors_are_structured() {
    for request in [
        serde_json::json!({"protocol":99,"action":"detect"}),
        serde_json::json!({"protocol":1,"action":"unknown","path":"missing"}),
        serde_json::json!({"protocol":1,"action":"detect","path":"missing"}),
        serde_json::json!({"protocol":1,"action":"detect","path":"missing","max_depth":-1}),
    ] {
        let response = rpc(request);
        assert_eq!(response["protocol"], 1);
        assert!(response["error"]["code"].is_string());
    }
}

#[test]
fn cli_and_rpc_unpack_real_samples() {
    let temp = tempfile::tempdir().unwrap();
    let input = root().join("testdata/upx/pe64.packed");
    let output = temp.path().join("with spaces.exe");
    let result = Command::new(binary())
        .args(["unpack", "--json", "-o"])
        .arg(&output)
        .arg(&input)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let response: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(response["history"][0]["packer_name"], "UPX");
    assert_eq!(
        fs::read(&output).unwrap(),
        fs::read(root().join("testdata/upx/pe64.unpacked")).unwrap()
    );
    let response = rpc(serde_json::json!({"protocol":1,"action":"detect","path":input}));
    assert_eq!(response["detection"]["name"], "UPX");
    let response =
        rpc(serde_json::json!({"protocol":1,"action":"unpack","path":input,"max_size":4}));
    assert_eq!(response["error"]["code"], "limit");
}

#[test]
fn cli_preserves_existing_files_and_never_overwrites_input() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("packed.exe");
    let output = temp.path().join("existing.exe");
    fs::copy(root().join("testdata/upx/pe32.packed"), &input).unwrap();
    fs::write(&output, b"keep this").unwrap();
    assert!(
        !Command::new(binary())
            .args(["unpack", "-o"])
            .arg(&output)
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&output).unwrap(), b"keep this");
    let before = fs::read(&input).unwrap();
    assert!(
        !Command::new(binary())
            .args(["unpack", "--force", "-o"])
            .arg(&input)
            .arg(&input)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(fs::read(&input).unwrap(), before);
}

#[test]
fn missing_backend_is_an_error_with_no_output_file() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("missing.exe");
    let result = Command::new(binary())
        .env("UNPACK_UPX", temp.path().join("no-upx"))
        .args(["unpack", "-o"])
        .arg(&output)
        .arg(root().join("testdata/upx/pe32.packed"))
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(!output.exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("cannot start UPX"));
}

#[cfg(unix)]
#[test]
fn backend_limits_terminate_and_clean_private_files() {
    use std::os::unix::fs::PermissionsExt;
    for (body, expected) in [
        ("while :; do :; done\n", "limit"),
        (
            "cp \"$UNPACK_TEST_GOLDEN\" \"$4\"\nwhile :; do :; done\n",
            "limit",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let private = temp.path().join("private");
        fs::create_dir(&private).unwrap();
        let backend = temp.path().join("backend");
        fs::write(&backend, format!("#!/bin/sh\n{body}")).unwrap();
        fs::set_permissions(&backend, fs::Permissions::from_mode(0o700)).unwrap();
        let mut child = Command::new(binary())
            .arg("rpc")
            .env("UNPACK_UPX", &backend)
            .env(
                "UNPACK_TEST_GOLDEN",
                root().join("testdata/upx/pe32.unpacked"),
            )
            .env("TMPDIR", &private)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let request = serde_json::json!({"protocol":1,"action":"unpack","path":root().join("testdata/upx/pe32.packed"),"timeout_ms":100,"max_size":4096});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(result.status.success());
        let response: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(response["error"]["code"], expected);
        assert_eq!(
            fs::read_dir(&private).unwrap().count(),
            0,
            "temporary backend files leaked"
        );
    }
}

#[test]
fn protocol_two_streams_exact_binary_data_and_preserves_protocol_one() {
    use base64::Engine;
    let input = root().join("testdata/upx/pe32.packed");
    let expected = fs::read(root().join("testdata/upx/pe32.unpacked")).unwrap();
    let legacy = rpc(serde_json::json!({"protocol":1,"action":"unpack","path":input}));
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(legacy["data"].as_str().unwrap())
            .unwrap(),
        expected
    );
    let mut child = Command::new(binary())
        .arg("rpc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::json!({"protocol":2,"action":"unpack","path":input})
                .to_string()
                .as_bytes(),
        )
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    let end = output.stdout.iter().position(|b| *b == b'\n').unwrap();
    let header: serde_json::Value = serde_json::from_slice(&output.stdout[..end]).unwrap();
    assert_eq!(header["protocol"], 2);
    assert_eq!(header["data_size"], expected.len());
    assert!(header.get("data").is_none());
    assert_eq!(&output.stdout[end + 1..], expected);
    let error = rpc(serde_json::json!({"protocol":2,"action":"unpack","path":"missing"}));
    assert_eq!(error["protocol"], 2);
    assert_eq!(error["error"]["code"], "io");
}

#[test]
fn explicit_lzma_cli_and_native_container_layers() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("decoded.bin");
    let result = Command::new(binary())
        .args(["unpack", "--format", "LZMA", "-o"])
        .arg(&output)
        .arg(root().join("testdata/payloads/text-lzma.packed"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(
        fs::read(output).unwrap(),
        fs::read(root().join("testdata/payloads/text-lzma.unpacked")).unwrap()
    );
    let response = rpc(
        serde_json::json!({"protocol":1,"action":"unpack","path":root().join("testdata/payloads/gzip-xz-upx.packed")}),
    );
    assert_eq!(response["history"].as_array().unwrap().len(), 3);
    assert_eq!(response["history"][2]["packer_name"], "UPX");
}
