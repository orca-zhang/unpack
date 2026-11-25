use crate::{Error, Options, Result, read_limited};
use std::{
    fs::{self, File},
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub fn upx(data: &[u8], options: &Options) -> Result<Vec<u8>> {
    let dir = tempfile::tempdir()?;
    let input = dir.path().join("packed.bin");
    let output = dir.path().join("unpacked.bin");
    let diagnostics = dir.path().join("stderr.txt");
    fs::write(&input, data)?;
    let executable = std::env::var_os("UNPACK_UPX").unwrap_or_else(|| "upx".into());
    let mut child = Command::new(executable)
        .args(["-d", "-q", "-o"])
        .arg(&output)
        .arg(&input)
        .env_remove("UPX")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(File::create(&diagnostics)?)
        .spawn()
        .map_err(|e| {
            Error::new(
                "backend",
                format!("cannot start UPX (install upx or set UNPACK_UPX): {e}"),
            )
        })?;
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e.into());
            }
        }
        if started.elapsed() > options.backend_timeout
            || fs::metadata(&output).is_ok_and(|m| m.len() > options.max_size as u64)
            || fs::metadata(&diagnostics).is_ok_and(|m| m.len() > 65536)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error::limit("UPX exceeded time or output size limit"));
        }
        thread::sleep(Duration::from_millis(10));
    };
    if !status.success() {
        let mut message = String::new();
        File::open(diagnostics)?
            .take(4096)
            .read_to_string(&mut message)?;
        return Err(Error::new(
            "backend",
            format!("UPX failed: {}", message.trim()),
        ));
    }
    read_limited(&output, options.max_size)
}
