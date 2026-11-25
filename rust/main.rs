use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
    time::Duration,
};
use unpack::{
    Detection, Error, FORMATS, LayerInfo, Options, Result, read_limited, unpack_format_owned,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: u32,
    action: String,
    path: Option<PathBuf>,
    format: Option<String>,
    max_depth: Option<usize>,
    max_size: Option<usize>,
    allow_recovery: Option<bool>,
    timeout_ms: Option<u64>,
    formats: Option<Vec<String>>,
}

#[derive(Serialize, Default)]
struct Response {
    protocol: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    detection: Option<Detection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_size: Option<usize>,
    history: Vec<LayerInfo>,
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<Error>,
}

fn rpc() -> Result<()> {
    let mut input = Vec::new();
    io::stdin().take(65537).read_to_end(&mut input)?;
    let mut protocol = 1;
    let mut payload = None;
    let result = (|| {
        if input.len() > 65536 {
            return Err(Error::limit("RPC request exceeds 64 KiB"));
        }
        let request: Request =
            serde_json::from_slice(&input).map_err(|e| Error::invalid(e.to_string()))?;
        if request.protocol != 1 && request.protocol != 2 {
            return Err(Error::invalid("unsupported RPC protocol"));
        }
        protocol = request.protocol;
        let mut options = Options::default();
        if let Some(v) = request.max_depth {
            options.max_depth = v;
        }
        if let Some(v) = request.max_size {
            if v == 0 || v > 1024 * 1024 * 1024 {
                return Err(Error::limit("max_size must be between 1 byte and 1 GiB"));
            }
            options.max_size = v;
        }
        if let Some(v) = request.allow_recovery {
            options.allow_recovery = v;
        }
        options.formats = request.formats;
        if let Some(v) = request.timeout_ms {
            options.backend_timeout = Duration::from_millis(v.clamp(1, 300_000));
        }
        let path = request
            .path
            .ok_or_else(|| Error::invalid("path is required"))?;
        let data = read_limited(&path, options.max_size)?;
        let mut response = Response {
            protocol,
            ..Response::default()
        };
        match request.action.as_str() {
            "detect" => {
                response.detection = unpack::detect_filtered(
                    &data,
                    request.format.as_deref(),
                    options.formats.as_deref(),
                )?
            }
            "unpack" => {
                let result = unpack_format_owned(data, &options, request.format.as_deref())?;
                if protocol == 1 {
                    response.data = Some(STANDARD.encode(&result.data));
                } else {
                    response.data_size = Some(result.data.len());
                    payload = Some(result.data);
                }
                response.history = result.history;
                response.warnings = result.warnings;
            }
            _ => return Err(Error::invalid("unknown RPC action")),
        }
        Ok(response)
    })();
    let response = result.unwrap_or_else(|error| Response {
        protocol,
        error: Some(error),
        ..Response::default()
    });
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|e| Error::new("io", e.to_string()))?;
    if protocol == 2 {
        stdout.write_all(b"\n")?;
        if let Some(data) = payload {
            stdout.write_all(&data)?;
        }
    }
    Ok(())
}

fn save(path: &Path, input: &Path, data: &[u8], force: bool) -> Result<()> {
    // Never truncate the source, including through a symlink.
    if path.exists() && fs::canonicalize(path)? == fs::canonicalize(input)? {
        return Err(Error::invalid("output must differ from input"));
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(data)?;
    temp.as_file().sync_all()?;
    if force {
        temp.persist(path)
    } else {
        temp.persist_noclobber(path)
    }
    .map_err(|e| Error::new("io", e.error.to_string()))?;
    Ok(())
}

fn cli() -> Result<()> {
    let mut args = env::args_os().skip(1);
    let command = args.next().unwrap_or_else(|| "help".into());
    match command.to_str() {
        Some("rpc") => rpc(),
        Some("version" | "--version" | "-v") => {
            println!("unpack-rs {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("formats") => {
            serde_json::to_writer_pretty(io::stdout().lock(), FORMATS)
                .map_err(|e| Error::new("io", e.to_string()))?;
            println!();
            Ok(())
        }
        Some("detect" | "unpack") => {
            let mut options = Options::default();
            let (mut input, mut output, mut json, mut force, mut format) =
                (None, None, false, false, None);
            while let Some(arg) = args.next() {
                match arg.to_str() {
                    Some("-o" | "--output") => {
                        output = Some(PathBuf::from(
                            args.next()
                                .ok_or_else(|| Error::invalid("missing output path"))?,
                        ))
                    }
                    Some("-depth" | "--depth" | "--max-depth") => {
                        options.max_depth = args
                            .next()
                            .and_then(|a| a.to_str().and_then(|v| v.parse().ok()))
                            .ok_or_else(|| Error::invalid("depth must be a nonnegative integer"))?;
                    }
                    Some("--max-size") => {
                        options.max_size = args
                            .next()
                            .and_then(|a| a.to_str().and_then(|v| v.parse().ok()))
                            .filter(|v| *v > 0 && *v <= 1024 * 1024 * 1024)
                            .ok_or_else(|| {
                                Error::invalid("max-size must be between 1 byte and 1 GiB")
                            })?;
                    }
                    Some("--recover") => options.allow_recovery = true,
                    Some("--format") => {
                        format = Some(
                            args.next()
                                .and_then(|s| s.into_string().ok())
                                .ok_or_else(|| Error::invalid("missing format name"))?,
                        )
                    }
                    Some("--json") => json = true,
                    Some("--force") => force = true,
                    Some("--") => {
                        if input.is_some() {
                            return Err(Error::invalid("exactly one input is required"));
                        }
                        input = args.next().map(PathBuf::from);
                        if args.next().is_some() {
                            return Err(Error::invalid("exactly one input is required"));
                        }
                        break;
                    }
                    Some(value) if value.starts_with('-') => {
                        return Err(Error::invalid(format!("unknown option: {value}")));
                    }
                    _ if input.is_none() => input = Some(PathBuf::from(arg)),
                    _ => return Err(Error::invalid("exactly one input is required")),
                }
            }
            let input = input.ok_or_else(|| Error::invalid("input path is required"))?;
            let data = read_limited(&input, options.max_size)?;
            if command == "detect" {
                let detection = unpack::detect_format(&data, format.as_deref())?;
                if json {
                    serde_json::to_writer(io::stdout().lock(), &detection)
                        .map_err(|e| Error::new("io", e.to_string()))?;
                    println!();
                } else if let Some(d) = detection {
                    println!(
                        "Packer detected: {} (version {}, {:?}; {})",
                        d.name, d.version, d.support, d.evidence
                    );
                } else {
                    println!("No packer detected in: {}", input.display());
                }
                return Ok(());
            }
            let result = unpack::unpack_format_owned(data, &options, format.as_deref())?;
            let output = output.unwrap_or_else(|| {
                let stem = input.file_stem().unwrap_or_default().to_string_lossy();
                let extension = input
                    .extension()
                    .map(|s| format!(".{}", s.to_string_lossy()))
                    .unwrap_or_default();
                input.with_file_name(format!("{stem}_unpacked{extension}"))
            });
            save(&output, &input, &result.data, force)?;
            if json {
                let response = Response {
                    protocol: 1,
                    history: result.history,
                    warnings: result.warnings,
                    ..Response::default()
                };
                serde_json::to_writer(io::stdout().lock(), &response)
                    .map_err(|e| Error::new("io", e.to_string()))?;
                println!();
            } else {
                for layer in result.history {
                    println!(
                        "Layer {}: {} ({:?})",
                        layer.layer, layer.packer_name, layer.support
                    );
                }
                for warning in result.warnings {
                    eprintln!("Warning: {warning}");
                }
                println!("Saved: {}", output.display());
            }
            Ok(())
        }
        Some("help" | "--help" | "-h") => {
            println!(
                "unpack-rs - executable packer analysis\n\nCommands:\n  detect [--json] FILE\n  unpack [-o OUTPUT] [--format NAME] [--depth N] [--recover] [--force] [--json] FILE\n  formats\n  version\n\nLimits: --max-size BYTES (default 256 MiB); depth 0 is unlimited (hard cap 1024).\nAP32/GZIP/ZLIB/XZ: native decoding. LZMA-Alone requires --format LZMA.\nUPX: install upx or set UNPACK_UPX. Recovery mode does not guarantee runnable output."
            );
            Ok(())
        }
        _ => Err(Error::invalid("unknown command; run unpack-rs help")),
    }
}

fn main() -> ExitCode {
    match cli() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}: {e}", e.code);
            ExitCode::FAILURE
        }
    }
}
