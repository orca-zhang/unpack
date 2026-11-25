use std::{
    env, fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::ExitCode,
};
use unpack::{Error, FORMATS, Options, Result, api::Response, read_limited};

fn rpc() -> Result<()> {
    let mut input = Vec::new();
    io::stdin().take(65537).read_to_end(&mut input)?;
    let (response, payload) = unpack::api::dispatch(&input, None);
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, &response).map_err(|e| Error::new("io", e.to_string()))?;
    if response.protocol == 2 {
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
            println!("unpack {}", env!("CARGO_PKG_VERSION"));
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
                "unpack - executable packer analysis\n\nCommands:\n  detect [--json] FILE\n  unpack [-o OUTPUT] [--format NAME] [--depth N] [--recover] [--force] [--json] FILE\n  formats\n  version\n\nLimits: --max-size BYTES (default 256 MiB); depth 0 is unlimited (hard cap 1024).\nAP32/GZIP/ZLIB/XZ: native decoding. LZMA-Alone requires --format LZMA.\nUPX: install upx or set UNPACK_UPX. Recovery mode does not guarantee runnable output."
            );
            Ok(())
        }
        _ => Err(Error::invalid("unknown command; run unpack help")),
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
