//! Rust core for executable packer detection, UPX unpacking and explicit legacy PE recovery.
pub mod aplib;
mod aspack;
mod backend;
pub mod compression;
mod detect;
pub mod macho;
pub mod pe;
mod recover;

pub use detect::{Detection, FORMATS, Format, Support, detect, detect_filtered, detect_format};
use serde::Serialize;
use std::{
    collections::HashSet,
    fmt,
    fs::File,
    hash::{Hash, Hasher},
    io::Read,
    path::Path,
    time::Duration,
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize)]
pub struct Error {
    pub code: String,
    pub message: String,
}
impl Error {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new("unsupported", message)
    }
    pub fn limit(message: impl Into<String>) -> Self {
        Self::new("limit", message)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new("io", e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub max_depth: usize,
    pub max_size: usize,
    pub allow_recovery: bool,
    pub backend_timeout: Duration,
    pub formats: Option<Vec<String>>,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            max_depth: 10,
            max_size: 256 * 1024 * 1024,
            allow_recovery: false,
            backend_timeout: Duration::from_secs(30),
            formats: None,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LayerInfo {
    pub packer_name: String,
    pub version: u32,
    pub layer: usize,
    pub support: Support,
}
#[derive(Debug)]
pub struct UnpackResult {
    pub data: Vec<u8>,
    pub history: Vec<LayerInfo>,
    pub warnings: Vec<String>,
}

pub fn read_limited(path: &Path, max_size: usize) -> Result<Vec<u8>> {
    validate_size(max_size)?;
    let f = File::open(path)?;
    let metadata = f.metadata()?;
    if !metadata.is_file() {
        return Err(Error::invalid("input must be a regular file"));
    }
    if metadata.len() > max_size as u64 {
        return Err(Error::limit("input exceeds size limit"));
    }
    let mut data = Vec::with_capacity(metadata.len() as usize + 1);
    f.take(max_size as u64 + 1).read_to_end(&mut data)?;
    if data.len() > max_size {
        return Err(Error::limit("input exceeds size limit"));
    }
    Ok(data)
}

pub fn unpack_path(path: impl AsRef<Path>, options: &Options) -> Result<UnpackResult> {
    unpack_owned(read_limited(path.as_ref(), options.max_size)?, options)
}

/// Reuse the caller's input allocation instead of cloning the whole file.
pub fn unpack_owned(data: Vec<u8>, options: &Options) -> Result<UnpackResult> {
    unpack_format_owned(data, options, None)
}

pub fn unpack(data: &[u8], options: &Options) -> Result<UnpackResult> {
    unpack_format(data, options, None)
}

/// A named format performs exactly one layer, for the existing Go driver API.
pub fn unpack_format(data: &[u8], options: &Options, format: Option<&str>) -> Result<UnpackResult> {
    validate_size(options.max_size)?;
    if data.len() > options.max_size {
        return Err(Error::limit("input exceeds size limit"));
    }
    unpack_format_owned(data.to_vec(), options, format)
}

/// Owned counterpart of `unpack_format`, used by the CLI and Go bridge.
pub fn unpack_format_owned(
    data: Vec<u8>,
    options: &Options,
    format: Option<&str>,
) -> Result<UnpackResult> {
    unpack_using(data, options, format, backend::upx)
}

fn unpack_using(
    data: Vec<u8>,
    options: &Options,
    format: Option<&str>,
    mut upx: impl FnMut(&[u8], &Options) -> Result<Vec<u8>>,
) -> Result<UnpackResult> {
    validate_size(options.max_size)?;
    if data.len() > options.max_size {
        return Err(Error::limit("input exceeds size limit"));
    }
    if let Some(name) = format {
        detect::find_format(name)?;
    }
    let mut result = UnpackResult {
        data,
        history: Vec::new(),
        warnings: Vec::new(),
    };
    let mut seen = HashSet::new();
    loop {
        if options.max_depth != 0 && result.history.len() >= options.max_depth {
            break;
        }
        if result.history.len() >= 1024 {
            return Err(Error::limit("hard layer limit reached"));
        }
        let detection =
            match detect::detect_filtered(&result.data, format, options.formats.as_deref())? {
                Some(d) => d,
                None if format.is_some() => {
                    return Err(Error::invalid("requested packer not detected"));
                }
                None => break,
            };
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        result.data.hash(&mut hash);
        if !seen.insert(hash.finish()) {
            return Err(Error::invalid("unpacking cycle detected"));
        }
        let next = match detection.support {
            Support::Unpack if detection.name == "AP32" => {
                aplib::unpack(&result.data, options.max_size)?
            }
            Support::Unpack if compression::NAMES.contains(&detection.name.as_str()) => {
                compression::unpack(&result.data, &detection.name, options.max_size)?
            }
            Support::Unpack => upx(&result.data, options)?,
            Support::Recovery if options.allow_recovery => {
                recover::recover(&result.data, &detection, options.max_size)?
            }
            Support::Recovery => {
                return Err(Error::unsupported(format!(
                    "{} only supports static PE recovery; enable allow_recovery / --recover explicitly",
                    detection.name
                )));
            }
            Support::DetectOnly => {
                return Err(Error::unsupported(format!(
                    "{} is recognized; unpacking is not implemented",
                    detection.name
                )));
            }
        };
        if next.len() > options.max_size {
            return Err(Error::limit("output exceeds size limit"));
        }
        if next == result.data {
            return Err(Error::invalid("unpacker made no progress"));
        }
        let executable_source = result.data.starts_with(b"MZ")
            || result.data.starts_with(b"\x7fELF")
            || macho::has_magic(&result.data);
        if (result.data.starts_with(b"MZ") && !next.starts_with(b"MZ"))
            || (result.data.starts_with(b"\x7fELF") && !next.starts_with(b"\x7fELF"))
            || (macho::has_magic(&result.data) && !macho::has_magic(&next))
            || (executable_source && detect(&next).is_err())
        {
            return Err(Error::invalid("unpacker produced a malformed executable"));
        }
        result.data = next;
        result.history.push(LayerInfo {
            packer_name: detection.name.clone(),
            version: detection.version,
            layer: result.history.len() + 1,
            support: detection.support,
        });
        if detection.support == Support::Recovery {
            result.warnings.push(format!("{}: static PE recovery only; compressed code, VM protection and runtime behavior are not verified", detection.name));
            // A repaired file keeps the packer's section names. Do not treat that as another layer.
            break;
        }
        if format.is_some() {
            break;
        }
    }
    Ok(result)
}

fn validate_size(size: usize) -> Result<()> {
    if size == 0 || size > 1024 * 1024 * 1024 {
        return Err(Error::limit("max_size must be between 1 byte and 1 GiB"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn legacy_codec_rejects_truncation_and_invalid_distance() {
        assert_eq!(
            recover::legacy_lz(&[0xe0, b'A', b'B', b'C'], 3).unwrap(),
            b"ABC"
        );
        assert_eq!(
            recover::legacy_lz(&[0x80, b'A', 0xff, 0xff], 3).unwrap(),
            b"AAA"
        );
        assert!(recover::legacy_lz(&[0xe0, b'A'], 3).is_err());
        assert!(recover::legacy_lz(&[0, 0xff, 0xff], 3).is_err());
    }

    #[test]
    fn recursive_control_flow_tracks_layers_depth_and_cycles() {
        // Mock decoder outputs exercise recursion; these are not real nested UPX streams.
        let inner = include_bytes!("../testdata/upx/pe32.packed").to_vec();
        let plain = include_bytes!("../testdata/upx/pe32.unpacked").to_vec();
        let mut outer = inner.clone();
        outer.extend_from_slice(b"mock outer layer");
        for depth in [0, 1, 2, 10] {
            let mut outputs = [inner.clone(), plain.clone()].into_iter();
            let result = unpack_using(
                outer.clone(),
                &Options {
                    max_depth: depth,
                    ..Options::default()
                },
                None,
                |_, _| Ok(outputs.next().unwrap()),
            )
            .unwrap();
            assert_eq!(result.history.len(), if depth == 1 { 1 } else { 2 });
            assert_eq!(
                result.data,
                if depth == 1 {
                    inner.clone()
                } else {
                    plain.clone()
                }
            );
        }
        let result = unpack_using(outer.clone(), &Options::default(), Some("UPX"), |_, _| {
            Ok(inner.clone())
        })
        .unwrap();
        assert_eq!(result.history.len(), 1);
        let mut outputs = [inner.clone(), outer.clone()].into_iter();
        let error = unpack_using(
            outer.clone(),
            &Options {
                max_depth: 0,
                ..Options::default()
            },
            None,
            |_, _| Ok(outputs.next().unwrap()),
        )
        .unwrap_err();
        assert!(error.message.contains("cycle"));
        assert!(
            unpack_using(outer.clone(), &Options::default(), None, |data, _| Ok(
                data.to_vec()
            ))
            .unwrap_err()
            .message
            .contains("no progress")
        );
        assert!(
            unpack_using(outer.clone(), &Options::default(), None, |_, _| Ok(
                b"invalid".to_vec()
            ))
            .is_err()
        );
    }

    #[test]
    fn unlimited_depth_retains_a_hard_limit() {
        let input = include_bytes!("../testdata/upx/pe32.packed");
        let error = unpack_using(
            input.to_vec(),
            &Options {
                max_depth: 0,
                ..Options::default()
            },
            None,
            |data, _| {
                let mut output = data.to_vec();
                output.push(0);
                Ok(output)
            },
        )
        .unwrap_err();
        assert_eq!(error.code, "limit");
    }
}
