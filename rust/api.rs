//! Shared request dispatcher for the CLI protocol and the statically linked SDK.
use crate::{Detection, Error, LayerInfo, Options, read_limited, unpack_format_owned};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
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
pub struct Response {
    pub protocol: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<Detection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_size: Option<usize>,
    pub history: Vec<LayerInfo>,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Error>,
}

pub fn dispatch(
    input: &[u8],
    cancellation: Option<Arc<AtomicBool>>,
) -> (Response, Option<Vec<u8>>) {
    let mut protocol = 1;
    let mut payload = None;
    let result = (|| {
        if input.len() > 65536 {
            return Err(Error::limit("RPC request exceeds 64 KiB"));
        }
        let request: Request =
            serde_json::from_slice(input).map_err(|e| Error::invalid(e.to_string()))?;
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
        options.cancellation = cancellation;
        options.check_cancelled()?;
        let path = request
            .path
            .ok_or_else(|| Error::invalid("path is required"))?;
        let data = read_limited(&path, options.max_size)?;
        options.check_cancelled()?;
        let mut response = Response {
            protocol,
            ..Response::default()
        };
        match request.action.as_str() {
            "detect" => {
                response.detection = crate::detect_filtered(
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
    (response, payload)
}
