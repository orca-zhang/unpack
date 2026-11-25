//! Ownership boundary for the cgo SDK. No Rust panic may unwind across C.
use crate::{
    Error,
    api::{self, Response},
};
use std::{
    ffi::c_void,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

#[repr(C)]
pub struct NativeResult {
    metadata: *const u8,
    metadata_len: usize,
    data: *const u8,
    data_len: usize,
    handle: *mut c_void,
}

struct OwnedResult {
    metadata: Vec<u8>,
    data: Vec<u8>,
}

fn error_response(error: Error) -> (Response, Option<Vec<u8>>) {
    (
        Response {
            protocol: 2,
            error: Some(error),
            ..Response::default()
        },
        None,
    )
}

#[unsafe(no_mangle)]
pub extern "C" fn unpack_core_context_new() -> *mut c_void {
    Box::into_raw(Box::new(Arc::new(AtomicBool::new(false)))).cast()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unpack_core_context_cancel(context: *mut c_void) {
    if !context.is_null() {
        unsafe { &*context.cast::<Arc<AtomicBool>>() }.store(true, Ordering::Relaxed);
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unpack_core_context_free(context: *mut c_void) {
    if !context.is_null() {
        drop(unsafe { Box::from_raw(context.cast::<Arc<AtomicBool>>()) });
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unpack_core_call(
    input: *const u8,
    length: usize,
    context: *const c_void,
) -> NativeResult {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if length > 65536 {
            return error_response(Error::limit("SDK request exceeds 64 KiB"));
        }
        if input.is_null() {
            return error_response(Error::invalid("null SDK request"));
        }
        let cancellation = if context.is_null() {
            None
        } else {
            Some(unsafe { &*context.cast::<Arc<AtomicBool>>() }.clone())
        };
        api::dispatch(
            unsafe { slice::from_raw_parts(input, length) },
            cancellation,
        )
    }));
    let (response, data) =
        result.unwrap_or_else(|_| error_response(Error::new("internal", "Rust core panicked")));
    let owned = Box::new(OwnedResult {
        metadata: serde_json::to_vec(&response).expect("response serialization is infallible"),
        data: data.unwrap_or_default(),
    });
    NativeResult {
        metadata: owned.metadata.as_ptr(),
        metadata_len: owned.metadata.len(),
        data: if owned.data.is_empty() {
            ptr::null()
        } else {
            owned.data.as_ptr()
        },
        data_len: owned.data.len(),
        handle: Box::into_raw(owned).cast(),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn unpack_core_result_free(handle: *mut c_void) {
    if !handle.is_null() {
        drop(unsafe { Box::from_raw(handle.cast::<OwnedResult>()) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    unsafe fn metadata(result: &NativeResult) -> Value {
        serde_json::from_slice(unsafe {
            slice::from_raw_parts(result.metadata, result.metadata_len)
        })
        .unwrap()
    }

    #[test]
    fn abi_owns_binary_output_and_preserves_errors() {
        let request = json!({"protocol":2,"action":"unpack","path":concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/aplib/tokens.ap32")}).to_string();
        unsafe {
            let context = unpack_core_context_new();
            let result = unpack_core_call(request.as_ptr(), request.len(), context);
            assert_eq!(metadata(&result)["data_size"], result.data_len);
            assert_eq!(
                slice::from_raw_parts(result.data, result.data_len),
                include_bytes!("../testdata/aplib/tokens.unpacked")
            );
            unpack_core_result_free(result.handle);
            unpack_core_context_cancel(context);
            let result = unpack_core_call(request.as_ptr(), request.len(), context);
            assert_eq!(metadata(&result)["error"]["code"], "cancelled");
            unpack_core_result_free(result.handle);
            unpack_core_context_free(context);
            for (input, size, code) in [
                (ptr::null(), 0, "invalid_input"),
                (ptr::null(), 65537, "limit"),
            ] {
                let result = unpack_core_call(input, size, ptr::null());
                assert_eq!(metadata(&result)["error"]["code"], code);
                assert_eq!(result.data_len, 0);
                unpack_core_result_free(result.handle);
            }
        }
    }
}
