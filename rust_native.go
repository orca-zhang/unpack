//go:build cgo

package unpack

/*
#cgo darwin,arm64 LDFLAGS: ${SRCDIR}/native/darwin-arm64/libunpack.a -liconv
#cgo darwin,amd64 LDFLAGS: ${SRCDIR}/native/darwin-amd64/libunpack.a -liconv
#cgo linux,amd64 LDFLAGS: ${SRCDIR}/native/linux-amd64/libunpack.a -ldl -lpthread -lm -lrt -lutil
#cgo linux,arm64 LDFLAGS: ${SRCDIR}/native/linux-arm64/libunpack.a -ldl -lpthread -lm -lrt -lutil
#cgo windows,amd64 LDFLAGS: ${SRCDIR}/native/windows-amd64/libunpack.a -lws2_32 -luserenv -lbcrypt -lntdll -lsynchronization
#include <stdlib.h>
#include "native/unpack.h"
*/
import "C"

import (
	"context"
	"errors"
	"sync"
	"unsafe"
)

func callNative(ctx context.Context, input []byte, action string, maxSize int64) (*response, error) {
	nativeCtx := C.unpack_core_context_new()
	var mu sync.Mutex // Serialize cancel/free; the Rust call runs without this lock.
	type outcome struct {
		result *response
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		defer func() {
			mu.Lock()
			C.unpack_core_context_free(nativeCtx)
			nativeCtx = nil
			mu.Unlock()
		}()
		request := C.CBytes(input)
		defer C.free(request)
		result := C.unpack_core_call((*C.uint8_t)(request), C.size_t(len(input)), nativeCtx)
		defer C.unpack_core_result_free(result.handle)
		if ctx.Err() != nil {
			done <- outcome{err: ctx.Err()}
			return
		}
		if result.metadata_len > 2*1024*1024 || result.metadata == nil {
			done <- outcome{err: errors.New("invalid Rust metadata buffer")}
			return
		}
		metadata := C.GoBytes(unsafe.Pointer(result.metadata), C.int(result.metadata_len))
		decoded, err := decodeMetadata(metadata, int64(result.data_len), action, maxSize)
		if err == nil && action == "unpack" {
			if result.data_len != 0 && result.data == nil {
				err = errors.New("invalid Rust output buffer")
			} else {
				// One copy transfers ownership from Rust to the returned Go ReaderAt.
				decoded.Data = C.GoBytes(unsafe.Pointer(result.data), C.int(result.data_len))
			}
		}
		done <- outcome{decoded, err}
	}()
	select {
	case result := <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return result.result, result.err
	case <-ctx.Done():
		mu.Lock()
		if nativeCtx != nil {
			C.unpack_core_context_cancel(nativeCtx)
		}
		mu.Unlock()
		return nil, ctx.Err()
	}
}
