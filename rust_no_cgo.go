//go:build !cgo

package unpack

import (
	"context"
	"errors"
)

func callNative(context.Context, []byte, string, int64) (*response, error) {
	return nil, errors.New("unpack SDK requires CGO_ENABLED=1 and the Rust static library; run python3 scripts/build_go_sdk.py before building")
}
