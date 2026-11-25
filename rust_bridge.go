package unpack

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Error preserves the machine-readable error code returned by Rust.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

type request struct {
	Protocol      int       `json:"protocol"`
	Action        string    `json:"action"`
	Path          string    `json:"path"`
	Format        string    `json:"format,omitempty"`
	MaxDepth      *int      `json:"max_depth,omitempty"`
	MaxSize       int64     `json:"max_size,omitempty"`
	AllowRecovery bool      `json:"allow_recovery"`
	Formats       *[]string `json:"formats,omitempty"`
}

type response struct {
	Protocol  int         `json:"protocol"`
	Detection *Detection  `json:"detection"`
	Data      []byte      `json:"-"`
	DataSize  *int64      `json:"data_size"`
	History   []LayerInfo `json:"history"`
	Warnings  []string    `json:"warnings"`
	Error     *Error      `json:"error"`
}

func callRust(ctx context.Context, req request) (*response, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	req.Protocol = 2
	input, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	if len(input) > 65536 {
		return nil, &Error{Code: "limit", Message: "SDK request exceeds 64 KiB"}
	}
	maxSize := req.MaxSize
	if maxSize == 0 {
		maxSize = 256 * 1024 * 1024
	}
	return callNative(ctx, input, req.Action, maxSize)
}

func decodeMetadata(metadata []byte, dataSize int64, action string, maxSize int64) (*response, error) {
	if len(metadata) > 2*1024*1024 {
		return nil, errors.New("Rust metadata exceeds size limit")
	}
	var result response
	if err := json.Unmarshal(metadata, &result); err != nil {
		return nil, fmt.Errorf("invalid Rust metadata: %w", err)
	}
	if result.Error != nil {
		return nil, result.Error
	}
	if result.Protocol != 2 {
		return nil, errors.New("incompatible Rust library protocol")
	}
	if action == "unpack" {
		if result.DataSize == nil || *result.DataSize < 0 || *result.DataSize > maxSize || *result.DataSize != dataSize {
			return nil, errors.New("Rust library returned invalid binary data size")
		}
	} else if dataSize != 0 || result.DataSize != nil {
		return nil, errors.New("unexpected Rust response data")
	}
	return &result, nil
}
