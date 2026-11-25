package unpack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	Data      []byte      `json:"data"`
	DataSize  *int64      `json:"data_size"`
	History   []LayerInfo `json:"history"`
	Warnings  []string    `json:"warnings"`
	Error     *Error      `json:"error"`
}

func enginePath() (string, error) {
	if path := os.Getenv("UNPACK_RUST_BIN"); path != "" {
		return path, nil
	}
	if path, err := exec.LookPath("unpack-rs"); err == nil {
		return path, nil
	}
	_, source, _, ok := runtime.Caller(0)
	if ok {
		suffix := ""
		if runtime.GOOS == "windows" {
			suffix = ".exe"
		}
		if path := localEnginePath(filepath.Dir(source), suffix); path != "" {
			return path, nil
		}
	}
	return "", errors.New("Rust engine not found: install unpack-rs or set UNPACK_RUST_BIN; run cargo build for development")
}

func localEnginePath(root, suffix string) string {
	var newest time.Time
	var selected string
	for _, profile := range []string{"release", "debug"} {
		path := filepath.Join(root, "target", profile, "unpack-rs"+suffix)
		if info, err := os.Stat(path); err == nil && !info.IsDir() && (selected == "" || info.ModTime().After(newest)) {
			selected, newest = path, info.ModTime()
		}
	}
	return selected
}

type limitedBuffer struct {
	bytes.Buffer
	limit int64
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len())+int64(len(p)) > b.limit {
		return 0, errors.New("Rust engine response exceeds size limit")
	}
	return b.Buffer.Write(p)
}

func callRust(ctx context.Context, req request) (*response, error) {
	path, err := enginePath()
	if err != nil {
		return nil, err
	}
	req.Protocol = 2
	input, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "rpc")
	cmd.Stdin = bytes.NewReader(input)
	maxSize := req.MaxSize
	if maxSize == 0 {
		maxSize = 256 * 1024 * 1024
	}
	stdout := &limitedBuffer{limit: maxSize + 2*1024*1024}
	stderr := &limitedBuffer{limit: 64 * 1024}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("Rust engine: %w: %s", err, stderr.String())
	}
	return decodeResponse(stdout.Bytes(), req.Action, maxSize)
}

func decodeResponse(frame []byte, action string, maxSize int64) (*response, error) {
	end := bytes.IndexByte(frame, '\n')
	if end < 0 || end > 2*1024*1024 {
		return nil, errors.New("invalid Rust response frame; a matching protocol-2 engine is required")
	}
	var result response
	if err := json.Unmarshal(frame[:end], &result); err != nil {
		return nil, fmt.Errorf("invalid Rust response: %w", err)
	}
	if result.Protocol != 2 || result.Data != nil {
		return nil, errors.New("incompatible Rust engine protocol")
	}
	if result.Error != nil {
		return nil, result.Error
	}
	body := frame[end+1:]
	if action == "unpack" {
		if result.DataSize == nil || *result.DataSize < 0 || *result.DataSize > maxSize || *result.DataSize != int64(len(body)) {
			return nil, errors.New("Rust engine returned invalid binary data size")
		}
		// The ReaderAt retains this buffer; no base64 decoding or second payload allocation.
		result.Data = body
	} else if len(body) != 0 || result.DataSize != nil {
		return nil, errors.New("unexpected Rust response body")
	}
	return &result, nil
}
