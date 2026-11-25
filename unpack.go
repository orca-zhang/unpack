// Package unpack is a Go SDK for the Rust unpacking engine.
package unpack

//go:generate python3 scripts/build_go_sdk.py

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sort"
	"sync"
)

type Unpacker interface {
	Name() string
	Detect(path string) int
	Unpack(path string) (io.ReaderAt, error)
}

type UnpackResult struct {
	ReaderAt io.ReaderAt
	History  []LayerInfo
	Warnings []string
}

type LayerInfo struct {
	PackerName string `json:"packer_name"`
	Version    int    `json:"version"`
	Layer      int    `json:"layer"`
	Support    string `json:"support"`
}

type Detection struct {
	Name     string `json:"name"`
	Version  int    `json:"version"`
	Support  string `json:"support"`
	Evidence string `json:"evidence"`
}

// Options is forwarded to Rust. Zero MaxSize uses 256 MiB; zero MaxDepth is unlimited.
type Options struct {
	MaxDepth      int
	MaxSize       int64
	AllowRecovery bool
	Format        string // Explicit built-in format; processes exactly one layer without registration.
}

var ups sync.Map

// RegisterFormat selects a Rust-backed SDK adapter. Go unpacker implementations are unsupported.
// Invalid adapters are reported when calling the SDK, rather than executing their Go methods.
func RegisterFormat(name string, up Unpacker) { ups.Store(name, up) }

func registeredNames() []string {
	names := []string{}
	ups.Range(func(k, v interface{}) bool { names = append(names, k.(string)); return true })
	sort.Strings(names)
	return names
}

func registeredFormats() ([]string, map[string]Unpacker, error) {
	formats := []string{}
	adapters := map[string]Unpacker{}
	for _, name := range registeredNames() {
		value, ok := ups.Load(name)
		if !ok {
			continue
		}
		up, ok := value.(Unpacker)
		if !ok {
			return nil, nil, errors.New("invalid SDK adapter")
		}
		rust, ok := up.(interface{ RustFormat() string })
		if !ok {
			return nil, nil, &Error{Code: "unsupported", Message: "Go unpacker implementations were removed; register a Rust-backed SDK adapter"}
		}
		format := rust.RustFormat()
		formats = append(formats, format)
		if _, ok := adapters[format]; !ok {
			adapters[format] = up
		}
	}
	return formats, adapters, nil
}

// Inspect asks Rust to detect all built-in formats, regardless of SDK registration.
func Inspect(path string) (*Detection, error) {
	result, err := callRust(context.Background(), request{Action: "detect", Path: path})
	if err != nil {
		return nil, err
	}
	return result.Detection, nil
}

// DetectFormat preserves the legacy no-match-on-error API. All detection runs in Rust.
func DetectFormat(path string) (Unpacker, int) {
	formats, adapters, err := registeredFormats()
	if err != nil || len(formats) == 0 {
		return nil, 0
	}
	result, err := callRust(context.Background(), request{Action: "detect", Path: path, Formats: &formats})
	if err != nil || result.Detection == nil {
		return nil, 0
	}
	return adapters[result.Detection.Name], result.Detection.Version
}

// Unpack keeps legacy recovery opt-in. Rust performs all file reading and recursive unpacking.
func Unpack(path string, maxDepth int) (*UnpackResult, error) {
	return UnpackWithOptions(context.Background(), path, Options{MaxDepth: maxDepth, AllowRecovery: true})
}
func UnpackAll(path string) (*UnpackResult, error) { return Unpack(path, 10) }

func UnpackWithOptions(ctx context.Context, path string, options Options) (*UnpackResult, error) {
	if options.MaxDepth < 0 || options.MaxSize < 0 || options.MaxSize > 1024*1024*1024 {
		return nil, errors.New("invalid depth or size (maximum size is 1 GiB)")
	}
	req := request{Action: "unpack", Path: path, Format: options.Format, MaxDepth: &options.MaxDepth, MaxSize: options.MaxSize, AllowRecovery: options.AllowRecovery}
	if options.Format == "" {
		formats, _, err := registeredFormats()
		if err != nil {
			return nil, err
		}
		req.Formats = &formats
	}
	result, err := callRust(ctx, req)
	if err != nil {
		return nil, err
	}
	return &UnpackResult{ReaderAt: bytes.NewReader(result.Data), History: result.History, Warnings: result.Warnings}, nil
}

// RustUnpacker adapts one built-in Rust format to the original SDK driver interface.
type RustUnpacker struct{ Format string }

func (u RustUnpacker) Name() string       { return u.Format }
func (u RustUnpacker) RustFormat() string { return u.Format }
func (u RustUnpacker) Detect(path string) int {
	result, err := callRust(context.Background(), request{Action: "detect", Path: path, Format: u.Format})
	if err != nil || result.Detection == nil {
		return 0
	}
	return result.Detection.Version
}
func (u RustUnpacker) Unpack(path string) (io.ReaderAt, error) {
	result, err := callRust(context.Background(), request{Action: "unpack", Path: path, Format: u.Format, AllowRecovery: true})
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(result.Data), nil
}
