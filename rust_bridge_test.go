package unpack

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestNativeMetadataValidation(t *testing.T) {
	for _, header := range []string{
		`{bad json}`, `{"protocol":1}`, `{"protocol":2}`, `{"protocol":2,"data_size":-1}`,
		`{"protocol":2,"data_size":8}`, `{"protocol":2,"data_size":2048}`,
	} {
		if _, err := decodeMetadata([]byte(header), 4, "unpack", 1024); err == nil {
			t.Fatalf("invalid metadata accepted: %s", header)
		}
	}
	if _, err := decodeMetadata([]byte(`{"protocol":2,"data_size":0}`), 0, "unpack", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeMetadata([]byte(`{"protocol":2}`), 1, "detect", 1024); err == nil {
		t.Fatal("detection output accepted")
	}
}

func TestConcurrentNativeCallsAndCancellation(t *testing.T) {
	path := filepath.Join("testdata", "aplib", "tokens.ap32")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if i%2 == 0 {
				cancel()
			}
			result, err := callRust(ctx, request{Action: "unpack", Path: path})
			if i%2 == 0 {
				if !errors.Is(err, context.Canceled) {
					t.Errorf("cancellation: %v", err)
				}
			} else if err != nil || len(result.Data) == 0 {
				t.Errorf("native call: %v", err)
			}
		}(i)
	}
	wg.Wait()
}

func TestNativeCancellationStopsUPX(t *testing.T) {
	// A benign blocking backend proves cancellation is forwarded into Rust.
	if os.PathSeparator != '/' {
		t.Skip("shell backend fixture requires Unix")
	}
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	backend := filepath.Join(dir, "backend")
	if err := os.WriteFile(backend, []byte("#!/bin/sh\nprintf '%s' \"$5\" > \"$UNPACK_TEST_STARTED\"\nwhile :; do :; done\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("UNPACK_UPX", backend)
	t.Setenv("UNPACK_TEST_STARTED", started)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := callRust(ctx, request{Action: "unpack", Path: sample("pe32.packed")}); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("backend did not start")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("SDK cancellation stalled")
	}
	// Observe Rust cleanup as well as the prompt Go context return.
	input, err := os.ReadFile(started)
	if err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(string(input)); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Rust backend was not reaped and cleaned up")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func BenchmarkNativeSDK(b *testing.B) {
	for _, size := range []int{64 * 1024, 4 * 1024 * 1024} {
		b.Run(fmt.Sprintf("%dKiB", size/1024), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "plain.bin")
			if err := os.WriteFile(path, make([]byte, size), 0600); err != nil {
				b.Fatal(err)
			}
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := callRust(context.Background(), request{Action: "unpack", Path: path}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
