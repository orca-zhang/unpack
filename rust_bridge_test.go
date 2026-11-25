package unpack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBinaryRPCFrames(t *testing.T) {
	for _, frame := range [][]byte{
		[]byte(`{"protocol":2}`),
		[]byte("{bad json}\n"),
		[]byte("{\"protocol\":1}\n"),
		[]byte("{\"protocol\":2,\"data_size\":-1}\n"),
		[]byte("{\"protocol\":2,\"data_size\":8}\nshort"),
		[]byte("{\"protocol\":2,\"data_size\":2}\nextra"),
		[]byte("{\"protocol\":2,\"data_size\":2000}\n"),
		[]byte("{\"protocol\":2,\"data\":\"eA==\",\"data_size\":1}\nx"),
	} {
		if _, err := decodeResponse(frame, "unpack", 1024); err == nil {
			t.Fatalf("invalid frame accepted: %q", frame)
		}
	}
	frame := append([]byte("{\"protocol\":2,\"data_size\":4}\n"), 0, 0xff, '\n', 'x')
	result, err := decodeResponse(frame, "unpack", 4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Data, []byte{0, 0xff, '\n', 'x'}) {
		t.Fatal("binary bytes changed")
	}
	frame[len(frame)-1] = 'y'
	if result.Data[3] != 'y' {
		t.Fatal("binary result was copied")
	}
	if _, err := decodeResponse([]byte("{\"protocol\":2,\"data_size\":0}\n"), "unpack", 1); err != nil {
		t.Fatal("empty output rejected", err)
	}
	if _, err := decodeResponse([]byte("{\"protocol\":2}\nextra"), "detect", 1024); err == nil {
		t.Fatal("detect body accepted")
	}
}

func BenchmarkRPCDecode(b *testing.B) {
	for _, size := range []int{64 * 1024, 4 * 1024 * 1024} {
		payload := bytes.Repeat([]byte{0xa5}, size)
		legacy, _ := json.Marshal(struct {
			Protocol int    `json:"protocol"`
			Data     []byte `json:"data"`
		}{1, payload})
		binary := append([]byte(fmt.Sprintf("{\"protocol\":2,\"data_size\":%d}\n", size)), payload...)
		b.Run(fmt.Sprintf("base64_%dKiB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				var result response
				if err := json.Unmarshal(legacy, &result); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("binary_%dKiB", size/1024), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, err := decodeResponse(binary, "unpack", int64(size)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestLocalEngineUsesNewestBuild(t *testing.T) {
	root := t.TempDir()
	if path := localEnginePath(root, ""); path != "" {
		t.Fatal(path)
	}
	var paths []string
	for _, profile := range []string{"release", "debug"} {
		path := filepath.Join(root, "target", profile, "unpack-rs")
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	old := time.Unix(1000, 0)
	newer := time.Unix(2000, 0)
	os.Chtimes(paths[0], old, old)
	os.Chtimes(paths[1], newer, newer)
	if path := localEnginePath(root, ""); path != paths[1] {
		t.Fatal("stale release selected", path)
	}
	os.Chtimes(paths[0], newer, newer)
	if path := localEnginePath(root, ""); path != paths[0] {
		t.Fatal("release should win equal timestamps", path)
	}
}
