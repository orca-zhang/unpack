// Package testfixture locates the shared regression fixtures.
package testfixture

import (
	"path/filepath"
	"runtime"
)

func Root() string {
	_, path, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(path), "../.."))
}
