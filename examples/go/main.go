package main

import (
	"context"
	"fmt"
	"github.com/orca-zhang/unpack"
	_ "github.com/orca-zhang/unpack/drivers"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./examples/go FILE")
		os.Exit(1)
	}
	result, err := unpack.UnpackWithOptions(context.Background(), os.Args[1], unpack.Options{MaxDepth: 10})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, layer := range result.History {
		fmt.Printf("Layer %d: %s (%s)\n", layer.Layer, layer.PackerName, layer.Support)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintln(os.Stderr, "Warning:", warning)
	}
	if reader, ok := result.ReaderAt.(interface{ Size() int64 }); ok {
		fmt.Printf("Output: %d bytes\n", reader.Size())
	}
}
