//go:build !linux

package main

import (
	"errors"
	"io"
)

func runCommand(_ []string, _ io.Writer, _ io.Writer) error {
	return errors.New("run is currently supported on Linux only")
}
