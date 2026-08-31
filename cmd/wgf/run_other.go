//go:build !linux && !darwin

package main

import (
	"errors"
	"io"
)

func runCommand(_ []string, _ io.Writer, _ io.Writer) error {
	return errors.New("wgf run is supported only on Linux and macOS")
}

func managerCommand(_ []string, _ io.Writer, _ io.Writer) error {
	return errors.New("wgf manager is supported only on Linux and macOS")
}
