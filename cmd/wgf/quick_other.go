//go:build !linux

package main

import (
	"errors"
	"io"
)

func quickCommand([]string, io.Writer, io.Writer) error {
	return errors.New("wgf quick is only supported on Linux")
}
