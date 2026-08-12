//go:build !linux

package main

import (
	"errors"
	"io"
)

func showconf([]string, statusGetter, io.Writer) error {
	return errors.New("wgf showconf is only supported on Linux")
}
