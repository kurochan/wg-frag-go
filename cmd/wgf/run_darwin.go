//go:build darwin

package main

import (
	"io"
)

func runCommand(args []string, stdout, stderr io.Writer) error {
	return runConfiguredInterface(args, stdout, stderr)
}

func managerCommand(args []string, stdout, stderr io.Writer) error {
	return runManagerCommand(args, stdout, stderr)
}
