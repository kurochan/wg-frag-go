//go:build linux || darwin

package main

import (
	"io"
	"testing"
)

func TestManagerCommandRejectsInvalidMetricsListeners(t *testing.T) {
	t.Parallel()
	for _, address := range []string{"auto", "localhost:9910", "127.0.0.1:0", "127.0.0.1"} {
		t.Run(address, func(t *testing.T) {
			t.Parallel()
			if err := runManagerCommand([]string{"--metrics", "--metrics-listen", address}, io.Discard, io.Discard); err == nil {
				t.Fatalf("runManagerCommand accepted metrics listener %q", address)
			}
		})
	}
}

func TestManagerCommandRejectsMetricsOptionsWhenDisabled(t *testing.T) {
	t.Parallel()
	for _, option := range []string{"--metrics-listen", "--metrics-include", "--metrics-exclude"} {
		t.Run(option, func(t *testing.T) {
			t.Parallel()
			if err := runManagerCommand([]string{option, "wgf_*"}, io.Discard, io.Discard); err == nil {
				t.Fatalf("runManagerCommand accepted %s without --metrics", option)
			}
		})
	}
}

func TestManagerCommandRejectsInvalidMetricsPatterns(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{"wgf_*_*", "wgf_unknown_metric"} {
		t.Run(pattern, func(t *testing.T) {
			t.Parallel()
			err := runManagerCommand([]string{
				"--metrics",
				"--metrics-listen", "127.0.0.1:9910",
				"--metrics-include", pattern,
			}, io.Discard, io.Discard)
			if err == nil {
				t.Fatalf("runManagerCommand accepted metrics pattern %q", pattern)
			}
		})
	}
}
