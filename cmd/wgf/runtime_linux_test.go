//go:build linux

package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/config"
)

func TestWarnUnwiredConcurrencyOptions(t *testing.T) {
	t.Parallel()
	var stderr bytes.Buffer
	warnUnwiredConcurrencyOptions(&config.Config{Interface: config.Interface{
		Workers:   config.AutoCount{Count: 4},
		TUNQueues: config.AutoCount{Count: 2},
	}}, slog.New(slog.NewTextHandler(&stderr, nil)))
	if !strings.Contains(stderr.String(), "not active") {
		t.Fatalf("warning = %q", stderr.String())
	}
}
