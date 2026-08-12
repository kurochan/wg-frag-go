package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestRateLimitedLogfSuppressesRepeatedMessages(t *testing.T) {
	var output bytes.Buffer
	clock := time.Unix(1, 0)
	logger := newRateLimitedLogf(slog.New(slog.NewTextHandler(&output, nil)), slog.LevelError, time.Second)
	logger.now = func() time.Time { return clock }

	logger.Logf("send error: %v", "EMSGSIZE")
	logger.Logf("send error: %v", "EMSGSIZE")
	clock = clock.Add(time.Second)
	logger.Logf("send error: %v", "EMSGSIZE")

	if got := strings.Count(output.String(), "send error"); got != 2 {
		t.Fatalf("logged messages = %d, want 2: %s", got, output.String())
	}
	if !strings.Contains(output.String(), "suppressed=1") {
		t.Fatalf("missing suppression count: %s", output.String())
	}
}

func TestSilentLogLevelSuppressesAllLevels(t *testing.T) {
	t.Setenv("WGF_LOG_LEVEL", "silent")
	var output bytes.Buffer
	logger := newAppLogger(&output)
	logger.Error("hidden")
	logger.Info("hidden")
	if output.Len() != 0 {
		t.Fatalf("silent logger output = %q", output.String())
	}
}
