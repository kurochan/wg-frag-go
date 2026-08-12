package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
)

const wireGuardLogInterval = 30 * time.Second

func newAppLogger(output io.Writer) *slog.Logger {
	level := slog.LevelInfo

	switch strings.ToLower(os.Getenv("WGF_LOG_LEVEL")) {
	case "debug", "verbose":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	case "silent":
		level = slog.Level(100)
	}

	options := &slog.HandlerOptions{Level: level}
	if strings.EqualFold(os.Getenv("WGF_LOG_FORMAT"), "json") {
		return slog.New(slog.NewJSONHandler(output, options))
	}
	return slog.New(slog.NewTextHandler(output, options))
}

func newWireGuardLogger(logger *slog.Logger) *device.Logger {
	wgLogger := logger.With("component", "wireguard")
	errors := newRateLimitedLogf(wgLogger, slog.LevelError, wireGuardLogInterval)

	deviceLogger := &device.Logger{Errorf: errors.Logf, Verbosef: device.DiscardLogf}
	if logger.Enabled(context.Background(), slog.LevelDebug) {
		deviceLogger.Verbosef = func(format string, args ...any) {
			wgLogger.Debug(fmt.Sprintf(format, args...))
		}
	}
	return deviceLogger
}

type rateLimitedLogf struct {
	logger   *slog.Logger
	level    slog.Level
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	entries map[string]rateLimitedLogEntry
}

type rateLimitedLogEntry struct {
	at         time.Time
	suppressed uint64
}

func newRateLimitedLogf(logger *slog.Logger, level slog.Level, interval time.Duration) *rateLimitedLogf {
	return &rateLimitedLogf{
		logger: logger, level: level, interval: interval, now: time.Now,
		entries: make(map[string]rateLimitedLogEntry),
	}
}

func (r *rateLimitedLogf) Logf(format string, args ...any) {
	now := r.now()
	r.mu.Lock()

	entry := r.entries[format]
	if !entry.at.IsZero() && now.Sub(entry.at) < r.interval {
		entry.suppressed++
		r.entries[format] = entry
		r.mu.Unlock()
		return
	}

	r.entries[format] = rateLimitedLogEntry{at: now}
	r.mu.Unlock()

	if entry.suppressed != 0 {
		r.logger.Log(context.Background(), r.level, fmt.Sprintf(format, args...), "suppressed", entry.suppressed)
		return
	}

	r.logger.Log(context.Background(), r.level, fmt.Sprintf(format, args...))
}
