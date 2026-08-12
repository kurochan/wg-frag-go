//go:build linux

package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kurochan/wg-frag-go/internal/quick"
)

func quickTestConfig(tableLine string) string {
	privateKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	peerKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	return "[Interface]\nPrivateKey = " + privateKey + "\n" + tableLine +
		"[Peer]\nPublicKey = " + peerKey + "\nAllowedIPs = 0.0.0.0/0\n"
}

func TestLoadQuickDownStateRejectsBrokenRuntimeConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "runtime.conf")
	fallback := filepath.Join(dir, "original.conf")
	route := filepath.Join(dir, "route")
	if err := os.WriteFile(input, []byte("[Interface]\nPrivateKey = not-a-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadQuickDownState(input, fallback, route); err == nil {
		t.Fatal("loadQuickDownState accepted an invalid runtime config")
	}
}

func TestLoadQuickDownStateDoesNotIgnoreMissingRouteState(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "runtime.conf")
	if err := os.WriteFile(input, []byte(quickTestConfig("Table = auto\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadQuickDownState(input, filepath.Join(dir, "unused.conf"), filepath.Join(dir, "missing.route"))
	if err == nil || !strings.Contains(err.Error(), "read route state") {
		t.Fatalf("loadQuickDownState error = %v, want missing route state", err)
	}
}

func TestLoadQuickDownStateFallsBackToOriginalConfig(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	input := filepath.Join(dir, "missing-runtime.conf")
	fallback := filepath.Join(dir, "original.conf")
	route := filepath.Join(dir, "unused.route")
	config := quickTestConfig("Table = off\nPreDown = echo down\n")
	if err := os.WriteFile(fallback, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	options, planned, err := loadQuickDownState(input, fallback, route)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.PreDown) != 1 || options.PreDown[0] != "echo down" {
		t.Fatalf("PreDown = %#v", options.PreDown)
	}
	if planned.FwMark != 0 || len(planned.Specific) != 0 || planned.SpecificTable != 0 ||
		len(planned.Defaults) != 0 || planned.DefaultTable != 0 || planned.RulesV4 || planned.RulesV6 {
		t.Fatalf("planned routes = %+v, want empty", planned)
	}
}

func TestReadDaemonPidTreatsMissingFilesAsStopped(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pid, err := readDaemonPidFromPaths("wgf0", filepath.Join(dir, "missing.pid"), filepath.Join(dir, "missing.sock"))
	if err != nil || pid != 0 {
		t.Fatalf("readDaemonPidFromPaths() = (%d, %v), want (0, nil)", pid, err)
	}
}

func TestReadDaemonPidRejectsLiveDaemonWithoutPidFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	socket := filepath.Join(dir, "wgf0.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	_, err = readDaemonPidFromPaths("wgf0", filepath.Join(dir, "missing.pid"), socket)
	if err == nil || !strings.Contains(err.Error(), "control socket is live") {
		t.Fatalf("readDaemonPidFromPaths() error = %v, want live-socket error", err)
	}
}

func TestQuickManifestRoundTripOwnsResources(t *testing.T) {
	t.Parallel()
	parsed, err := quick.Parse(quickTestConfig("Table = off\n"))
	if err != nil {
		t.Fatal(err)
	}
	plan := quick.PlanRoutes(parsed.Options, parsed.Config)
	manifest := newQuickManifest(parsed, plan)
	manifest.Phase = "tearing_down"
	roundTrip, err := manifest.routePlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(roundTrip.Specific) != len(plan.Specific) || roundTrip.SpecificTable != plan.SpecificTable {
		t.Fatalf("route plan = %+v, want %+v", roundTrip, plan)
	}
	addresses, err := manifest.addresses()
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != len(parsed.Config.Interface.Addresses) {
		t.Fatalf("addresses = %v, want %v", addresses, parsed.Config.Interface.Addresses)
	}
}

func TestTeardownBlackholeRulesProtectOwnedPrefixes(t *testing.T) {
	t.Parallel()
	plan := quick.RoutePlan{
		Specific:     []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		Defaults:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
		FwMark:       51820,
		DefaultTable: 51820,
		RulesV4:      true,
	}
	rules := teardownBlackholeRules(plan)
	if len(rules) != 2 {
		t.Fatalf("blackhole rules = %d, want default and specific rules", len(rules))
	}
	if !rules[0].Invert || rules[0].Mark != plan.FwMark || rules[0].Dst != nil {
		t.Fatalf("default blackhole rule = %+v", rules[0])
	}
	if rules[1].Dst == nil || rules[1].Dst.String() != "10.0.0.0/8" {
		t.Fatalf("specific blackhole rule = %+v", rules[1])
	}
}

func TestQuickFileLockSerializesOperations(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "quick.lock")
	release, err := acquireQuickFileLock(path)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err := acquireQuickFileLock(path); !errors.Is(err, errQuickLockBusy) {
		t.Fatalf("second lock error = %v, want errQuickLockBusy", err)
	}
}

func TestRunHooksTimeoutKillsProcessGroup(t *testing.T) {
	t.Parallel()
	marker := filepath.Join(t.TempDir(), "escaped-child")
	command := "(sleep 0.2; touch '" + strings.ReplaceAll(marker, "'", "'\\''") + "') & wait"

	err := runHooksWithTimeout("PreUp", []string{command}, "wgf0", &bytes.Buffer{}, &bytes.Buffer{}, 20*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "hook timed out") {
		t.Fatalf("runHooksWithTimeout error = %v, want timeout", err)
	}

	time.Sleep(350 * time.Millisecond)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("timed-out hook child created %s", marker)
	}
}
