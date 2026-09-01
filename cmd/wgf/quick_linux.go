//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kurochan/wg-frag-go/controlapi"
	"github.com/kurochan/wg-frag-go/internal/platform/runtimedir"
	"github.com/kurochan/wg-frag-go/internal/quick"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	daemonReadyTimeout = 15 * time.Second
	daemonStopTimeout  = 5 * time.Second
	// hookTimeout bounds a Pre/PostUp shell hook so a hung hook cannot leave the
	// interface half-configured with the quick lock held.
	hookTimeout = 5 * time.Minute
	// Rule priorities follow wg-quick's resulting order: the fwmark exemption
	// must be consulted before the suppressed main-table lookup.
	ruleBlackholePriority = 32763
	ruleFwmarkPriority    = 32764
	ruleSuppressPriority  = 32765
	autoTableAttempts     = 4096
)

func quickCommand(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: wgf quick up|reload|down|save|strip <interface|config-file>")
	}

	switch args[0] {
	case "up":
		return quickUp(args[1:], stdout, stderr)
	case "reload":
		return quickReload(args[1:], stdout, stderr)
	case "down":
		return quickDown(args[1:], stdout, stderr)
	case "save":
		return quickSave(args[1:], stdout, stderr)
	case "strip":
		return quickStrip(args[1:], stdout)
	default:
		return fmt.Errorf("unknown quick command %q", args[0])
	}
}

// quickTarget is the configuration source selected by a quick command
// argument.
type quickTarget struct {
	ifname string
	path   string
	// explicit reports that the operator named a file instead of an interface.
	explicit bool
	// legacy reports that path is in quick.LegacyConfigDir.
	legacy bool
}

// resolveQuickTarget accepts either an interface name or a config path.
// A path is anything containing a separator or ending in .conf.
func resolveQuickTarget(argument string) (quickTarget, error) {
	if strings.ContainsRune(argument, os.PathSeparator) || strings.HasSuffix(argument, ".conf") {
		base := strings.TrimSuffix(filepath.Base(argument), ".conf")
		if err := quick.ValidateName(base); err != nil {
			return quickTarget{}, err
		}
		absolute, err := filepath.Abs(argument)
		if err != nil {
			return quickTarget{}, err
		}
		return quickTarget{ifname: base, path: absolute, explicit: true}, nil
	}
	if err := quick.ValidateName(argument); err != nil {
		return quickTarget{}, err
	}
	path, legacy := quick.ResolveConfigPath(argument)
	return quickTarget{ifname: argument, path: path, legacy: legacy}, nil
}

// resolveStartedTarget resolves an argument for a command that acts on a
// started interface, preferring the configuration recorded at start.
func resolveStartedTarget(argument string) (quickTarget, error) {
	target, err := resolveQuickTarget(argument)
	if err != nil || target.explicit {
		return target, err
	}
	origin, err := os.ReadFile(originPath(target.ifname))
	if err != nil {
		return target, nil
	}
	recorded := strings.TrimSpace(string(origin))
	if recorded == "" {
		return target, nil
	}
	target.path = recorded
	target.legacy = recorded == quick.LegacyConfigPath(target.ifname)
	return target, nil
}

// legacyConfigWarning reports the removal notice for a configuration read from
// quick.LegacyConfigDir.
func legacyConfigWarning(target quickTarget) string {
	if !target.legacy {
		return ""
	}
	return fmt.Sprintf(
		"warning: %s is a legacy location; move it to %s (support is removed in v0.7.0)",
		target.path,
		quick.ConfigPath(target.ifname),
	)
}

func snapshotPath(ifname string) string { return filepath.Join(runtimedir.Default, ifname+".conf") }
func pidPath(ifname string) string      { return filepath.Join(runtimedir.Default, ifname+".pid") }
func originPath(ifname string) string   { return filepath.Join(runtimedir.Default, ifname+".origin") }
func inputPath(ifname string) string    { return filepath.Join(runtimedir.Default, ifname+".quick.conf") }
func routePath(ifname string) string    { return filepath.Join(runtimedir.Default, ifname+".route") }
func manifestPath(ifname string) string { return filepath.Join(runtimedir.Default, ifname+".manifest") }

type quickManifest struct {
	Version       uint8    `json:"version"`
	Phase         string   `json:"phase"`
	Addresses     []string `json:"addresses"`
	Specific      []string `json:"specific_routes"`
	SpecificTable uint32   `json:"specific_table"`
	Defaults      []string `json:"default_routes"`
	DefaultTable  uint32   `json:"default_table"`
	FwMark        uint32   `json:"fwmark"`
	RulesV4       bool     `json:"rules_v4"`
	RulesV6       bool     `json:"rules_v6"`
}

func loadQuickDownParsed(input, fallback, route string) (quick.Parsed, quick.RoutePlan, error) {
	text, err := os.ReadFile(input)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return quick.Parsed{}, quick.RoutePlan{}, fmt.Errorf("read runtime config %s: %w", input, err)
		}

		// #nosec G703 -- The fallback path is an explicit operator-selected config path.
		text, err = os.ReadFile(fallback)
		if err != nil {
			return quick.Parsed{}, quick.RoutePlan{}, fmt.Errorf("read config %s: %w", fallback, err)
		}
	}

	parsed, err := quick.Parse(string(text))
	if err != nil {
		return quick.Parsed{}, quick.RoutePlan{}, fmt.Errorf("parse quick config: %w", err)
	}
	planned := quick.PlanRoutes(parsed.Options, parsed.Config)
	if planned.DefaultTable != 0 {
		mark, err := readRouteTablePath(route)
		if err != nil {
			return quick.Parsed{}, quick.RoutePlan{}, fmt.Errorf("read route state: %w", err)
		}
		planned.FwMark = mark
		planned.DefaultTable = mark
	}
	return parsed, planned, nil
}

func newQuickManifest(parsed quick.Parsed, plan quick.RoutePlan) quickManifest {
	manifest := quickManifest{
		Version:       1,
		Phase:         "active",
		SpecificTable: plan.SpecificTable,
		DefaultTable:  plan.DefaultTable,
		FwMark:        plan.FwMark,
		RulesV4:       plan.RulesV4,
		RulesV6:       plan.RulesV6,
	}
	for _, prefix := range parsed.Config.Interface.Addresses {
		manifest.Addresses = append(manifest.Addresses, prefix.String())
	}
	for _, prefix := range plan.Specific {
		manifest.Specific = append(manifest.Specific, prefix.String())
	}
	for _, prefix := range plan.Defaults {
		manifest.Defaults = append(manifest.Defaults, prefix.String())
	}
	return manifest
}

func (m quickManifest) routePlan() (quick.RoutePlan, error) {
	if m.Version != 1 || (m.Phase != "active" && m.Phase != "tearing_down") {
		return quick.RoutePlan{}, errors.New("invalid quick resource manifest")
	}
	plan := quick.RoutePlan{
		SpecificTable: m.SpecificTable,
		DefaultTable:  m.DefaultTable,
		FwMark:        m.FwMark,
		RulesV4:       m.RulesV4,
		RulesV6:       m.RulesV6,
	}
	for _, value := range m.Specific {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return quick.RoutePlan{}, fmt.Errorf("invalid specific route %q: %w", value, err)
		}
		plan.Specific = append(plan.Specific, prefix)
	}
	for _, value := range m.Defaults {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return quick.RoutePlan{}, fmt.Errorf("invalid default route %q: %w", value, err)
		}
		plan.Defaults = append(plan.Defaults, prefix)
	}
	return plan, nil
}

func (m quickManifest) addresses() ([]netip.Prefix, error) {
	addresses := make([]netip.Prefix, 0, len(m.Addresses))
	for _, value := range m.Addresses {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("invalid interface address %q: %w", value, err)
		}
		addresses = append(addresses, prefix)
	}
	return addresses, nil
}

func readQuickManifest(ifname string) (quickManifest, error) {
	text, err := os.ReadFile(manifestPath(ifname))
	if err != nil {
		return quickManifest{}, err
	}
	var manifest quickManifest
	if err := json.Unmarshal(text, &manifest); err != nil {
		return quickManifest{}, fmt.Errorf("parse resource manifest: %w", err)
	}
	if _, err := manifest.routePlan(); err != nil {
		return quickManifest{}, err
	}
	if _, err := manifest.addresses(); err != nil {
		return quickManifest{}, err
	}
	return manifest, nil
}

func writeQuickManifest(ifname string, manifest quickManifest) error {
	text, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return quick.WriteAtomic(manifestPath(ifname), append(text, '\n'))
}

func loadQuickDownState(input, fallback, route string) (quick.Options, quick.RoutePlan, error) {
	parsed, planned, err := loadQuickDownParsed(input, fallback, route)
	if err != nil {
		return quick.Options{}, quick.RoutePlan{}, err
	}
	return parsed.Options, planned, nil
}

// runHooks executes wg-quick style shell hooks with %i replaced by the
// interface name. A failing hook aborts the surrounding operation.
func runHooks(stage string, hooks []string, ifname string, stdout, stderr io.Writer) error {
	return runHooksWithTimeout(stage, hooks, ifname, stdout, stderr, hookTimeout)
}

func runHooksWithTimeout(
	stage string,
	hooks []string,
	ifname string,
	stdout, stderr io.Writer,
	timeout time.Duration,
) error {
	for _, hook := range hooks {
		command := strings.ReplaceAll(hook, "%i", ifname)
		fmt.Fprintf(stdout, "[#] %s\n", command)
		hookCtx, cancelHook := context.WithTimeout(context.Background(), timeout)
		// #nosec G702 -- Pre/Post hooks intentionally execute the operator's shell command.
		cmd := exec.CommandContext(hookCtx, "/bin/sh", "-c", command)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error {
			if cmd.Process == nil {
				return nil
			}
			err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			if errors.Is(err, syscall.ESRCH) {
				return os.ErrProcessDone
			}
			return err
		}
		cmd.Stdout = stdout

		cmd.Stderr = stderr
		err := cmd.Run()
		cancelHook()
		if err != nil {
			if errors.Is(hookCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%s hook timed out: %w", stage, hookCtx.Err())
			}
			return fmt.Errorf("%s hook failed: %w", stage, err)
		}
	}
	return nil
}

// rollback runs deferred undo steps in reverse order, keeping the first error
// for the log but never stopping early.
type rollback struct {
	steps []func() error
}

func (r *rollback) add(step func() error) { r.steps = append(r.steps, step) }

func (r *rollback) run(stderr io.Writer) {
	for i := len(r.steps) - 1; i >= 0; i-- {
		if err := r.steps[i](); err != nil {
			fmt.Fprintf(stderr, "wgf quick: rollback: %v\n", err)
		}
	}
}

func quickUp(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: wgf quick up <interface|config-file>")
	}
	target, err := resolveQuickTarget(args[0])
	if err != nil {
		return err
	}
	ifname, path := target.ifname, target.path

	unlock, err := acquireQuickLock(stderr, "up", ifname)
	if err != nil {
		return err
	}
	defer unlock()

	if _, err := os.Stat(snapshotPath(ifname)); err == nil {
		return fmt.Errorf("`%s' already exists as a wgf interface (wgf quick down %s first)", ifname, ifname)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect quick runtime state: %w", err)
	}
	if warning := legacyConfigWarning(target); warning != "" {
		fmt.Fprintln(stderr, warning)
	}
	if warning := quick.WarnLoosePermissions(path); warning != "" {
		fmt.Fprintln(stderr, warning)
	}
	// #nosec G703 -- The config path is explicitly selected by the operator.
	text, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	parsed, err := quick.Parse(string(text))
	if err != nil {
		return err
	}

	if len(parsed.Options.DNS) != 0 {
		fmt.Fprintln(stderr, "warning: DNS is not supported by wgf quick and was ignored")
	}
	plan := quick.PlanRoutes(parsed.Options, parsed.Config)
	if parsed.Config.Interface.FwMark == 0 {
		plan, err = chooseAutoTable(plan)
		if err != nil {
			return err
		}
	}
	runtime := quick.InjectFwMark(parsed.Runtime, plan.FwMark)

	if err := runHooks("PreUp", parsed.Options.PreUp, ifname, stdout, stderr); err != nil {
		return err
	}
	undo := &rollback{}
	success := false

	defer func() {
		if !success {
			undo.run(stderr)
		}
	}()

	if err := os.MkdirAll(runtimedir.Default, 0o700); err != nil {
		return err
	}

	if err := quick.WriteAtomic(snapshotPath(ifname), []byte(runtime)); err != nil {
		return err
	}

	undo.add(func() error { return os.Remove(snapshotPath(ifname)) })
	if err := quick.WriteAtomic(originPath(ifname), []byte(path+"\n")); err != nil {
		return err
	}

	undo.add(func() error { return os.Remove(originPath(ifname)) })

	if err := quick.WriteAtomic(inputPath(ifname), text); err != nil {
		return err
	}

	undo.add(func() error { return os.Remove(inputPath(ifname)) })
	if plan.DefaultTable != 0 {
		if err := quick.WriteAtomic(
			routePath(ifname),
			[]byte(strconv.FormatUint(uint64(plan.DefaultTable), 10)+"\n"),
		); err != nil {
			return err
		}

		undo.add(func() error { return os.Remove(routePath(ifname)) })
	}
	if err := writeQuickManifest(ifname, newQuickManifest(parsed, plan)); err != nil {
		return fmt.Errorf("write resource manifest: %w", err)
	}
	undo.add(func() error { return os.Remove(manifestPath(ifname)) })

	pid, err := spawnDaemon(ifname, stdout, stderr)
	if err != nil {
		return err
	}

	undo.add(func() error {
		_ = stopDaemon(pid)
		return os.Remove(pidPath(ifname))
	})
	if err := waitDaemonReady(ifname, pid); err != nil {
		return err
	}

	link, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("interface %s did not appear: %w", ifname, err)
	}

	for _, prefix := range parsed.Config.Interface.Addresses {
		fmt.Fprintf(stdout, "[#] ip address add %s dev %s\n", prefix, ifname)

		address, err := prefixToAddr(prefix)
		if err != nil {
			return err
		}

		if err := netlink.AddrAdd(link, address); err != nil {
			return fmt.Errorf("add address %s: %w", prefix, err)
		}
		undo.add(func() error {
			if err := netlink.AddrDel(link, address); err != nil && !errors.Is(err, syscall.ENOENT) {
				return fmt.Errorf("remove address %s: %w", prefix, err)
			}
			return nil
		})
	}
	fmt.Fprintf(stdout, "[#] ip link set %s up\n", ifname)
	if err := netlink.LinkSetUp(link); err != nil {
		return err
	}
	undo.add(func() error { return netlink.LinkSetDown(link) })

	for _, prefix := range plan.Specific {
		fmt.Fprintf(stdout, "[#] ip route add %s dev %s%s\n", prefix, ifname, tableSuffix(plan.SpecificTable))
		if err := addRoute(link, prefix, plan.SpecificTable); err != nil {
			return fmt.Errorf("add route %s: %w", prefix, err)
		}
		undo.add(func() error { return deleteRoute(link, prefix, plan.SpecificTable) })
	}

	for _, prefix := range plan.Defaults {
		fmt.Fprintf(stdout, "[#] ip route add %s dev %s table %d\n", prefix, ifname, plan.DefaultTable)

		if err := addRoute(link, prefix, plan.DefaultTable); err != nil {
			return fmt.Errorf("add route %s: %w", prefix, err)
		}
		undo.add(func() error { return deleteRoute(link, prefix, plan.DefaultTable) })
	}

	for _, family := range ruleFamilies(plan) {
		fmt.Fprintf(stdout, "[#] ip %s rule add not fwmark %d table %d\n", familyFlag(family), plan.FwMark, plan.DefaultTable)
		fmt.Fprintf(stdout, "[#] ip %s rule add table main suppress_prefixlength 0\n", familyFlag(family))
		if err := addPolicyRules(family, plan.FwMark, plan.DefaultTable); err != nil {
			return err
		}

		undo.add(func() error { return deletePolicyRules(family, plan.FwMark, plan.DefaultTable) })
	}

	if err := runHooks("PostUp", parsed.Options.PostUp, ifname, stdout, stderr); err != nil {
		return err
	}
	success = true
	return nil
}

func quickDown(args []string, stdout, stderr io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: wgf quick down <interface|config-file>")
	}
	target, err := resolveStartedTarget(args[0])
	if err != nil {
		return err
	}
	ifname, path := target.ifname, target.path
	unlock, err := acquireQuickLock(stderr, "down", ifname)
	if err != nil {
		return err
	}

	defer unlock()

	if _, err := os.Stat(snapshotPath(ifname)); err != nil {
		return fmt.Errorf("`%s' is not a wgf interface", ifname)
	}
	// Use the original input snapshot so edited or removed configuration files
	// cannot leave routes or hooks behind during teardown.
	parsed, planned, err := loadQuickDownParsed(inputPath(ifname), path, routePath(ifname))
	if err != nil {
		return fmt.Errorf("cannot safely determine teardown state for %s: %w", ifname, err)
	}
	addresses := parsed.Config.Interface.Addresses
	manifest, manifestErr := readQuickManifest(ifname)
	if manifestErr == nil {
		planned, err = manifest.routePlan()
		if err != nil {
			return fmt.Errorf("cannot safely determine teardown resources for %s: %w", ifname, err)
		}
		addresses, err = manifest.addresses()
		if err != nil {
			return fmt.Errorf("cannot safely determine teardown addresses for %s: %w", ifname, err)
		}
	} else if !errors.Is(manifestErr, os.ErrNotExist) {
		return fmt.Errorf("cannot safely read teardown manifest for %s: %w", ifname, manifestErr)
	}

	pid, err := readDaemonPid(ifname)
	if err != nil {
		return fmt.Errorf("cannot safely stop wgf run %s: %w", ifname, err)
	}

	if err := runHooks("PreDown", parsed.Options.PreDown, ifname, stdout, stderr); err != nil {
		return err
	}
	if parsed.Options.SaveConfig {
		if err := saveRunningConfig(ifname, "", stdout, stderr); err != nil {
			return fmt.Errorf("SaveConfig: %w", err)
		}
	}
	if manifestErr == nil {
		manifest.Phase = "tearing_down"
		if err := writeQuickManifest(ifname, manifest); err != nil {
			return fmt.Errorf("mark teardown state: %w", err)
		}
	}

	blackholes, err := installTeardownBlackholes(planned)
	if err != nil {
		return fmt.Errorf("install teardown blackhole: %w", err)
	}

	if pid != 0 {
		fmt.Fprintf(stdout, "[#] stopping wgf run %s (pid %d)\n", ifname, pid)
		if err := stopDaemon(pid); err != nil {
			return fmt.Errorf("stop wgf run %s: %w", ifname, err)
		}
	}

	link, linkErr := netlink.LinkByName(ifname)
	if linkErr != nil && !isLinkGone(linkErr) {
		return fmt.Errorf("find interface %s for teardown: %w", ifname, linkErr)
	}
	if linkErr == nil {
		if err := deleteOwnedRoutes(link, planned); err != nil {
			return fmt.Errorf("remove routes: %w", err)
		}
		if err := deleteOwnedAddresses(link, addresses); err != nil {
			return fmt.Errorf("remove addresses: %w", err)
		}
	}
	for _, family := range ruleFamilies(planned) {
		if err := deletePolicyRules(family, planned.FwMark, planned.DefaultTable); err != nil {
			return fmt.Errorf("remove policy rules: %w", err)
		}
	}
	if err := removeTeardownBlackholes(blackholes); err != nil {
		return fmt.Errorf("remove teardown blackhole: %w", err)
	}
	if err := removeQuickState(ifname); err != nil {
		return err
	}
	return runHooks("PostDown", parsed.Options.PostDown, ifname, stdout, stderr)
}

func isLinkGone(err error) bool {
	if errors.Is(err, syscall.ENODEV) || errors.Is(err, os.ErrNotExist) {
		return true
	}
	var notFound netlink.LinkNotFoundError
	return errors.As(err, &notFound)
}

func quickSave(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("quick save", flag.ContinueOnError)
	flags.SetOutput(stderr)
	output := flags.String("output", "", "write the configuration to this path instead of the canonical location")

	if len(args) == 0 {
		return errors.New("usage: wgf quick save <interface> [--output <path>]")
	}
	ifname := args[0]
	if err := quick.ValidateName(ifname); err != nil {
		return err
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	return saveRunningConfig(ifname, *output, stdout, stderr)
}

func quickStrip(args []string, stdout io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: wgf quick strip <interface|config-file>")
	}
	target, err := resolveQuickTarget(args[0])
	if err != nil {
		return err
	}
	path := target.path
	// #nosec G703 -- The input path is explicitly selected by the operator.
	text, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	stripped, err := quick.Strip(string(text))
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, stripped)
	return err
}

// saveRunningConfig renders the live peer set over the persistent
// [Interface] section. Instances started from outside the configuration
// directories must pass an explicit output; the runtime snapshot is never the
// persistence authority.
func saveRunningConfig(ifname, output string, stdout, stderr io.Writer) error {
	migrateFrom := ""
	if output == "" {
		origin, err := os.ReadFile(originPath(ifname))
		if err != nil {
			return fmt.Errorf("cannot determine how %s was started: %w", ifname, err)
		}
		destination, legacy, err := saveDestination(ifname, strings.TrimSpace(string(origin)))
		if err != nil {
			return err
		}
		output, migrateFrom = destination, legacy
	}

	status, err := getStatusWithSecrets(context.Background(), controlapi.SocketPath(ifname), ifname)
	if err != nil {
		return fmt.Errorf("is `wgf run %s` running? %w", ifname, err)
	}

	source, err := os.ReadFile(inputPath(ifname))
	if err != nil {
		if source, err = os.ReadFile(snapshotPath(ifname)); err != nil {
			return err
		}
	}
	rendered, err := renderSavedConfig(string(source), status)
	if err != nil {
		return err
	}
	canonicalExisted := false
	if migrateFrom != "" {
		if _, err := os.Stat(output); err == nil {
			canonicalExisted = true
		}
	}
	// #nosec G703 -- The output path is explicitly selected by the operator.
	if err := os.MkdirAll(filepath.Dir(output), 0o700); err != nil {
		return err
	}
	if err := quick.WriteAtomic(output, []byte(rendered)); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "wgf quick: saved %s to %s\n", ifname, output)
	if migrateFrom != "" {
		removeLegacyConfig(migrateFrom, output, canonicalExisted, stdout, stderr)
	}
	return nil
}

// saveDestination resolves where an interface started from recorded persists
// its configuration. migrateFrom names the legacy file this save replaces.
func saveDestination(ifname, recorded string) (output, migrateFrom string, err error) {
	canonical := quick.ConfigPath(ifname)
	switch recorded {
	case canonical:
		return canonical, "", nil
	case quick.LegacyConfigPath(ifname):
		return canonical, recorded, nil
	default:
		return "", "", fmt.Errorf(
			"%s was started from %s; use --output to save explicitly",
			ifname,
			recorded,
		)
	}
}

// removeLegacyConfig drops the legacy configuration this save replaced. A
// failure here must not fail the teardown that triggered the save.
func removeLegacyConfig(legacy, canonical string, canonicalExisted bool, stdout, stderr io.Writer) {
	if canonicalExisted {
		fmt.Fprintf(stderr, "warning: %s already existed; %s was left in place\n", canonical, legacy)
		return
	}
	if err := os.Remove(legacy); err != nil {
		fmt.Fprintf(stderr, "warning: could not remove %s: %v\n", legacy, err)
		return
	}
	fmt.Fprintf(stdout, "wgf quick: removed legacy %s\n", legacy)
}

// daemonLogDir receives the detached daemon's output outside systemd. An
// interactive parent must not hand its own stdio to the daemon: an ssh
// session would never see EOF, and a later closed pipe kills the daemon
// with SIGPIPE on its next log line.
const daemonLogDir = "/var/log/wg-frag"

func spawnDaemon(ifname string, stdout, stderr io.Writer) (int, error) {
	self, err := os.Executable()
	if err != nil {
		return 0, err
	}
	// The daemon intentionally outlives quick up, so its context is not cancelled.
	// #nosec G702 -- The executable is resolved by os.Executable and arguments are not shell-interpreted.
	cmd := exec.CommandContext(context.Background(), self, "run", ifname, "--config", snapshotPath(ifname))
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	logPath := "journal"

	if os.Getenv("INVOCATION_ID") != "" {
		// Under systemd the inherited descriptors are the journal, which
		// outlives this process.
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		if err := os.MkdirAll(daemonLogDir, 0o700); err != nil {
			return 0, err
		}
		logPath = filepath.Join(daemonLogDir, ifname+".log")
		// #nosec G703 -- ifname was validated before constructing this log path.
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			return 0, err
		}

		defer func() { _ = logFile.Close() }()

		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}

	if err := cmd.Start(); err != nil {
		return 0, err
	}
	pid := cmd.Process.Pid
	fmt.Fprintf(stdout, "[#] wgf run %s --config %s (pid %d, log %s)\n", ifname, snapshotPath(ifname), pid, logPath)

	if err := quick.WriteAtomic(pidPath(ifname), []byte(strconv.Itoa(pid)+"\n")); err != nil {
		_ = stopDaemon(pid)
		return 0, err
	}
	// The daemon outlives this process; reap it if it exits while we wait.
	go func() { _, _ = cmd.Process.Wait() }()
	return pid, nil
}

func waitDaemonReady(ifname string, pid int) error {
	deadline := time.Now().Add(daemonReadyTimeout)
	socket := controlapi.SocketPath(ifname)

	for time.Now().Before(deadline) {
		alive, err := daemonCommandMatches(pid, ifname)
		if err != nil || !alive {
			return fmt.Errorf("wgf run %s exited during startup; check its log output", ifname)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, err = getStatus(ctx, socket, ifname)
		cancel()
		if err == nil {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("wgf run %s did not become ready within %s", ifname, daemonReadyTimeout)
}

// readDaemonPid returns the recorded pid only when it still names a live wgf
// daemon for this interface, so a recycled pid is never signaled.
func readDaemonPid(ifname string) (int, error) {
	return readDaemonPidFromPaths(ifname, pidPath(ifname), controlapi.SocketPath(ifname))
}

func readDaemonPidFromPaths(ifname, pidFile, socketPath string) (int, error) {
	content, err := os.ReadFile(pidFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			alive, probeErr := daemonSocketAlive(socketPath)
			if probeErr != nil {
				return 0, probeErr
			}
			if alive {
				return 0, fmt.Errorf("pid file for wgf run %s is missing while its control socket is live", ifname)
			}
			return 0, nil
		}
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil || pid <= 1 {
		return 0, fmt.Errorf("invalid pid file for %s", ifname)
	}
	alive, err := daemonCommandMatches(pid, ifname)
	if err != nil {
		return 0, err
	}
	if !alive {
		if _, statErr := os.Stat(fmt.Sprintf("/proc/%d", pid)); errors.Is(statErr, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("pid %d is not wgf run %s", pid, ifname)
	}
	return pid, nil
}

func daemonSocketAlive(path string) (bool, error) {
	conn, err := net.DialTimeout("unix", path, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return false, nil
	}
	return false, fmt.Errorf("probe daemon socket: %w", err)
}

func daemonCommandMatches(pid int, ifname string) (bool, error) {
	cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("inspect wgf run %s: %w", ifname, err)
	}
	arguments := strings.Split(string(cmdline), "\x00")
	if len(arguments) < 3 || arguments[1] != "run" || arguments[2] != ifname {
		return false, nil
	}
	return true, nil
}

func stopDaemon(pid int) error {
	if pid <= 1 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	deadline := time.Now().Add(daemonStopTimeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return nil
			}
			return fmt.Errorf("check process %d: %w", pid, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	if err := syscall.Kill(pid, 0); err == nil {
		return fmt.Errorf("process %d did not exit after SIGKILL", pid)
	} else if !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("check process %d after SIGKILL: %w", pid, err)
	}
	return nil
}

func tableSuffix(table uint32) string {
	if table == 0 {
		return ""
	}
	return fmt.Sprintf(" table %d", table)
}

func readRouteTablePath(path string) (uint32, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	table, err := strconv.ParseUint(strings.TrimSpace(string(text)), 10, 32)
	if err != nil || table == 0 {
		return 0, fmt.Errorf("invalid route state for %s", path)
	}
	return uint32(table), nil
}

func chooseAutoTable(plan quick.RoutePlan) (quick.RoutePlan, error) {
	if plan.DefaultTable == 0 {
		return plan, nil
	}

	for candidate := plan.DefaultTable; candidate < plan.DefaultTable+autoTableAttempts; candidate++ {
		available, err := routeTableAvailable(candidate)
		if err != nil {
			return quick.RoutePlan{}, err
		}

		if available {
			plan.FwMark = candidate
			plan.DefaultTable = candidate
			return plan, nil
		}
	}
	return quick.RoutePlan{}, fmt.Errorf(
		"no free routing table in %d..%d",
		plan.DefaultTable,
		plan.DefaultTable+autoTableAttempts-1,
	)
}

func routeTableAvailable(table uint32) (bool, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_ALL,
		&netlink.Route{Table: int(table)},
		netlink.RT_FILTER_TABLE,
	)
	if err != nil {
		return false, fmt.Errorf("list route table %d: %w", table, err)
	}
	if len(routes) != 0 {
		return false, nil
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			return false, fmt.Errorf("list policy rules: %w", err)
		}

		for _, rule := range rules {
			if rule.Table == int(table) || rule.Mark == table {
				return false, nil
			}
		}
	}
	return true, nil
}

func prefixToAddr(prefix netip.Prefix) (*netlink.Addr, error) {
	address, err := netlink.ParseAddr(prefix.String())
	if err != nil {
		return nil, err
	}
	return address, nil
}

func addRoute(link netlink.Link, prefix netip.Prefix, table uint32) error {
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		},
	}
	if table != 0 {
		route.Table = int(table)
	}
	return netlink.RouteAdd(route)
}

func ruleFamilies(plan quick.RoutePlan) []int {
	families := []int{}
	if plan.RulesV4 {
		families = append(families, netlink.FAMILY_V4)
	}
	if plan.RulesV6 {
		families = append(families, netlink.FAMILY_V6)
	}
	return families
}

func familyFlag(family int) string {
	if family == netlink.FAMILY_V6 {
		return "-6"
	}
	return "-4"
}

func policyRules(family int, mark, table uint32) []*netlink.Rule {
	exempt := netlink.NewRule()
	exempt.Family = family
	exempt.Invert = true
	exempt.Mark = mark
	exempt.Table = int(table)
	exempt.Priority = ruleFwmarkPriority

	suppress := netlink.NewRule()
	suppress.Family = family
	suppress.Table = 254 // main
	suppress.SuppressPrefixlen = 0
	suppress.Priority = ruleSuppressPriority
	return []*netlink.Rule{exempt, suppress}
}

func addPolicyRules(family int, mark, table uint32) error {
	var added []*netlink.Rule

	for _, rule := range policyRules(family, mark, table) {
		if err := netlink.RuleAdd(rule); err != nil {
			for i := len(added) - 1; i >= 0; i-- {
				_ = netlink.RuleDel(added[i])
			}
			return fmt.Errorf("add rule (family %d): %w", family, err)
		}

		added = append(added, rule)
	}
	return nil
}

func deletePolicyRules(family int, mark, table uint32) error {
	var firstErr error
	for _, rule := range policyRules(family, mark, table) {
		if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func teardownBlackholeRules(plan quick.RoutePlan) []*netlink.Rule {
	rules := make([]*netlink.Rule, 0, len(plan.Specific)+2)
	if plan.DefaultTable != 0 {
		for _, family := range ruleFamilies(plan) {
			rule := netlink.NewRule()
			rule.Family = family
			rule.Priority = ruleBlackholePriority
			rule.Type = unix.RTN_BLACKHOLE
			rule.Invert = true
			rule.Mark = plan.FwMark
			rules = append(rules, rule)
		}
	}
	for _, prefix := range plan.Specific {
		rule := netlink.NewRule()
		rule.Family = netlink.FAMILY_V4
		if prefix.Addr().Is6() {
			rule.Family = netlink.FAMILY_V6
		}
		rule.Priority = ruleBlackholePriority
		rule.Type = unix.RTN_BLACKHOLE
		rule.Dst = &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		}
		rules = append(rules, rule)
	}
	return rules
}

func installTeardownBlackholes(plan quick.RoutePlan) ([]*netlink.Rule, error) {
	rules := teardownBlackholeRules(plan)
	added := make([]*netlink.Rule, 0, len(rules))
	for _, rule := range rules {
		if err := netlink.RuleAdd(rule); err != nil {
			if !errors.Is(err, syscall.EEXIST) || !ruleExists(rule) {
				for i := len(added) - 1; i >= 0; i-- {
					_ = netlink.RuleDel(added[i])
				}
				return nil, err
			}
			continue
		}
		added = append(added, rule)
	}
	return rules, nil
}

func removeTeardownBlackholes(rules []*netlink.Rule) error {
	var firstErr error
	for _, rule := range rules {
		if err := netlink.RuleDel(rule); err != nil && !errors.Is(err, syscall.ENOENT) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func ruleExists(want *netlink.Rule) bool {
	rules, err := netlink.RuleList(want.Family)
	if err != nil {
		return false
	}
	for _, got := range rules {
		if got.Priority != want.Priority || got.Family != want.Family || got.Type != want.Type ||
			got.Mark != want.Mark || got.Invert != want.Invert || !sameRuleDestination(got.Dst, want.Dst) {
			continue
		}
		return true
	}
	return false
}

func sameRuleDestination(left, right *net.IPNet) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.String() == right.String()
}

func deleteOwnedRoutes(link netlink.Link, plan quick.RoutePlan) error {
	for _, prefix := range plan.Specific {
		if err := deleteRoute(link, prefix, plan.SpecificTable); err != nil {
			return err
		}
	}
	for _, prefix := range plan.Defaults {
		if err := deleteRoute(link, prefix, plan.DefaultTable); err != nil {
			return err
		}
	}
	return nil
}

func deleteRoute(link netlink.Link, prefix netip.Prefix, table uint32) error {
	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   prefix.Addr().AsSlice(),
			Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
		},
	}
	if table != 0 {
		route.Table = int(table)
	}
	if err := netlink.RouteDel(route); err != nil && !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("delete route %s: %w", prefix, err)
	}
	return nil
}

func deleteOwnedAddresses(link netlink.Link, prefixes []netip.Prefix) error {
	for _, prefix := range prefixes {
		address, err := prefixToAddr(prefix)
		if err != nil {
			return fmt.Errorf("parse address %s: %w", prefix, err)
		}
		if err := netlink.AddrDel(link, address); err != nil && !errors.Is(err, syscall.ENOENT) {
			return fmt.Errorf("delete address %s: %w", prefix, err)
		}
	}
	return nil
}

func removeQuickState(ifname string) error {
	paths := []string{
		snapshotPath(ifname), originPath(ifname), inputPath(ifname), routePath(ifname), pidPath(ifname),
		manifestPath(ifname), controlapi.SocketPath(ifname),
	}
	for _, path := range paths {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove runtime state %s: %w", path, err)
		}
	}
	return nil
}
