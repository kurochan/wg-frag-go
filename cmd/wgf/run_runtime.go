//go:build linux || darwin

package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/kurochan/wg-frag-go/controlapi"
	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/controlconfig"
	"github.com/kurochan/wg-frag-go/internal/metrics"
	publicmanager "github.com/kurochan/wg-frag-go/manager"
	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
)

const managerShutdownTimeout = 10 * time.Second

// runConfiguredInterface owns the portable daemon lifecycle after each
// platform has supplied its TUN and no-fragment UDP Bind implementation.
func runConfiguredInterface(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] == "" || args[0][0] == '-' {
		return errors.New("run requires exactly one interface name")
	}
	ifname := args[0]
	cfg, controlSocket, err := parseRunConfig(args[1:], stderr)
	if err != nil {
		return err
	}
	logger := newAppLogger(stderr)
	warnUnwiredConcurrencyOptions(cfg, logger)
	manager, err := publicmanager.New(publicmanager.Options{MaxInterfaces: 1, Logger: logger})
	if err != nil {
		return err
	}
	defer closeManager(manager, logger)
	if err := createInitialInterface(context.Background(), manager, ifname, cfg); err != nil {
		return err
	}
	return serveManager(manager, ifname, cfg.Interface, controlSocket, logger)
}

func createInitialInterface(ctx context.Context, manager *publicmanager.Manager, ifname string, cfg *config.Config) error {
	if manager == nil || cfg == nil {
		return errors.New("invalid initial interface configuration")
	}
	spec := controlconfig.SpecFromConfig(ifname, cfg, true)
	spec.SetPrivateKey(append([]byte(nil), cfg.Interface.PrivateKey[:]...))
	requestID := make([]byte, 16)
	if _, err := rand.Read(requestID); err != nil {
		return fmt.Errorf("generate create request ID: %w", err)
	}
	request := controlapiv1.CreateInterfaceRequest_builder{}.Build()
	request.SetRequestId(requestID)
	request.SetSpec(spec)
	_, err := manager.CreateInterface(ctx, request)
	return err
}

func parseRunConfig(args []string, stderr io.Writer) (*config.Config, string, error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "", "path to a wgf configuration file")
	controlSocket := flags.String("control-socket", "", "management socket path")
	if err := flags.Parse(args); err != nil {
		return nil, "", err
	}
	if *path == "" {
		return nil, "", errors.New("run requires --config")
	}
	if flags.NArg() != 0 {
		return nil, "", fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	cfg, err := config.ParseFile(*path)
	if err != nil {
		return nil, "", err
	}
	return cfg, *controlSocket, nil
}

func runManagerCommand(args []string, _ io.Writer, stderr io.Writer) error {
	flags := flag.NewFlagSet("manager", flag.ContinueOnError)
	flags.SetOutput(stderr)
	controlSocket := flags.String("control-socket", controlapi.ManagerSocketPath(), "management socket path")
	maxInterfaces := flags.Int("max-interfaces", publicmanager.DefaultMaxInterfaces, "maximum managed interfaces")
	metricsEnabled := flags.Bool("metrics", false, "enable the process OpenMetrics endpoint")
	var metricsListen, metricsInclude, metricsExclude stringListFlag
	flags.Var(&metricsListen, "metrics-listen", "OpenMetrics listen address; repeat for multiple addresses")
	flags.Var(&metricsInclude, "metrics-include", "included metric family pattern; repeat as needed")
	flags.Var(&metricsExclude, "metrics-exclude", "excluded metric family pattern; repeat as needed")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}
	if *maxInterfaces <= 0 {
		return errors.New("max-interfaces must be positive")
	}
	if !*metricsEnabled && (len(metricsListen) != 0 || len(metricsInclude) != 0 || len(metricsExclude) != 0) {
		return errors.New("manager metrics options require --metrics")
	}
	metricsConfig := config.Default().Interface
	metricsConfig.Metrics = *metricsEnabled
	metricsConfig.MetricsInclude = append([]string(nil), metricsInclude...)
	metricsConfig.MetricsExclude = append([]string(nil), metricsExclude...)
	if *metricsEnabled {
		if len(metricsListen) == 0 {
			return errors.New("manager --metrics requires at least one --metrics-listen")
		}
		parsedListen, err := config.ParseMetricsListen(strings.Join(metricsListen, ","))
		if err != nil {
			return fmt.Errorf("manager metrics listen: %w", err)
		}
		if parsedListen.Auto {
			return errors.New("manager metrics listen must be an explicit IP address and port")
		}
		metricsConfig.MetricsListen = parsedListen
		if _, err := metrics.NewSelector(metricsConfig.MetricsInclude, metricsConfig.MetricsExclude); err != nil {
			return err
		}
	}
	logger := newAppLogger(stderr)
	manager, err := publicmanager.New(publicmanager.Options{MaxInterfaces: *maxInterfaces, Logger: logger})
	if err != nil {
		return err
	}
	defer closeManager(manager, logger)
	return serveManager(manager, "", metricsConfig, *controlSocket, logger)
}

func closeManager(manager *publicmanager.Manager, logger *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), managerShutdownTimeout)
	defer cancel()
	if err := manager.Close(ctx); err != nil {
		logger.Warn("manager shutdown did not complete", "error", err)
	}
}

type stringListFlag []string

func (values *stringListFlag) String() string {
	return strings.Join(*values, ",")
}

func (values *stringListFlag) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func warnUnwiredConcurrencyOptions(cfg *config.Config, logger *slog.Logger) {
	if cfg == nil || (cfg.Interface.Workers.Auto && cfg.Interface.TUNQueues.Auto) {
		return
	}
	logger.Warn("WGFWorkers and WGFTUNQueues are not active; using one shim worker and one TUN queue")
}

func serveManager(
	manager *publicmanager.Manager,
	primaryInterface string,
	metricsConfig config.Interface,
	controlSocket string,
	logger *slog.Logger,
) error {
	if manager == nil || logger == nil {
		return errors.New("invalid manager")
	}
	var metricsListener *metricsServer
	if metricsConfig.Metrics {
		var metricsErr error
		metricsListener, metricsErr = startManagerMetrics(manager, primaryInterface, metricsConfig, logger)
		if metricsErr != nil {
			logger.Warn("metrics disabled", "error", metricsErr)
		} else {
			defer func() {
				if closeErr := metricsListener.Close(); closeErr != nil {
					logger.Warn("metrics listener shutdown failed", "error", closeErr)
				}
				logger.Info("metrics listener stopped")
			}()
		}
	}
	if controlSocket == "" {
		if primaryInterface == "" {
			return errors.New("manager mode requires a control socket")
		}
		controlSocket = controlapi.SocketPath(primaryInterface)
	}
	api, err := controlapi.ServeUnix(controlapi.ServerConfig{
		SocketPath: controlSocket,
		Service:    manager,
	})
	if err != nil {
		return err
	}
	defer api.Close()
	stopProfile, err := startCPUProfile()
	if err != nil {
		return err
	}
	defer stopProfile()
	logger.Info("manager started", "interfaces", manager.InterfaceCount(), "control_socket", controlSocket)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)
	defer signal.Stop(signals)
	for received := range signals {
		if received == syscall.SIGUSR1 {
			manager.DumpStats()
			continue
		}
		logger.Info("shutdown requested", "signal", received.String())
		return nil
	}
	return nil
}

func startManagerMetrics(
	manager *publicmanager.Manager,
	primaryInterface string,
	metricsConfig config.Interface,
	logger *slog.Logger,
) (*metricsServer, error) {
	var port uint16
	if metricsConfig.MetricsListen.Auto {
		if primaryInterface == "" {
			return nil, errors.New("manager metrics require an explicit listen address")
		}
		var err error
		port, err = manager.EffectiveListenPort(primaryInterface)
		if err != nil {
			return nil, err
		}
	}
	return startMetricsServerRenderer(metricsConfig, port, logger, func() ([]byte, error) {
		return manager.GatherOpenMetrics(metricsConfig.MetricsInclude, metricsConfig.MetricsExclude)
	})
}

func startCPUProfile() (func(), error) {
	path := os.Getenv("WGF_CPU_PROFILE")
	if path == "" {
		return func() {}, nil
	}
	// #nosec G703 -- The profile path is an explicit operator diagnostic setting.
	profile, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(profile); err != nil {
		_ = profile.Close()
		return nil, err
	}
	return func() {
		pprof.StopCPUProfile()
		_ = profile.Close()
	}, nil
}
