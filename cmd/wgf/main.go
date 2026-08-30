// Command wgf manages wg-frag-go interfaces.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/kurochan/wg-frag-go/internal/controlapi"
	"github.com/kurochan/wg-frag-go/internal/quick"
	"github.com/kurochan/wg-frag-go/internal/version"
	"github.com/kurochan/wg-frag-go/internal/wgadapter"
)

func main() {
	args := os.Args[1:]
	// The wgf-quick program name is an alias for the quick subcommand, avoiding
	// a second binary for wg-quick-style invocation.
	if strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") == "wgf-quick" {
		args = append([]string{"quick"}, args...)
	}

	if err := run(args, os.Stdout, os.Stderr); err != nil {
		newAppLogger(os.Stderr).Error("command failed", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		usage(stdout)
		return nil
	}

	switch args[0] {
	case "help", "--help", "-h":
		usage(stdout)
		return nil
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "wgf %s\n", version.String())
		return nil
	case "genkey":
		return genkey(args[1:], stdout)
	case "genpsk":
		return genpsk(args[1:], stdout)
	case "pubkey":
		return pubkey(args[1:], os.Stdin, stdout)
	case "check":
		return check(args[1:], stdout, stderr)
	case "run":
		return runCommand(args[1:], stdout, stderr)
	case "quick":
		return quickCommand(args[1:], stdout, stderr)
	case "show":
		return show(args[1:], controlapi.GetStatus, stdout)
	case "showconf":
		return showconf(args[1:], controlapi.GetStatusWithSecrets, stdout)
	case "set":
		return setCommand(args[1:], controlapi.GetStatus, controlapi.ApplyConfig, stdout)
	case "setconf":
		return setconf(confSet, args[1:], controlapi.GetStatus, controlapi.ApplyConfig, stdout)
	case "addconf":
		return setconf(confAdd, args[1:], controlapi.GetStatus, controlapi.ApplyConfig, stdout)
	case "syncconf":
		return setconf(confSync, args[1:], controlapi.GetStatus, controlapi.ApplyConfig, stdout)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func check(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(stderr)

	path := flags.String("config", "", "path to a wgf configuration file")
	if err := flags.Parse(args); err != nil {
		return err
	}

	if *path == "" {
		return errors.New("check requires --config")
	}

	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q", flags.Arg(0))
	}

	text, err := os.ReadFile(*path)
	if err != nil {
		return err
	}
	parsed, err := quick.Parse(string(text))
	if err != nil {
		return err
	}

	if _, err := wgadapter.PreparePeers(parsed.Config); err != nil {
		return err
	}

	fmt.Fprintln(stdout, "configuration is valid")
	return nil
}

func usage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: wgf <command>")
	fmt.Fprintln(writer, "\ncommands:")
	fmt.Fprintln(writer, "  version  print the build version")
	fmt.Fprintln(writer, "  genkey  generate a WireGuard private key")
	fmt.Fprintln(writer, "  genpsk  generate a preshared key")
	fmt.Fprintln(writer, "  pubkey  derive a WireGuard public key from standard input")
	fmt.Fprintln(writer, "  show [IFNAME|all|interfaces] [fragment|path-mtu|stats]  print running status")
	fmt.Fprintln(writer, "  showconf IFNAME  print the running configuration in setconf syntax")
	fmt.Fprintln(
		writer,
		"  set IFNAME peer KEY [remove|endpoint|allowed-ips|persistent-keepalive] ... "+
			" change peers at runtime",
	)
	fmt.Fprintln(writer, "  setconf IFNAME FILE  replace the running peer set with the file's peers")
	fmt.Fprintln(writer, "  addconf IFNAME FILE  add the file's peers to the running set")
	fmt.Fprintln(writer, "  syncconf IFNAME FILE  same as setconf; existing sessions are preserved")
	fmt.Fprintln(writer, "  check --config PATH  validate a WGF configuration")
	fmt.Fprintln(writer, "  run IFNAME --config PATH  run one interface in the foreground")
	fmt.Fprintln(writer, "  quick up|down|save|strip ARG  wg-quick style lifecycle (also as wgf-quick)")
}
