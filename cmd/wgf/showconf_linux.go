//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/kurochan/wg-frag-go/controlapi"
	"github.com/kurochan/wg-frag-go/internal/quick"
)

// showconf renders the running configuration in setconf-compatible syntax.
// The [Interface] identity comes from the daemon's runtime snapshot because
// the control API deliberately never exposes the private key; peers come from
// the live daemon so runtime set/setconf changes are included.
func showconf(args []string, getStatus statusGetter, stdout io.Writer) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: wgf showconf <interface>")
	}
	ifname := args[0]
	if err := quick.ValidateName(ifname); err != nil {
		return err
	}
	source, err := os.ReadFile(snapshotPath(ifname))
	if err != nil {
		return fmt.Errorf("showconf needs the runtime snapshot written by wgf quick up: %w", err)
	}
	runtime, err := quick.Strip(string(source))
	if err != nil {
		return err
	}
	status, err := getStatus(context.Background(), controlapi.SocketPath(ifname), ifname)
	if err != nil {
		return fmt.Errorf("is `wgf run %s` running? %w", ifname, err)
	}
	rendered, err := renderSavedConfig(runtime, status)
	if err != nil {
		return err
	}
	_, err = io.WriteString(stdout, rendered)
	return err
}
