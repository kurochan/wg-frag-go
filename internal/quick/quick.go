// Package quick implements the wg-quick-compatible configuration layer: the
// split between quick-only keys (routing, hooks) and the runtime configuration
// the daemon accepts, plus the canonical save path handling.
package quick

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/config/syntax"
)

// ConfigDir is the canonical location for persistent quick configurations.
const ConfigDir = "/etc/wg-frag"

// RuntimeDir holds ephemeral daemon startup snapshots; it is never the
// authority for persistent configuration.
const RuntimeDir = "/run/wg-frag"

var ErrInvalidName = errors.New("quick: interface name must be 1..15 characters of [a-zA-Z0-9_=+.-]")

// TableMode selects how quick installs routes for peer AllowedIPs.
type TableMode struct {
	// Off disables all route installation.
	Off bool
	// Table is an explicit routing table number; zero with Off=false is auto.
	Table uint32
}

// Auto reports the default behavior: main table for specific prefixes and
// policy routing for default routes.
func (m TableMode) Auto() bool { return !m.Off && m.Table == 0 }

// Options are the quick-only keys extracted from a configuration file. All
// remaining lines form the runtime configuration passed to the daemon.
type Options struct {
	TableMode  TableMode
	SaveConfig bool
	PreUp      []string
	PostUp     []string
	PreDown    []string
	PostDown   []string
	// DNS values are recognized for wg-quick compatibility but unsupported;
	// callers warn and continue.
	DNS []string
}

// Parsed is a quick configuration split into its two halves.
type Parsed struct {
	Options Options
	// Runtime is the stripped configuration text accepted by wgf run.
	Runtime string
	// Config is the parsed runtime configuration.
	Config *config.Config
}

func quickOnlyKey(key string) bool {
	switch key {
	case "Table", "SaveConfig", "PreUp", "PostUp", "PreDown", "PostDown", "DNS":
		return true
	default:
		return false
	}
}

// ValidateName enforces Linux interface-name limits before the name is used
// in paths and shell hook substitution.
func ValidateName(name string) error {
	if name == "" || len(name) > 15 {
		return ErrInvalidName
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '_' || r == '=' || r == '+' || r == '.' || r == '-':
		default:
			return ErrInvalidName
		}
	}
	return nil
}

// ConfigPath returns the canonical configuration path for a name already
// accepted by ValidateName.
func ConfigPath(name string) string {
	return filepath.Join(ConfigDir, name+".conf")
}

// Parse splits text into quick options and runtime configuration, then
// validates the runtime half with the daemon's own parser.
func Parse(text string) (Parsed, error) {
	options, runtime, err := split(text)
	if err != nil {
		return Parsed{}, err
	}
	cfg, err := config.Parse(strings.NewReader(runtime))
	if err != nil {
		return Parsed{}, err
	}
	return Parsed{Options: options, Runtime: runtime, Config: cfg}, nil
}

// Strip returns only the runtime half, preserving the original line text of
// every kept line so comments survive like wg-quick strip.
func Strip(text string) (string, error) {
	_, runtime, err := split(text)
	if err != nil {
		return "", err
	}
	return runtime, nil
}

// split walks the file once. Only [Interface] can contain quick-only keys;
// they are invalid in [Peer], matching wg-quick.
func split(text string) (Options, string, error) {
	options := Options{}

	var runtime strings.Builder
	inInterface := false
	err := syntax.Scan(strings.NewReader(text), func(source syntax.Line) error {
		raw := source.Raw
		if source.IsSection {
			inInterface = source.Section == "Interface"
		}
		if !inInterface || !source.IsField || !quickOnlyKey(source.Key) {
			runtime.WriteString(raw)
			runtime.WriteByte('\n')
			return nil
		}
		if err := options.apply(source.Key, source.Value); err != nil {
			return fmt.Errorf("line %d: %w", source.Number, err)
		}
		return nil
	})
	if err != nil {
		return Options{}, "", err
	}
	return options, runtime.String(), nil
}

func (o *Options) apply(key, value string) error {
	if value == "" {
		return fmt.Errorf("%s: empty value", key)
	}

	switch key {
	case "Table":
		switch value {
		case "off":
			o.TableMode = TableMode{Off: true}
		case "auto":
			o.TableMode = TableMode{}
		case "main":
			// Explicit main matches auto for specific prefixes; default routes
			// still use policy routing because main would capture the tunnel's
			// own endpoint traffic.
			o.TableMode = TableMode{}
		default:
			table, err := strconv.ParseUint(value, 0, 32)
			if err != nil || table == 0 {
				return errors.New("Table: must be auto, off, main, or a table number")
			}
			o.TableMode = TableMode{Table: uint32(table)}
		}
	case "SaveConfig":
		switch value {
		case "true":
			o.SaveConfig = true
		case "false":
			o.SaveConfig = false
		default:
			return errors.New("SaveConfig: must be true or false")
		}
	case "PreUp":
		o.PreUp = append(o.PreUp, value)
	case "PostUp":
		o.PostUp = append(o.PostUp, value)
	case "PreDown":
		o.PreDown = append(o.PreDown, value)
	case "PostDown":
		o.PostDown = append(o.PostDown, value)
	case "DNS":
		o.DNS = append(o.DNS, value)
	}
	return nil
}

// WriteAtomic writes content to path with mode 0600 via a temporary file in
// the same directory and an atomic rename, so a crash cannot leave a partial
// or world-readable configuration.
func WriteAtomic(path string, content []byte) error {
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}

	defer func() {
		if temporary != nil {
			_ = temporary.Close()
			_ = os.Remove(temporary.Name())
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	name := temporary.Name()
	if err := temporary.Close(); err != nil {
		temporary = nil
		_ = os.Remove(name)
		return err
	}
	temporary = nil
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

// WarnLoosePermissions reports a non-empty warning when the configuration is
// readable by group or others, mirroring wg-quick's advice.
func WarnLoosePermissions(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return fmt.Sprintf(
			"warning: %s has mode %04o; private keys should not be readable by "+
				"other users (chmod 600)",
			path,
			mode,
		)
	}
	return ""
}
