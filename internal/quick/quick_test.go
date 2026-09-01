package quick

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kurochan/wg-frag-go/internal/config"
)

const sampleConfig = `# tunnel to hq
[Interface]
Address = 10.9.0.2/24
PrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=
ListenPort = 51820
MTU = 1420
Table = off
SaveConfig = true
PreUp = echo pre-up %i
PostUp = echo post-up %i
PreDown = echo pre-down %i
PostDown = echo post-down %i
DNS = 10.9.0.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
Endpoint = 203.0.113.5:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`

func TestParseSplitsQuickOnlyKeys(t *testing.T) {
	t.Parallel()
	parsed, err := Parse(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	options := parsed.Options
	if !options.TableMode.Off || !options.SaveConfig || len(options.DNS) != 1 {
		t.Fatalf("options = %+v", options)
	}
	for _, hooks := range [][]string{options.PreUp, options.PostUp, options.PreDown, options.PostDown} {
		if len(hooks) != 1 {
			t.Fatalf("hooks = %+v", options)
		}
	}
	if parsed.Config.Interface.ListenPort != 51820 || len(parsed.Config.Peers) != 1 {
		t.Fatalf("runtime config = %+v", parsed.Config)
	}
	if len(parsed.Config.Interface.Addresses) != 1 {
		t.Fatal("Address must stay in the runtime configuration")
	}
	for _, key := range []string{"Table", "SaveConfig", "PreUp", "PostUp", "PreDown", "PostDown", "DNS"} {
		if strings.Contains(parsed.Runtime, key+" =") || strings.Contains(parsed.Runtime, key+"=") {
			t.Fatalf("runtime retains quick-only key %s:\n%s", key, parsed.Runtime)
		}
	}
	if !strings.Contains(parsed.Runtime, "# tunnel to hq") {
		t.Fatal("strip must preserve comments")
	}
}

func TestStripOutputIsAcceptedByConfigParser(t *testing.T) {
	t.Parallel()
	runtime, err := Strip(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(strings.NewReader(runtime)); err != nil {
		t.Fatalf("stripped runtime is not accepted by config parser: %v\n%s", err, runtime)
	}
}

func TestParseTableModes(t *testing.T) {
	t.Parallel()
	base := "[Interface]\nPrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=\nTable = %s\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/24\n"
	cases := []struct {
		value string
		off   bool
		table uint32
	}{
		{value: "auto"},
		{value: "main"},
		{value: "off", off: true},
		{value: "123", table: 123},
	}
	for _, c := range cases {
		parsed, err := Parse(strings.ReplaceAll(base, "%s", c.value))
		if err != nil {
			t.Fatalf("Table=%s: %v", c.value, err)
		}
		if parsed.Options.TableMode.Off != c.off || parsed.Options.TableMode.Table != c.table {
			t.Fatalf("Table=%s parsed as %+v", c.value, parsed.Options.TableMode)
		}
	}
	if _, err := Parse(strings.ReplaceAll(base, "%s", "0")); err == nil {
		t.Fatal("Table=0 must be rejected")
	}
}

func TestQuickKeysRejectedInPeerSection(t *testing.T) {
	t.Parallel()
	text := "[Interface]\nPrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=\n\n[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/24\nTable = off\n"
	if _, err := Parse(text); err == nil {
		t.Fatal("Table inside [Peer] must fail runtime validation")
	}
}

func TestValidateName(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"wgf0", "wg-hq.1", "a_B=+."} {
		if err := ValidateName(name); err != nil {
			t.Fatalf("ValidateName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "0123456789abcdef", "wg/0", "wg 0", "wg\x00"} {
		if err := ValidateName(name); err == nil {
			t.Fatalf("ValidateName(%q) accepted", name)
		}
	}
}

func TestConfigPathUsesCanonicalDirectory(t *testing.T) {
	t.Parallel()
	if got, want := ConfigPath("wgf0"), "/etc/wgf/wgf0.conf"; got != want {
		t.Fatalf("ConfigPath() = %q, want %q", got, want)
	}
}

func TestResolveConfigPathPrefersCanonicalDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	dir := filepath.Join(root, "wgf")
	legacyDir := filepath.Join(root, "wg-frag")
	for _, made := range []string{dir, legacyDir} {
		if err := os.MkdirAll(made, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write := func(directory string) string {
		path := filepath.Join(directory, "wgf0.conf")
		if err := os.WriteFile(path, []byte("[Interface]\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// No file in either directory resolves to the canonical path.
	if got, legacy := resolveConfigPath(dir, legacyDir, "wgf0"); got != filepath.Join(dir, "wgf0.conf") || legacy {
		t.Fatalf("resolveConfigPath() = (%q, %v), want canonical", got, legacy)
	}

	legacyPath := write(legacyDir)
	if got, legacy := resolveConfigPath(dir, legacyDir, "wgf0"); got != legacyPath || !legacy {
		t.Fatalf("resolveConfigPath() = (%q, %v), want (%q, true)", got, legacy, legacyPath)
	}

	canonicalPath := write(dir)
	if got, legacy := resolveConfigPath(dir, legacyDir, "wgf0"); got != canonicalPath || legacy {
		t.Fatalf("resolveConfigPath() = (%q, %v), want (%q, false)", got, legacy, canonicalPath)
	}
}

func TestWriteAtomicModeAndContent(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wgf0.conf")
	if err := WriteAtomic(path, []byte("data\n")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o, want 0600", info.Mode().Perm())
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "data\n" {
		t.Fatalf("content = %q, %v", content, err)
	}
	if entries, err := os.ReadDir(filepath.Dir(path)); err != nil || len(entries) != 1 {
		t.Fatalf("directory entries = %d, %v (temporary file leak)", len(entries), err)
	}
}

func TestWarnLoosePermissions(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wgf0.conf")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if warning := WarnLoosePermissions(path); warning == "" {
		t.Fatal("0644 configuration produced no warning")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if warning := WarnLoosePermissions(path); warning != "" {
		t.Fatalf("0600 configuration warned: %s", warning)
	}
}

func TestPlanRoutesAutoWithDefaults(t *testing.T) {
	t.Parallel()
	parsed, err := Parse(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Options.TableMode = TableMode{} // auto
	plan := PlanRoutes(parsed.Options, parsed.Config)
	if len(plan.Defaults) != 2 || len(plan.Specific) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.FwMark != DefaultRouteTable || plan.DefaultTable != DefaultRouteTable {
		t.Fatalf("fwmark/table = %d/%d", plan.FwMark, plan.DefaultTable)
	}
	if !plan.RulesV4 || !plan.RulesV6 {
		t.Fatalf("rules = v4:%t v6:%t", plan.RulesV4, plan.RulesV6)
	}
}

func TestPlanRoutesExplicitTableSkipsRules(t *testing.T) {
	t.Parallel()
	parsed, err := Parse(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Options.TableMode = TableMode{Table: 77}
	plan := PlanRoutes(parsed.Options, parsed.Config)
	if len(plan.Specific) != 2 || plan.SpecificTable != 77 || len(plan.Defaults) != 0 {
		t.Fatalf("plan = %+v", plan)
	}
	if plan.FwMark != 0 || plan.RulesV4 || plan.RulesV6 {
		t.Fatalf("explicit table must not install rules: %+v", plan)
	}
}

func TestPlanRoutesOff(t *testing.T) {
	t.Parallel()
	parsed, err := Parse(sampleConfig)
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanRoutes(parsed.Options, parsed.Config)
	if len(plan.Specific)+len(plan.Defaults) != 0 {
		t.Fatalf("Table=off installed routes: %+v", plan)
	}
}

func TestInjectFwMark(t *testing.T) {
	t.Parallel()
	runtime := "# c\n[Interface]\nPrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=\n"
	injected := InjectFwMark(runtime, 51820)
	parsed, err := Parse(injected)
	if err != nil {
		t.Fatalf("injected config invalid: %v\n%s", err, injected)
	}
	if parsed.Config.Interface.FwMark != 51820 {
		t.Fatalf("FwMark = %d", parsed.Config.Interface.FwMark)
	}
	withDisabledMark := runtime + "FwMark = off\n"
	rewritten := InjectFwMark(withDisabledMark, 51820)
	parsed, err = Parse(rewritten)
	if err != nil {
		t.Fatalf("rewritten config invalid: %v\n%s", err, rewritten)
	}
	if parsed.Config.Interface.FwMark != 51820 || strings.Count(rewritten, "FwMark") != 1 {
		t.Fatalf("existing FwMark was not replaced:\n%s", rewritten)
	}
	if InjectFwMark(runtime, 0) != runtime {
		t.Fatal("zero mark must not rewrite")
	}
	spaced := "[ Interface ] # comment\nPrivateKey = GGHiF3lJmZSPqQfHelxSTObVh8lGYbBAyTNTdEIsuEc=\n"
	if got := InjectFwMark(spaced, 51820); !strings.Contains(got, "FwMark = 51820") {
		t.Fatalf("FwMark was not injected into spaced section: %s", got)
	}
}
