package quick

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/kurochan/wg-frag-go/internal/config"
	"github.com/kurochan/wg-frag-go/internal/config/syntax"
)

func syntaxField(line string) (key, value string, ok bool) {
	if line == "" || strings.HasPrefix(line, "[") {
		return "", "", false
	}
	key, value, ok = strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(key), strings.TrimSpace(value), true
}

// DefaultRouteTable is used for policy-routed default routes when the
// configuration sets no FwMark, matching wg-quick's convention.
const DefaultRouteTable = 51820

// RoutePlan is the platform-independent routing decision for one interface.
type RoutePlan struct {
	// FwMark must be present in the runtime configuration when nonzero: the
	// daemon marks its outer UDP sockets so the "not fwmark" rule exempts
	// tunnel traffic, which is what prevents an endpoint route loop.
	FwMark uint32
	// Specific prefixes are installed into SpecificTable (zero = main).
	Specific      []netip.Prefix
	SpecificTable uint32
	// Defaults are /0 prefixes installed into DefaultTable together with the
	// policy rules; empty means no policy routing.
	Defaults     []netip.Prefix
	DefaultTable uint32
	// RulesV4/RulesV6 request the two policy rules per address family.
	RulesV4 bool
	RulesV6 bool
}

// PlanRoutes computes route and rule installation from the parsed
// configuration. Explicit table numbers reproduce wg-quick: every route goes
// into that table and no rules or fwmark are installed.
func PlanRoutes(options Options, cfg *config.Config) RoutePlan {
	plan := RoutePlan{}
	if options.TableMode.Off {
		return plan
	}
	seen := make(map[netip.Prefix]bool)

	for _, peer := range cfg.Peers {
		for _, prefix := range peer.AllowedIPs {
			prefix = prefix.Masked()
			if seen[prefix] {
				continue
			}
			seen[prefix] = true
			if prefix.Bits() == 0 && options.TableMode.Auto() {
				plan.Defaults = append(plan.Defaults, prefix)

				continue
			}
			plan.Specific = append(plan.Specific, prefix)
		}
	}
	if table := options.TableMode.Table; table != 0 {
		plan.SpecificTable = table
		return plan
	}
	if len(plan.Defaults) == 0 {
		return plan
	}
	plan.FwMark = cfg.Interface.FwMark
	if plan.FwMark == 0 {
		plan.FwMark = DefaultRouteTable
	}
	plan.DefaultTable = plan.FwMark
	for _, prefix := range plan.Defaults {
		if prefix.Addr().Is4() {
			plan.RulesV4 = true
		} else {
			plan.RulesV6 = true
		}
	}
	return plan
}

// InjectFwMark returns runtime configuration text whose [Interface] section
// carries mark, replacing an existing FwMark when necessary.
func InjectFwMark(runtime string, mark uint32) string {
	if mark == 0 {
		return runtime
	}
	hasFwMark := false
	inInterface := false

	for line := range strings.Lines(runtime) {
		trimmed := strings.TrimSpace(syntax.StripComment(line))
		section := syntax.Section(line)
		if section != "" {
			inInterface = section == "Interface"
		}
		if key, _, ok := syntaxField(trimmed); inInterface && ok && key == "FwMark" {
			hasFwMark = true

			break
		}
	}
	var out strings.Builder
	injected := false
	inInterface = false
	for line := range strings.Lines(runtime) {
		trimmed := strings.TrimSpace(syntax.StripComment(line))
		section := syntax.Section(line)
		if section != "" {
			inInterface = section == "Interface"
		}
		if inInterface {
			if key, _, ok := syntaxField(trimmed); ok && key == "FwMark" {
				fmt.Fprintf(&out, "FwMark = %d\n", mark)
				injected = true
				continue
			}
		}
		out.WriteString(line)
		if !hasFwMark && !injected && section == "Interface" {
			fmt.Fprintf(&out, "FwMark = %d\n", mark)
			injected = true
		}
	}
	return out.String()
}
