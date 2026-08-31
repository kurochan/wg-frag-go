// Package interfacename validates WGF interface identifiers shared by the
// manager and its control transports.
package interfacename

import "path/filepath"

// Valid reports whether name is safe for native TUN names and canonical
// per-interface control socket paths.
func Valid(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 15 || filepath.Base(name) != name {
		return false
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			r == '_' || r == '=' || r == '+' || r == '.' || r == '-' {
			continue
		}
		return false
	}
	return true
}
