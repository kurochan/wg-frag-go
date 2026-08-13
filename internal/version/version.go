// Package version contains build-time version metadata for the wgf binary.
package version

import "fmt"

// These values are replaced by the release build with GoReleaser ldflags.
var (
	Version = "devel"
	Commit  = "unknown"
	Date    = "unknown"
)

// String returns a compact human-readable build identifier.
func String() string {
	if Version == "devel" {
		return Version
	}
	return fmt.Sprintf("%s (commit %s, built %s)", Version, Commit, Date)
}
