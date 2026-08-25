//go:build darwin

package runtimedir

// Default is the macOS directory for root-owned daemon state. /var/run is
// group-writable on macOS, so it cannot meet the control socket's trusted
// parent-directory requirement.
const Default = "/var/db/wg-frag"
