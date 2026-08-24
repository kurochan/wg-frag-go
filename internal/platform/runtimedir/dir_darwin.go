//go:build darwin

package runtimedir

// Default is the macOS runtime directory for root-owned daemon state.
const Default = "/var/run/wg-frag"
