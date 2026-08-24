//go:build !linux && !darwin

package runtimedir

// Default is a Unix-style fallback for unsupported platforms.
const Default = "/var/run/wg-frag"
