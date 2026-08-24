//go:build linux

package runtimedir

// Default is the Linux runtime directory managed by tmpfs and systemd.
const Default = "/run/wg-frag"
