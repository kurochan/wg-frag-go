// Package controlapi serves the local management API over a private
// Unix-domain socket. Socket directories are owner-only and socket files are
// mode 0600; callers must keep the path within that trust boundary.
package controlapi
