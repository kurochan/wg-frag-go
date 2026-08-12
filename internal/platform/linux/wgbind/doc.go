// Package wgbind provides the Linux UDP bind used by wg-frag-go.
//
// The implementation is Linux-specific, but this file intentionally is not
// build-tagged so importing the parent module on another OS does not make
// package discovery fail.
package wgbind
