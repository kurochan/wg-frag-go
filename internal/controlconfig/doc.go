// Package controlconfig converts between the public control API specifications
// and the internal runtime configuration.
//
// The conversion keeps secret fields explicit: interface private keys are
// accepted only when supplied by the caller, while status snapshots can omit
// them and preserve existing values during an update. Peer preshared keys use
// the PRESERVE, SET, and CLEAR actions defined by the control protocol.
package controlconfig
