// Package manager owns the lifecycle of one or more wg-frag interfaces.
//
// The Service interface is the transport-independent control contract. It
// uses the public protobuf request and response types directly, so an
// in-process caller and the gRPC control adapter execute the same operations.
// Manager implementations own interface runtimes and are safe for concurrent
// Service calls. The manager's Close method releases all resources owned by
// the manager; a control transport owns only its listener and server.
//
// Each interface has a supervisor that serializes lifecycle mutations, keeps
// its TUN anchor stable across runtime generations, and preserves counters for
// a public-key identity across delete and recreate operations within the same
// process.
package manager
