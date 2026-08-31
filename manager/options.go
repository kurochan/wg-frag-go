package manager

import "log/slog"

// DefaultMaxInterfaces is the default process-wide interface limit.
const DefaultMaxInterfaces = 16

// Options controls manager-wide lifecycle behavior.
//
// A zero value is valid. MaxInterfaces == 0 selects the default limit;
// negative values are invalid and must be rejected by the constructor.
// Logger nil disables manager lifecycle logging; data-plane components keep
// their own logging policy.
type Options struct {
	MaxInterfaces int
	Logger        *slog.Logger
}

func (o Options) maxInterfaces() int {
	if o.MaxInterfaces == 0 {
		return DefaultMaxInterfaces
	}
	return o.MaxInterfaces
}
