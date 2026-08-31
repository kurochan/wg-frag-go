//go:build !linux && !darwin

package manager

// GatherOpenMetrics reports that metrics are unavailable without a platform
// runtime.
func (*Manager) GatherOpenMetrics([]string, []string) ([]byte, error) {
	return nil, NewError(CodeUnavailable, "manager is not supported on this platform")
}
