package wgadapter

import (
	"errors"
	"testing"
)

func TestNewRejectsNilDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(DeviceConfig{}); !errors.Is(err, ErrNilTUN) {
		t.Fatalf("New() error = %v, want ErrNilTUN", err)
	}
}
