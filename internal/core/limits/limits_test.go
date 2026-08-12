package limits

import "testing"

func TestMinCarrierPayload(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mtu  int
		want int
	}{
		{1280, 92},
		{1500, 106},
		{9612, 613},
		{9616, 613},
	}

	for _, tt := range tests {
		t.Run("mtu", func(t *testing.T) {
			if got := MinCarrierPayload(tt.mtu); got != tt.want {
				t.Fatalf("MinCarrierPayload(%d) = %d, want %d", tt.mtu, got, tt.want)
			}
		})
	}
}

func TestValidateMinCarrierPayload(t *testing.T) {
	t.Parallel()
	if err := ValidateInnerMTU(MinInnerMTU); err != nil {
		t.Fatalf("minimum MTU rejected: %v", err)
	}
	if err := ValidateInnerMTU(MinInnerMTU - 1); err == nil {
		t.Fatal("MTU below v1 minimum was accepted")
	}
	if err := ValidateMinCarrierPayload(1500, DefaultCarrierPayload); err != nil {
		t.Fatalf("default payload rejected: %v", err)
	}
	if err := ValidateMinCarrierPayload(MaxInnerMTU, DefaultCarrierPayload); err != nil {
		t.Fatalf("maximum MTU payload rejected: %v", err)
	}
	if err := ValidateMinCarrierPayload(MaxInnerMTU, DefaultCarrierPayload-1); err == nil {
		t.Fatal("payload below BASE was accepted")
	}
}
