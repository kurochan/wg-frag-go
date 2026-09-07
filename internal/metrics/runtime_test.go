package metrics

import (
	"math"
	"testing"
)

func TestRuntimeSamplesExposeSelectedMetrics(t *testing.T) {
	t.Parallel()
	samples := RuntimeSamples()
	if len(samples) != len(runtimeMetricSpecs) {
		t.Fatalf("runtime sample count = %d, want %d", len(samples), len(runtimeMetricSpecs))
	}
	for index, sample := range samples {
		spec := runtimeMetricSpecs[index]
		if sample.Name != spec.name {
			t.Fatalf("runtime sample %d name = %q, want %q", index, sample.Name, spec.name)
		}
		if sample.IsFloat {
			if math.IsNaN(sample.FloatValue) || math.IsInf(sample.FloatValue, 0) {
				t.Fatalf("runtime sample %q is non-finite: %v", sample.Name, sample.FloatValue)
			}
		}
	}
}
