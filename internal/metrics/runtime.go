package metrics

import runtimeMetrics "runtime/metrics"

type runtimeMetricSpec struct {
	name    string
	runtime string
}

// Names retain WGF's namespace while following common Go runtime metric
// concepts. Monotonic runtime values are exposed as OpenMetrics counters.
var runtimeMetricSpecs = []runtimeMetricSpec{
	{name: "wgf_go_num_goroutine", runtime: "/sched/goroutines:goroutines"},
	{name: "wgf_go_gomaxprocs", runtime: "/sched/gomaxprocs:threads"},
	{name: "wgf_go_mem_stats_num_gc_total", runtime: "/gc/cycles/total:gc-cycles"},
	{name: "wgf_go_mem_stats_gc_cpu_seconds_total", runtime: "/cpu/classes/gc/total:cpu-seconds"},
	{name: "wgf_go_mem_stats_heap_alloc", runtime: "/memory/classes/heap/objects:bytes"},
	{name: "wgf_go_mem_stats_heap_objects", runtime: "/gc/heap/objects:objects"},
	{name: "wgf_go_mem_stats_total_alloc_bytes_total", runtime: "/gc/heap/allocs:bytes"},
	{name: "wgf_go_mem_stats_frees_bytes_total", runtime: "/gc/heap/frees:bytes"},
}

// RuntimeSamples reads the selected scalar Go runtime metrics at scrape time.
// Unsupported metrics are omitted so the process remains compatible with Go
// versions that do not expose every runtime/metrics key.
func RuntimeSamples() []Sample {
	raw := make([]runtimeMetrics.Sample, len(runtimeMetricSpecs))
	for index, spec := range runtimeMetricSpecs {
		raw[index].Name = spec.runtime
	}
	runtimeMetrics.Read(raw)

	samples := make([]Sample, 0, len(raw))
	for index, value := range raw {
		switch value.Value.Kind() {
		case runtimeMetrics.KindUint64:
			samples = append(samples, Sample{Name: runtimeMetricSpecs[index].name, Value: value.Value.Uint64()})
		case runtimeMetrics.KindFloat64:
			samples = append(samples, Sample{Name: runtimeMetricSpecs[index].name, FloatValue: value.Value.Float64(), IsFloat: true})
		}
	}
	return samples
}
