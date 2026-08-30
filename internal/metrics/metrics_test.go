package metrics

import (
	"bytes"
	"strings"
	"testing"
)

func TestSelector(t *testing.T) {
	t.Parallel()
	selector, err := NewSelector([]string{"wgf_tx_*", "wgf_build_info"}, []string{"wgf_tx_*drops_total"})
	if err != nil {
		t.Fatal(err)
	}
	if selector.Enabled("wgf_tx_packet_drops_total") {
		t.Fatal("exclude must take precedence")
	}
	if !selector.Enabled("wgf_tx_carriers_total") {
		t.Fatal("selected metric is disabled")
	}
	if !selector.Enabled("wgf_build_info") {
		t.Fatal("exact selected metric is disabled")
	}
	if selector.Enabled("wgf_rx_data_carriers_total") {
		t.Fatal("unselected metric is enabled")
	}
}

func TestSelectorRejectsInvalidPattern(t *testing.T) {
	t.Parallel()
	for _, pattern := range []string{"wgf_**", "wgf_?", "missing_metric"} {
		if _, err := NewSelector([]string{pattern}, nil); err == nil {
			t.Fatalf("NewSelector(%q) succeeded", pattern)
		}
	}
}

func TestWriteOpenMetrics(t *testing.T) {
	t.Parallel()
	selector, err := NewSelector([]string{"wgf_build_info", "wgf_tx_carriers_total"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = WriteOpenMetrics(&output, selector, Snapshot{
		BuildLabels: map[string]string{"version": "v1\"x", "commit": "abc", "go_version": "go-test"},
		Samples:     []Sample{{Name: "wgf_tx_carriers_total", Labels: map[string]string{"interface": "wgf0"}, Value: 7}},
	})
	if err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, want := range []string{
		"# TYPE wgf_build_info gauge\n",
		"wgf_build_info{commit=\"abc\",go_version=\"go-test\",version=\"v1\\\"x\"} 1\n",
		"# TYPE wgf_tx_carriers counter\n",
		"wgf_tx_carriers_total{interface=\"wgf0\"} 7\n",
		"# EOF\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestCounterFamiliesUseOpenMetricsBaseNames(t *testing.T) {
	t.Parallel()
	for _, descriptor := range Descriptors {
		if descriptor.Type != "counter" {
			continue
		}
		if !strings.HasSuffix(descriptor.Name, "_total") || descriptor.Family == descriptor.Name {
			t.Fatalf("counter descriptor = %+v", descriptor)
		}
	}
}
