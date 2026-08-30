package metrics

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// Sample is one metric value with its labels.
type Sample struct {
	Name   string
	Labels map[string]string
	Value  uint64
}

// Snapshot is a request-time view of WGF state.
type Snapshot struct {
	BuildLabels map[string]string
	Samples     []Sample
}

// WriteOpenMetrics encodes a snapshot as OpenMetrics 1.0 text.
func WriteOpenMetrics(w io.Writer, selector Selector, snapshot Snapshot) error {
	for _, descriptor := range Descriptors {
		if !selector.Enabled(descriptor.Name) {
			continue
		}
		if _, err := fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", descriptor.Family, descriptor.Help, descriptor.Family, descriptor.Type); err != nil {
			return err
		}
		if descriptor.Name == "wgf_build_info" {
			if err := writeSample(w, descriptor.Name, snapshot.BuildLabels, 1); err != nil {
				return err
			}
		}
		for _, sample := range snapshot.Samples {
			if sample.Name != descriptor.Name {
				continue
			}
			if err := writeSample(w, sample.Name, sample.Labels, sample.Value); err != nil {
				return err
			}
		}
	}
	_, err := io.WriteString(w, "# EOF\n")
	return err
}

func writeSample(w io.Writer, name string, labels map[string]string, value uint64) error {
	if _, err := io.WriteString(w, name); err != nil {
		return err
	}
	if len(labels) != 0 {
		keys := make([]string, 0, len(labels))
		for key := range labels {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		if _, err := io.WriteString(w, "{"); err != nil {
			return err
		}
		for index, key := range keys {
			if index != 0 {
				if _, err := io.WriteString(w, ","); err != nil {
					return err
				}
			}
			if _, err := fmt.Fprintf(w, "%s=\"%s\"", key, escapeLabel(labels[key])); err != nil {
				return err
			}
		}
		if _, err := io.WriteString(w, "}"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, " %d\n", value)
	return err
}

func escapeLabel(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\n", "\\n", "\"", "\\\"").Replace(value)
}
