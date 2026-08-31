package metrics

import (
	"errors"
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

// InterfaceSnapshot is a request-time view of one WGF interface.
//
// Samples contain only the metric-specific labels. The encoder adds the
// required interface and interface_id labels to every sample.
type InterfaceSnapshot struct {
	Name    string
	ID      string
	Samples []Sample
}

// Snapshot is a request-time view of process and interface state.
type Snapshot struct {
	BuildLabels        map[string]string
	Samples            []Sample
	InterfaceSnapshots []InterfaceSnapshot
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
			if err := writeScopedSample(w, descriptor, Sample{Name: descriptor.Name, Labels: snapshot.BuildLabels, Value: 1}, nil); err != nil {
				return err
			}
		}
		for _, sample := range snapshot.Samples {
			if sample.Name != descriptor.Name {
				continue
			}
			if descriptor.Scope != ScopeProcess {
				return fmt.Errorf("metric %s must be supplied in an interface snapshot", sample.Name)
			}
			if err := writeScopedSample(w, descriptor, sample, nil); err != nil {
				return err
			}
		}
		for _, iface := range snapshot.InterfaceSnapshots {
			if iface.Name == "" || iface.ID == "" {
				return errors.New("interface snapshot requires name and id")
			}
			for _, sample := range iface.Samples {
				if sample.Name != descriptor.Name {
					continue
				}
				if descriptor.Scope == ScopeProcess {
					return fmt.Errorf("process metric %s must not be supplied in an interface snapshot", sample.Name)
				}
				if err := writeScopedSample(w, descriptor, sample, &iface); err != nil {
					return err
				}
			}
		}
	}
	_, err := io.WriteString(w, "# EOF\n")
	return err
}

func writeScopedSample(w io.Writer, descriptor Descriptor, sample Sample, iface *InterfaceSnapshot) error {
	labels := sample.Labels
	if descriptor.Scope == ScopeProcess {
		if hasLabel(labels, "interface") || hasLabel(labels, "interface_id") || hasLabel(labels, "peer_id") {
			return fmt.Errorf("process metric %s has interface-scoped labels", sample.Name)
		}
	} else {
		if iface == nil {
			return fmt.Errorf("metric %s has no interface scope", sample.Name)
		}
		labels = cloneLabels(labels)
		labels["interface"] = iface.Name
		labels["interface_id"] = iface.ID
		if descriptor.Scope == ScopePeer {
			if !hasNonEmptyLabel(labels, "peer_id") {
				return fmt.Errorf("peer metric %s is missing peer_id", sample.Name)
			}
		} else if hasLabel(labels, "peer_id") {
			return fmt.Errorf("interface metric %s has peer_id", sample.Name)
		}
	}
	if err := validateScopedLabels(descriptor.Scope, labels); err != nil {
		return fmt.Errorf("metric %s: %w", sample.Name, err)
	}
	if err := writeSample(w, sample.Name, labels, sample.Value); err != nil {
		return err
	}
	return nil
}

func validateScopedLabels(scope Scope, labels map[string]string) error {
	if scope == ScopeProcess {
		return nil
	}
	expected := 2
	if scope == ScopePeer {
		expected++
	}
	if len(labels) != expected {
		return fmt.Errorf("has %d labels, want %d", len(labels), expected)
	}
	if !hasNonEmptyLabel(labels, "interface") || !hasNonEmptyLabel(labels, "interface_id") {
		return errors.New("missing interface labels")
	}
	if scope == ScopePeer && !hasNonEmptyLabel(labels, "peer_id") {
		return errors.New("missing peer_id label")
	}
	return nil
}

func cloneLabels(labels map[string]string) map[string]string {
	cloned := make(map[string]string, len(labels)+2)
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

func hasLabel(labels map[string]string, name string) bool {
	_, ok := labels[name]
	return ok
}

func hasNonEmptyLabel(labels map[string]string, name string) bool {
	return labels[name] != ""
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
