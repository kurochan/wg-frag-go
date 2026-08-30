package syntax

import (
	"strings"
	"testing"
)

func TestScanSharesCommentAndFieldRules(t *testing.T) {
	t.Parallel()
	var lines []Line
	err := Scan(strings.NewReader("; c\n[Interface] # section\nHook = echo # keep\n[Peer]\nAllowedIPs = 10.0.0.0/24 ; comment\n"), func(line Line) error {
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 5 || !lines[1].IsSection || lines[1].Section != "Interface" {
		t.Fatalf("lines = %+v", lines)
	}
	if !lines[2].IsField || lines[2].Key != "Hook" || lines[2].Value != "echo" {
		t.Fatalf("field = %+v", lines[2])
	}
	if !lines[4].IsField || lines[4].Value != "10.0.0.0/24" {
		t.Fatalf("comment stripping = %+v", lines[4])
	}
}

func TestSectionNormalizesCommentsAndSpacing(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"[Interface] # comment": "Interface",
		"[ Peer ] ; comment":    "Peer",
		"key = value":           "",
	} {
		if got := Section(input); got != want {
			t.Errorf("Section(%q) = %q, want %q", input, got, want)
		}
	}
}
