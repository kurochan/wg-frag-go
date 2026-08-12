// Package syntax provides the shared lexical pass for WireGuard-style config
// files. It removes comments and identifies sections and key/value fields;
// semantic validation remains in the consuming package.
package syntax

import (
	"bufio"
	"io"
	"strings"
	"unicode"
)

// Line is one source line after lexical comment removal.
type Line struct {
	Number    int
	Raw       string
	Text      string
	Section   string
	Key       string
	Value     string
	IsSection bool
	IsField   bool
}

// Section returns the normalized section name in a source line.
func Section(line string) string {
	text := strings.TrimSpace(StripComment(line))
	if len(text) < 2 || text[0] != '[' || text[len(text)-1] != ']' ||
		strings.Count(text, "[") != 1 || strings.Count(text, "]") != 1 {
		return ""
	}
	return strings.TrimSpace(text[1 : len(text)-1])
}

// Scan calls fn for each input line. Raw retains the original line without
// its newline; Text is trimmed after comment removal.
func Scan(reader io.Reader, fn func(Line) error) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024), 64*1024)
	for number := 1; scanner.Scan(); number++ {
		raw := scanner.Text()
		text := strings.TrimSpace(StripComment(raw))
		line := Line{Number: number, Raw: raw, Text: text}
		if text != "" && strings.HasPrefix(text, "[") {
			line.IsSection = true
			line.Section = Section(text)
		} else if text != "" {
			if key, value, ok := strings.Cut(text, "="); ok {
				line.Key = strings.TrimSpace(key)
				line.Value = strings.TrimSpace(value)
				line.IsField = true
			}
		}
		if err := fn(line); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// StripComment removes comments introduced at the beginning of a line or
// after whitespace. This keeps # and ; usable in unquoted hook values.
func StripComment(line string) string {
	previousSpace := true
	for index, char := range line {
		if (char == '#' || char == ';') && previousSpace {
			return line[:index]
		}
		previousSpace = unicode.IsSpace(char)
	}
	return line
}
