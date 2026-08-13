package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testConfig = `[Interface]
PrivateKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Peer]
PublicKey = AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 10.0.0.0/24
`

func TestRunHelp(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"help"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got := stdout.String(); got == "" {
		t.Fatal("empty help")
	}
}

func TestRunVersion(t *testing.T) {
	t.Parallel()
	var stdout, stderr bytes.Buffer
	if err := run([]string{"version"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "wgf devel\n"; got != want {
		t.Fatalf("version output = %q, want %q", got, want)
	}
}

func TestRunCheck(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "wgf0.conf")
	if err := os.WriteFile(path, []byte(testConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"check", "--config", path}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	if got, want := stdout.String(), "configuration is valid\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestRunCheckRequiresPath(t *testing.T) {
	t.Parallel()
	if err := run([]string{"check"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("run(check) unexpectedly succeeded")
	}
}

func TestGeneratePrivateKeyClampsScalar(t *testing.T) {
	t.Parallel()
	key, err := generatePrivateKey(bytes.NewReader(bytes.Repeat([]byte{0xff}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if key[0] != 248 || key[31] != 127 {
		t.Fatalf("unclamped private key: first=%#x last=%#x", key[0], key[31])
	}
}

func TestPubkey(t *testing.T) {
	t.Parallel()
	private, err := generatePrivateKey(bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	if err := pubkey(nil, strings.NewReader(base64.StdEncoding.EncodeToString(private[:])+"\n"), &stdout); err != nil {
		t.Fatal(err)
	}
	public, err := base64.StdEncoding.DecodeString(strings.TrimSpace(stdout.String()))
	if err != nil || len(public) != 32 || isAllZero(public) {
		t.Fatalf("pubkey output = %q, decode error = %v", stdout.String(), err)
	}
}

func TestPubkeyRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	if err := pubkey(nil, strings.NewReader("not-a-key\n"), &bytes.Buffer{}); !errors.Is(err, errInvalidKey) {
		t.Fatalf("pubkey error = %v, want errInvalidKey", err)
	}
}
