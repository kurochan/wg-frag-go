package tunanchor

import (
	"errors"
	"io"
	"os"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/tun"
)

func TestLeaseCloseDoesNotCloseAnchor(t *testing.T) {
	anchorFile, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()

	var leasedFile *os.File
	anchor := newAnchor(anchorFile, "test0", func(file *os.File, _ int) (tun.Device, error) {
		leasedFile = file
		return &fakeLease{file: file}, nil
	})
	lease, err := anchor.Lease(1500)
	if err != nil {
		t.Fatal(err)
	}
	if leasedFile == nil {
		t.Fatal("lease factory did not receive a file")
	}

	if err := anchor.Close(); err != nil {
		t.Fatalf("Anchor.Close() error = %v", err)
	}
	if err := anchor.Close(); err != nil {
		t.Fatalf("second Anchor.Close() error = %v", err)
	}
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatalf("write through live lease = %v", err)
	}
	got := make([]byte, 1)
	if _, err := leasedFile.Read(got); err != nil {
		t.Fatalf("read through live lease = %v", err)
	}
	if got[0] != 'x' {
		t.Fatalf("read through live lease = %q, want x", got)
	}
	if err := lease.Close(); err != nil {
		t.Fatalf("lease Close() error = %v", err)
	}
	if _, err := leasedFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("closed lease file Stat() error = %v, want os.ErrClosed", err)
	}
}

func TestLeaseFailureClosesDuplicatedFile(t *testing.T) {
	anchorFile, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()

	var failedFile *os.File
	anchor := newAnchor(anchorFile, "test0", func(file *os.File, _ int) (tun.Device, error) {
		failedFile = file
		return nil, io.ErrUnexpectedEOF
	})
	if _, err := anchor.Lease(1500); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("Lease() error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
	if failedFile == nil {
		t.Fatal("lease factory did not receive a file")
	}
	if _, err := failedFile.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("failed lease file Stat() error = %v, want os.ErrClosed", err)
	}
	if _, err := anchorFile.Stat(); err != nil {
		t.Fatalf("anchor file was closed after lease failure: %v", err)
	}
	if err := anchor.Close(); err != nil {
		t.Fatalf("Anchor.Close() error = %v", err)
	}
}

func TestLeaseAfterCloseIsRejected(t *testing.T) {
	anchorFile, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = writer.Close() }()

	called := false
	anchor := newAnchor(anchorFile, "test0", func(file *os.File, _ int) (tun.Device, error) {
		called = true
		return &fakeLease{file: file}, nil
	})
	if err := anchor.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := anchor.Lease(1500); !errors.Is(err, ErrClosed) {
		t.Fatalf("Lease() error = %v, want ErrClosed", err)
	}
	if called {
		t.Fatal("lease factory was called after anchor close")
	}
}

type fakeLease struct {
	file      *os.File
	closeOnce sync.Once
}

func (f *fakeLease) File() *os.File { return f.file }

func (f *fakeLease) Read([][]byte, []int, int) (int, error) { return 0, io.EOF }

func (f *fakeLease) Write([][]byte, int) (int, error) { return 0, io.EOF }

func (f *fakeLease) MTU() (int, error) { return 1500, nil }

func (f *fakeLease) Name() (string, error) { return "test0", nil }

func (f *fakeLease) Events() <-chan tun.Event { return nil }

func (f *fakeLease) Close() error {
	var err error
	f.closeOnce.Do(func() { err = f.file.Close() })
	return err
}

func (f *fakeLease) BatchSize() int { return 1 }

var _ tun.Device = (*fakeLease)(nil)
