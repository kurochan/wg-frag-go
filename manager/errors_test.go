package manager

import (
	"errors"
	"fmt"
	"testing"
)

func TestErrorCodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		code     Code
		sentinel error
	}{
		{name: "invalid argument", code: CodeInvalidArgument, sentinel: ErrInvalidArgument},
		{name: "not found", code: CodeNotFound, sentinel: ErrNotFound},
		{name: "already exists", code: CodeAlreadyExists, sentinel: ErrAlreadyExists},
		{name: "aborted", code: CodeAborted, sentinel: ErrAborted},
		{name: "failed precondition", code: CodeFailedPrecondition, sentinel: ErrFailedPrecondition},
		{name: "resource exhausted", code: CodeResourceExhausted, sentinel: ErrResourceExhausted},
		{name: "unavailable", code: CodeUnavailable, sentinel: ErrUnavailable},
		{name: "internal", code: CodeInternal, sentinel: ErrInternal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := Wrap(tt.code, "operation failed", fmt.Errorf("cause"))
			if got := CodeOf(err); got != tt.code {
				t.Fatalf("CodeOf() = %s, want %s", got, tt.code)
			}
			if !errors.Is(err, tt.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", err, tt.sentinel)
			}
			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatal("errors.As() = false")
			}
			if typed.Code() != tt.code {
				t.Fatalf("Error.Code() = %s, want %s", typed.Code(), tt.code)
			}
		})
	}
}

func TestCodeOfUnknownAndNil(t *testing.T) {
	t.Parallel()

	if got := CodeOf(nil); got != CodeOK {
		t.Fatalf("CodeOf(nil) = %s, want %s", got, CodeOK)
	}
	if got := CodeOf(errors.New("external failure")); got != CodeInternal {
		t.Fatalf("CodeOf(external) = %s, want %s", got, CodeInternal)
	}
	if got := CodeOf(fmt.Errorf("wrapped: %w", ErrUnavailable)); got != CodeUnavailable {
		t.Fatalf("CodeOf(wrapped) = %s, want %s", got, CodeUnavailable)
	}
}

func TestInvalidCodeMapsToInternal(t *testing.T) {
	t.Parallel()

	err := NewError(Code(255), "bad code")
	if got := CodeOf(err); got != CodeInternal {
		t.Fatalf("CodeOf(invalid) = %s, want %s", got, CodeInternal)
	}
}

func TestCodeString(t *testing.T) {
	t.Parallel()

	if got := Code(255).String(); got != "Unknown" {
		t.Fatalf("Code(255).String() = %q, want Unknown", got)
	}
}

func TestOptionsDefaultMaxInterfaces(t *testing.T) {
	t.Parallel()

	if got := (Options{MaxInterfaces: 0}).maxInterfaces(); got != DefaultMaxInterfaces {
		t.Fatalf("Options{MaxInterfaces: 0}.maxInterfaces() = %d, want %d", got, DefaultMaxInterfaces)
	}
	for _, value := range []int{-2, -1, 1, 3} {
		if got := (Options{MaxInterfaces: value}).maxInterfaces(); got != value {
			t.Fatalf("Options{MaxInterfaces: %d}.maxInterfaces() = %d, want %d", value, got, value)
		}
	}
}
