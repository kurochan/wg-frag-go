package manager

import (
	"errors"
	"fmt"
)

// Code classifies an error returned by a manager operation.
type Code uint8

const (
	// CodeOK indicates success and is returned by CodeOf(nil).
	CodeOK Code = iota
	// CodeInvalidArgument indicates malformed or incomplete input.
	CodeInvalidArgument
	// CodeNotFound indicates that the requested interface or peer does not exist.
	CodeNotFound
	// CodeAlreadyExists indicates a name or public key collision.
	CodeAlreadyExists
	// CodeAborted indicates that an optimistic concurrency check failed.
	CodeAborted
	// CodeFailedPrecondition indicates that the operation is not valid in the
	// interface's current lifecycle state.
	CodeFailedPrecondition
	// CodeResourceExhausted indicates that a configured resource limit was hit.
	CodeResourceExhausted
	// CodeUnavailable indicates that the manager is shutting down or unavailable.
	CodeUnavailable
	// CodeInternal indicates an unexpected manager failure.
	CodeInternal
)

// String returns the stable name of a Code.
func (c Code) String() string {
	switch c {
	case CodeOK:
		return "OK"
	case CodeInvalidArgument:
		return "InvalidArgument"
	case CodeNotFound:
		return "NotFound"
	case CodeAlreadyExists:
		return "AlreadyExists"
	case CodeAborted:
		return "Aborted"
	case CodeFailedPrecondition:
		return "FailedPrecondition"
	case CodeResourceExhausted:
		return "ResourceExhausted"
	case CodeUnavailable:
		return "Unavailable"
	case CodeInternal:
		return "Internal"
	default:
		return "Unknown"
	}
}

// valid reports whether c is one of the supported manager error codes.
func (c Code) valid() bool {
	return c >= CodeInvalidArgument && c <= CodeInternal
}

// Error is a manager error with a transport-independent Code.
//
// Use errors.Is(err, ErrNotFound) for code-only checks, errors.As to inspect
// the complete error, or CodeOf(err) when adapting the error to a transport.
type Error struct {
	code    Code
	message string
	cause   error
}

// Error implements error.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.message == "" {
		return "manager: " + e.code.String()
	}
	return "manager: " + e.code.String() + ": " + e.message
}

// Unwrap exposes the underlying error, if one was supplied.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Code returns the classification carried by e.
func (e *Error) Code() Code {
	if e == nil {
		return CodeInternal
	}
	return e.code
}

// Message returns the transport-neutral detail without the manager prefix or
// error code. It is intended for protocol adapters.
func (e *Error) Message() string {
	if e == nil {
		return ""
	}
	return e.message
}

// Is reports whether target carries the same manager error code.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e != nil && other != nil && e.code == other.code
}

// NewError creates an error with code and message. Invalid codes are reported
// as CodeInternal so callers cannot accidentally expose an unsupported class.
func NewError(code Code, message string) error {
	return newError(code, message, nil)
}

// Wrap annotates cause with a manager error code while preserving cause for
// errors.Is and errors.As.
func Wrap(code Code, message string, cause error) error {
	if cause == nil {
		return NewError(code, message)
	}
	return newError(code, message, cause)
}

// Errorf creates a formatted manager error.
func Errorf(code Code, format string, args ...any) error {
	return NewError(code, fmt.Sprintf(format, args...))
}

func newError(code Code, message string, cause error) error {
	if !code.valid() {
		code = CodeInternal
	}
	return &Error{code: code, message: message, cause: cause}
}

// CodeOf returns the manager code carried by err. Nil is CodeOK; an error
// from outside this package is treated as CodeInternal.
func CodeOf(err error) Code {
	if err == nil {
		return CodeOK
	}
	var managerErr *Error
	if errors.As(err, &managerErr) && managerErr != nil {
		return managerErr.code
	}
	return CodeInternal
}

var (
	// ErrInvalidArgument is the CodeInvalidArgument sentinel.
	ErrInvalidArgument = &Error{code: CodeInvalidArgument}
	// ErrNotFound is the CodeNotFound sentinel.
	ErrNotFound = &Error{code: CodeNotFound}
	// ErrAlreadyExists is the CodeAlreadyExists sentinel.
	ErrAlreadyExists = &Error{code: CodeAlreadyExists}
	// ErrAborted is the CodeAborted sentinel.
	ErrAborted = &Error{code: CodeAborted}
	// ErrFailedPrecondition is the CodeFailedPrecondition sentinel.
	ErrFailedPrecondition = &Error{code: CodeFailedPrecondition}
	// ErrResourceExhausted is the CodeResourceExhausted sentinel.
	ErrResourceExhausted = &Error{code: CodeResourceExhausted}
	// ErrUnavailable is the CodeUnavailable sentinel.
	ErrUnavailable = &Error{code: CodeUnavailable}
	// ErrInternal is the CodeInternal sentinel.
	ErrInternal = &Error{code: CodeInternal}
)
