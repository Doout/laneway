// Package agent implements the Laneway node control-session state machine.
package agent

import (
	"errors"
	"fmt"

	lanewayv1 "github.com/Doout/laneway/go/api/laneway/v1"
)

var (
	ErrMalformed             = errors.New("malformed Laneway control message")
	ErrUnsupportedVersion    = errors.New("unsupported Laneway protocol version")
	ErrUnauthenticated       = errors.New("unauthenticated Laneway session")
	ErrPermissionDenied      = errors.New("Laneway permission denied")
	ErrStaleEpoch            = errors.New("stale Laneway configuration epoch")
	ErrResourceExhausted     = errors.New("Laneway resource exhausted")
	ErrInternal              = errors.New("internal Laneway session error")
	ErrInvalidIdentifier     = errors.New("invalid Laneway session identifier")
	ErrIdentityMismatch      = errors.New("Hello identity does not match authenticated identity")
	ErrRequiredCapabilities  = errors.New("required Laneway capabilities not negotiated")
	ErrInvalidEnvelope       = errors.New("invalid Laneway control envelope")
	ErrUnexpectedSequence    = errors.New("unexpected Laneway control sequence")
	ErrUnexpectedMessage     = errors.New("unexpected Laneway control message")
	ErrHandshakeState        = errors.New("invalid Laneway handshake state")
	ErrInvalidControlLimit   = errors.New("invalid Laneway control payload limit")
	ErrInvalidPacketLimit    = errors.New("invalid Laneway packet payload limit")
	ErrInvalidOverlayAddress = errors.New("invalid Laneway overlay address")
)

// SessionError carries a stable wire error code while retaining an errors.Is
// compatible local category. Detail is diagnostic and must not drive protocol
// behavior.
type SessionError struct {
	Code      lanewayv1.ErrorCode
	Detail    string
	Retryable bool
	Kind      error
}

func (e *SessionError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Detail != "" {
		return fmt.Sprintf("Laneway session error %s: %s", e.Code.String(), e.Detail)
	}
	return fmt.Sprintf("Laneway session error %s", e.Code.String())
}

func (e *SessionError) Unwrap() error { return e.Kind }

func (e *SessionError) Is(target error) bool {
	if e == nil {
		return false
	}
	if target == e.Kind {
		return true
	}
	switch e.Code {
	case lanewayv1.ErrorCode_ERROR_CODE_MALFORMED:
		return target == ErrMalformed
	case lanewayv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION:
		return target == ErrUnsupportedVersion
	case lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED:
		return target == ErrUnauthenticated
	case lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED:
		return target == ErrPermissionDenied
	case lanewayv1.ErrorCode_ERROR_CODE_STALE_EPOCH:
		return target == ErrStaleEpoch
	case lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED:
		return target == ErrResourceExhausted
	case lanewayv1.ErrorCode_ERROR_CODE_INTERNAL:
		return target == ErrInternal
	default:
		return false
	}
}

// ProtocolError returns the stable protobuf representation of a local error.
func (e *SessionError) ProtocolError() *lanewayv1.ProtocolError {
	if e == nil {
		return nil
	}
	return &lanewayv1.ProtocolError{Code: e.Code, Detail: e.Detail, Retryable: e.Retryable}
}

func sessionError(code lanewayv1.ErrorCode, kind error, format string, args ...any) error {
	return &SessionError{Code: code, Kind: kind, Detail: fmt.Sprintf(format, args...)}
}

func malformed(kind error, format string, args ...any) error {
	if kind == nil {
		kind = ErrMalformed
	}
	return sessionError(lanewayv1.ErrorCode_ERROR_CODE_MALFORMED, kind, format, args...)
}

func unsupported(kind error, format string, args ...any) error {
	if kind == nil {
		kind = ErrUnsupportedVersion
	}
	return sessionError(lanewayv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION, kind, format, args...)
}

// ErrorCode returns the stable protocol error category for err. Unknown local
// failures are deliberately reported as INTERNAL.
func ErrorCode(err error) lanewayv1.ErrorCode {
	var sessionErr *SessionError
	if errors.As(err, &sessionErr) && sessionErr.Code != lanewayv1.ErrorCode_ERROR_CODE_UNSPECIFIED {
		return sessionErr.Code
	}
	return lanewayv1.ErrorCode_ERROR_CODE_INTERNAL
}

func validErrorCode(code lanewayv1.ErrorCode) bool {
	return code >= lanewayv1.ErrorCode_ERROR_CODE_MALFORMED && code <= lanewayv1.ErrorCode_ERROR_CODE_INTERNAL
}

// RemoteError validates and converts a peer's ProtocolError. Unspecified and
// unknown numeric codes are malformed rather than silently treated as known.
func RemoteError(in *lanewayv1.ProtocolError) error {
	if in == nil || !validErrorCode(in.GetCode()) {
		return malformed(ErrMalformed, "invalid protocol error code %d", func() int32 {
			if in == nil {
				return 0
			}
			return int32(in.GetCode())
		}())
	}
	kinds := map[lanewayv1.ErrorCode]error{
		lanewayv1.ErrorCode_ERROR_CODE_MALFORMED:           ErrMalformed,
		lanewayv1.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION: ErrUnsupportedVersion,
		lanewayv1.ErrorCode_ERROR_CODE_UNAUTHENTICATED:     ErrUnauthenticated,
		lanewayv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED:   ErrPermissionDenied,
		lanewayv1.ErrorCode_ERROR_CODE_STALE_EPOCH:         ErrStaleEpoch,
		lanewayv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED:  ErrResourceExhausted,
		lanewayv1.ErrorCode_ERROR_CODE_INTERNAL:            ErrInternal,
	}
	return &SessionError{Code: in.GetCode(), Detail: in.GetDetail(), Retryable: in.GetRetryable(), Kind: kinds[in.GetCode()]}
}
