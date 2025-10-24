package dproxy

import (
	"errors"
	"fmt"
)

var ErrorUnexpectedType = "expected packet type %d, got %d"

var (
	ErrInvalidVersion    = errors.New("invalid protocol version")
	ErrInvalidPacketType = errors.New("invalid packet type")
	ErrInvalidPublicKey  = errors.New("invalid public key")
	ErrHandshakeFailed   = errors.New("handshake failed")
	ErrConnectionClosed  = errors.New("connection closed")
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
)

// ProtocolError wraps protocol-specific errors
type ProtocolError struct {
	Code    DProxyError
	Message string
}

func (e *ProtocolError) Error() string {
	return fmt.Sprintf("protocol error %d: %s", e.Code, e.Message)
}

func NewProtocolError(code DProxyError, message string) *ProtocolError {
	return &ProtocolError{Code: code, Message: message}
}
