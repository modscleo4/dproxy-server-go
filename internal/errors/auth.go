package errors

import "errors"

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrClientNotConnected = errors.New("client not connected")
	ErrClientDisabled     = errors.New("client disabled")
	ErrUnauthorized       = errors.New("unauthorized")
)
