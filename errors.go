package jwt

import "errors"

var (
	ErrMalformedToken = errors.New("token is malformed")

	ErrInvalidSignature = errors.New("invalid signature")

	ErrInvalidAlgorithm = errors.New("invalid algorithm")
)
