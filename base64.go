package jwt

import (
	"encoding/base64"
	"errors"
)

type Base64Codec interface {
	EncodeToBase64(src []byte) (string, error)
	DecodeFromBase64(content string) ([]byte, error)
}

// ErrInvalidBase64Content must be returned by Base64Decoder implementations when the content is not valid base64.
var ErrInvalidBase64Content = errors.New("invalid base64 content")

type defaultBase64Codec struct{}

func (d defaultBase64Codec) DecodeFromBase64(content string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(content)
	if err != nil {
		return nil, ErrInvalidBase64Content
	}

	return decoded, nil
}

func (d defaultBase64Codec) EncodeToBase64(src []byte) (string, error) {
	return base64.RawURLEncoding.EncodeToString(src), nil
}

var DefaultBase64Codec = defaultBase64Codec{}
