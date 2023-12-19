package jwt

import (
	"errors"
	"strings"
)

func NewJWTTokenManager[H, P any](
	base64Codec Base64Codec, jsonCodec JSONCodec,
	signatureValidationFunc func(jwt *JWT[H, P]) error,
	signatureGenerationFunc func(jwt *JWT[H, P]) error,
) JWTTokenManager[H, P] {
	return JWTTokenManager[H, P]{
		base64Codec: base64Codec,
		jsonCodec:   jsonCodec,

		signatureValidationFunc: signatureValidationFunc,
		signatureGenerationFunc: signatureGenerationFunc,
	}
}

type JWTTokenManager[H, P any] struct {
	base64Codec Base64Codec
	jsonCodec   JSONCodec

	// This function must validate jwt.Signature.
	signatureValidationFunc func(jwt *JWT[H, P]) error
	// This function must generate and set jwt.Signature.
	signatureGenerationFunc func(jwt *JWT[H, P]) error
}

func (tm JWTTokenManager[H, P]) ValidateJWT(jwt *JWT[H, P]) error {
	return tm.signatureValidationFunc(jwt)
}

func (tm JWTTokenManager[H, P]) ParseJWT(token string) (*JWT[H, P], error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformedToken
	}

	jwt := &JWT[H, P]{
		RawHeader:  parts[0],
		RawPayload: parts[1],
	}

	base64DecodedHeader, err := tm.base64Codec.DecodeFromBase64(parts[0])
	if err != nil {
		if errors.Is(err, ErrInvalidBase64Content) {
			return nil, ErrMalformedToken
		}

		return nil, err
	}

	if err := tm.jsonCodec.DecodeFromJSON(base64DecodedHeader, &jwt.Header); err != nil {
		if errors.Is(err, ErrInvalidJSONContent) {
			return nil, ErrMalformedToken
		}

		return nil, err
	}

	base64DecodedPayload, err := tm.base64Codec.DecodeFromBase64(parts[1])
	if err != nil {
		if errors.Is(err, ErrInvalidBase64Content) {
			return nil, ErrMalformedToken
		}

		return nil, err
	}

	if err := tm.jsonCodec.DecodeFromJSON(base64DecodedPayload, &jwt.Payload); err != nil {
		if errors.Is(err, ErrInvalidJSONContent) {
			return nil, ErrMalformedToken
		}

		return nil, err
	}

	jwt.Signature, err = tm.base64Codec.DecodeFromBase64(parts[2])
	if err != nil {
		if errors.Is(err, ErrInvalidBase64Content) {
			return nil, ErrMalformedToken
		}

		return nil, err
	}

	return jwt, nil
}

func (tm JWTTokenManager[H, P]) ParseAndValidateJWT(token string) (*JWT[H, P], error) {
	jwt, err := tm.ParseJWT(token)
	if err != nil {
		return nil, err
	}

	if err := tm.ValidateJWT(jwt); err != nil {
		return nil, err
	}

	return jwt, nil
}

func (tm JWTTokenManager[H, P]) GenerateJWT(header *H, payload *P) (string, error) {
	jwt := &JWT[H, P]{
		Header:  *header,
		Payload: *payload,
	}

	jsonHeader, err := tm.jsonCodec.EncodeToJSON(header)
	if err != nil {
		return "", err
	}

	jwt.RawHeader, err = tm.base64Codec.EncodeToBase64(jsonHeader)
	if err != nil {
		return "", err
	}

	jsonPayload, err := tm.jsonCodec.EncodeToJSON(payload)
	if err != nil {
		return "", err
	}

	jwt.RawPayload, err = tm.base64Codec.EncodeToBase64(jsonPayload)
	if err != nil {
		return "", err
	}

	if err := tm.signatureGenerationFunc(jwt); err != nil {
		return "", err
	}

	base64EncodedSignature, err := tm.base64Codec.EncodeToBase64(jwt.Signature)
	if err != nil {
		return "", err
	}

	return jwt.RawHeader + "." + jwt.RawPayload + "." + base64EncodedSignature, nil
}
