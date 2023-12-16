package jwt

type JWT[H, P any] struct {
	Header  H
	Payload P

	Signature []byte

	// Base64URL json encoded header
	RawHeader string
	// Base64URL json encoded payload
	RawPayload string
}

func (j *JWT[H, P]) GetSignatureSource() []byte {
	return []byte(j.RawHeader + "." + j.RawPayload)
}

type DefaultJWTHeader struct {
	Algorithm string `json:"alg,omitempty"`
	Type      string `json:"typ,omitempty"`
	KeyID     string `json:"kid,omitempty"`
}

type DefaultJWTPayload struct {
	Issuer     string `json:"iss,omitempty"`
	Subject    string `json:"sub,omitempty"`
	Audience   string `json:"aud,omitempty"`
	Expiration uint64 `json:"exp,omitempty"`
	NotBefore  uint64 `json:"nbf,omitempty"`
	IssuedAt   uint64 `json:"iat,omitempty"`
	JWTID      string `json:"jti,omitempty"`
}
