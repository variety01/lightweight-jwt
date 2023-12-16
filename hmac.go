package jwt

import (
	"crypto"
	"crypto/hmac"
)

type HMACSignatureManager struct {
	hash crypto.Hash
}

func (sm HMACSignatureManager) Sign(signatureSource []byte, secretKey []byte) ([]byte, error) {
	h := hmac.New(sm.hash.New, secretKey)
	h.Write(signatureSource)

	return h.Sum(nil), nil
}

func (sm HMACSignatureManager) Verify(signatureSource []byte, signature []byte, secretKey []byte) error {
	h := hmac.New(sm.hash.New, secretKey)
	h.Write(signatureSource)
	calculatedSignature := h.Sum(nil)
	if !hmac.Equal(signature, calculatedSignature) {
		return ErrInvalidSignature
	}

	return nil
}

var (
	HS256SignatureManager = HMACSignatureManager{hash: crypto.SHA256}
	HS384SignatureManager = HMACSignatureManager{hash: crypto.SHA384}
	HS512SignatureManager = HMACSignatureManager{hash: crypto.SHA512}
)
