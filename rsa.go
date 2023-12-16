package jwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

type RSASignatureManager struct {
	hash crypto.Hash
}

func (sm RSASignatureManager) Sign(signatureSource []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hasher := sm.hash.New()
	hasher.Write(signatureSource)

	return rsa.SignPKCS1v15(rand.Reader, privateKey, sm.hash, hasher.Sum(nil))
}

func (sm RSASignatureManager) Verify(signatureSource []byte, signature []byte, publicKey *rsa.PublicKey) error {
	hasher := sm.hash.New()
	hasher.Write(signatureSource)

	if err := rsa.VerifyPKCS1v15(publicKey, sm.hash, hasher.Sum(nil), signature); err != nil {
		return ErrInvalidSignature
	}

	return nil
}

var (
	RS256SignatureManager = RSASignatureManager{hash: crypto.SHA256}
	RS384SignatureManager = RSASignatureManager{hash: crypto.SHA384}
	RS512SignatureManager = RSASignatureManager{hash: crypto.SHA512}
)
