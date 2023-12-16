package jwt

import "crypto/ed25519"

type ED25519SignatureManager struct{}

func (sm ED25519SignatureManager) Sign(signatureSource []byte, privateKey ed25519.PrivateKey) ([]byte, error) {
	return ed25519.Sign(privateKey, signatureSource), nil
}

func (sm ED25519SignatureManager) Verify(signatureSource []byte, signature []byte, publicKey ed25519.PublicKey) error {
	if !ed25519.Verify(publicKey, signatureSource, signature) {
		return ErrInvalidSignature
	}

	return nil
}

var EDDSASignatureManager ED25519SignatureManager
