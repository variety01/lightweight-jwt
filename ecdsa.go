package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
)

type ECDSASignatureManager struct {
	hash      crypto.Hash
	keySize   int
	curveBits int
}

func (sm ECDSASignatureManager) Sign(signatureSource []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hasher := sm.hash.New()
	hasher.Write(signatureSource)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hasher.Sum(nil))
	if err != nil {
		return nil, err
	}

	curveBits := privateKey.Curve.Params().BitSize
	if curveBits != sm.curveBits {
		return nil, fmt.Errorf("ecdsa: invalid curve bitsize: %d", curveBits)
	}

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	signature := make([]byte, 2*keyBytes)
	r.FillBytes(signature[0:keyBytes])
	s.FillBytes(signature[keyBytes:])

	return signature, nil
}

func (sm ECDSASignatureManager) Verify(signatureSource []byte, signature []byte, publicKey *ecdsa.PublicKey) error {
	if len(signature) != 2*sm.keySize {
		return ErrInvalidSignature
	}

	hasher := sm.hash.New()
	hasher.Write(signatureSource)

	r := big.NewInt(0).SetBytes(signature[:sm.keySize])
	s := big.NewInt(0).SetBytes(signature[sm.keySize:])

	if !ecdsa.Verify(publicKey, hasher.Sum(nil), r, s) {
		return ErrInvalidSignature
	}

	return nil
}

var (
	ES256SignatureManager = ECDSASignatureManager{hash: crypto.SHA256, keySize: 32, curveBits: 256}
	ES384SignatureManager = ECDSASignatureManager{hash: crypto.SHA384, keySize: 48, curveBits: 384}
	ES512SignatureManager = ECDSASignatureManager{hash: crypto.SHA512, keySize: 66, curveBits: 521}
)
