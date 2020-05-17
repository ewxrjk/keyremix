package keyremix

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
)

// GetPublicKey returns the public half of a private key
func GetPublicKey(privkey crypto.PrivateKey) (pubkey crypto.PublicKey, err error) {
	switch k := privkey.(type) {
	case *rsa.PrivateKey:
		pubkey = &k.PublicKey
	case *dsa.PrivateKey:
		pubkey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubkey = &k.PublicKey
	case ed25519.PrivateKey:
		pubkey = k.Public()
	default:
		err = ErrNotImplemented
	}
	return
}

// MarshalOpenSSLDSAKey marshal a DSA key using OpenSSL's "traditional" format.
func MarshalOpenSSLDSAKey(key *dsa.PrivateKey) (b []byte, err error) {
	type dsaPrivateKey struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Y       *big.Int
		X       *big.Int
	}
	if b, err = asn1.Marshal(dsaPrivateKey{0, key.P, key.Q, key.G, key.Y, key.X}); err != nil {
		return
	}
	b = pem.EncodeToMemory(&pem.Block{
		Type:    "DSA PRIVATE KEY",
		Headers: nil,
		Bytes:   b,
	})
	return
}
