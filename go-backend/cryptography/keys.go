package cryptography

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateE2EEKeys generates a new X25519 key pair for E2EE.
func GenerateE2EEKeys() (privateKeyB64 string, publicKeyB64 string, err error) {
	curve := ecdh.X25519()

	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	privateKeyBytes := privateKey.Bytes()
	publicKeyBytes := publicKey.Bytes()

	privateKeyB64 = base64.StdEncoding.EncodeToString(privateKeyBytes)
	publicKeyB64 = base64.StdEncoding.EncodeToString(publicKeyBytes)

	return privateKeyB64, publicKeyB64, nil
}
