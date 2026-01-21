package cryptography

import (
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

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

func CalculateSharedSecret(privateKeyB64, publicKeyB64 string) ([]byte, error) {
	curve := ecdh.X25519()

	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	privateKey, err := curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key object: %w", err)
	}

	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	publicKey, err := curve.NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key object: %w", err)
	}

	return privateKey.ECDH(publicKey)
}

// DeriveKeysFromSecret uses HKDF to derive a new root key and chain key from a shared secret.
// This is a crucial step in a Double Ratchet implementation.
func DeriveKeysFromSecret(sharedSecret, oldRootKey []byte, hashFunc func() hash.Hash) (newRootKey, newChainKey []byte, err error) {
	hkdf := hkdf.New(hashFunc, sharedSecret, oldRootKey, nil)

	newRootKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf, newRootKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive new root key: %w", err)
	}

	newChainKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf, newChainKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive new chain key: %w", err)
	}

	return newRootKey, newChainKey, nil
}

// DeriveMessageKeyFromChainKey performs a symmetric-key ratchet step.
// Based on the Signal Protocol's KDF for message keys.
func DeriveMessageKeyFromChainKey(chainKey []byte, hashFunc func() hash.Hash) (messageKey, nextChainKey []byte) {
	mac := hmac.New(hashFunc, chainKey)

	mac.Write([]byte{0x01})
	messageKey = mac.Sum(nil)

	mac.Reset()
	mac.Write([]byte{0x02})
	nextChainKey = mac.Sum(nil)

	return messageKey, nextChainKey
}
