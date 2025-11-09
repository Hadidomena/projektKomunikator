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

// GenerateE2EEKeys creates a new private and public key pair for E2EE.
// It returns the base64-encoded string representation of the keys.
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

// CalculateSharedSecret computes the shared secret using a local private key and a remote public key.
// Both keys are expected to be base64-encoded strings.
func CalculateSharedSecret(privateKeyB64, publicKeyB64 string) ([]byte, error) {
	curve := ecdh.X25519()

	// Decode the private key from base64
	privateKeyBytes, err := base64.StdEncoding.DecodeString(privateKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	privateKey, err := curve.NewPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key object: %w", err)
	}

	// Decode the public key from base64
	publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	publicKey, err := curve.NewPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to create public key object: %w", err)
	}

	// Perform the ECDH key exchange
	return privateKey.ECDH(publicKey)
}

// DeriveKeysFromSecret uses HKDF to derive a new root key and chain key from a shared secret.
// This is a crucial step in a Double Ratchet implementation.
func DeriveKeysFromSecret(sharedSecret, oldRootKey []byte, hashFunc func() hash.Hash) (newRootKey, newChainKey []byte, err error) {
	// The sharedSecret from ECDH is used as the input key material (IKM) for HKDF.
	// The oldRootKey is used as the "salt". This binds the new keys to the previous state.
	hkdf := hkdf.New(hashFunc, sharedSecret, oldRootKey, nil)

	// Derive the new root key (32 bytes)
	newRootKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf, newRootKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive new root key: %w", err)
	}

	// Derive the new chain key (32 bytes)
	newChainKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdf, newChainKey); err != nil {
		return nil, nil, fmt.Errorf("failed to derive new chain key: %w", err)
	}

	return newRootKey, newChainKey, nil
}

// DeriveMessageKeyFromChainKey performs a symmetric-key ratchet step.
// It takes the current chain key and derives a message key for encryption
// and the next chain key for the subsequent message. This is based on the
// Signal Protocol's KDF for message keys.
func DeriveMessageKeyFromChainKey(chainKey []byte, hashFunc func() hash.Hash) (messageKey, nextChainKey []byte) {
	mac := hmac.New(hashFunc, chainKey)

	// Derive the message key by feeding a constant (0x01) into the HMAC
	mac.Write([]byte{0x01})
	messageKey = mac.Sum(nil)

	// Derive the next chain key by feeding a different constant (0x02)
	mac.Reset()
	mac.Write([]byte{0x02})
	nextChainKey = mac.Sum(nil)

	return messageKey, nextChainKey
}
