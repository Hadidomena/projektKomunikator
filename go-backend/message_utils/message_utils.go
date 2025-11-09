package message_utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// EncryptMessage encrypts a plaintext message using AES-GCM with the provided key.
// The key should be a 32-byte message key derived from the Double Ratchet.
// The output is a base64-encoded string containing the nonce and the ciphertext.
func EncryptMessage(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key size: must be 32 bytes for AES-256")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// A nonce is a unique number for each message encrypted with the same key.
	// It does not have to be secret, just unique.
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal will encrypt the plaintext and append the authentication tag.
	// The nonce is prepended to the ciphertext for use during decryption.
	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptMessage decrypts a base64-encoded ciphertext using AES-GCM.
// The key must be the same 32-byte message key used for encryption.
func DecryptMessage(ciphertextB64 string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key size: must be 32 bytes for AES-256")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// This error can indicate a wrong key or a tampered message.
		return "", fmt.Errorf("failed to decrypt message: %w", err)
	}

	return string(plaintext), nil
}
