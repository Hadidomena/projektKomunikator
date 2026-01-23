package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
)

var encryptionKey []byte

// InitializeEncryptionKey initializes the encryption key from the master secret
// This should be called once during application startup
func InitializeEncryptionKey(masterSecret string) error {
	if masterSecret == "" {
		return fmt.Errorf("master secret cannot be empty")
	}

	// Derive a 32-byte key from the master secret using SHA-256
	hash := sha256.Sum256([]byte(masterSecret))
	encryptionKey = hash[:]

	return nil
}

// EncryptSensitiveData encrypts sensitive data using AES-256-GCM
// This should be used for encrypting TOTP secrets, password reset tokens, etc.
func EncryptSensitiveData(plaintext string) (string, error) {
	if encryptionKey == nil || len(encryptionKey) != 32 {
		return "", fmt.Errorf("encryption key not initialized")
	}

	if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptSensitiveData decrypts sensitive data encrypted with EncryptSensitiveData
func DecryptSensitiveData(ciphertextB64 string) (string, error) {
	if encryptionKey == nil || len(encryptionKey) != 32 {
		return "", fmt.Errorf("encryption key not initialized")
	}

	if ciphertextB64 == "" {
		return "", fmt.Errorf("ciphertext cannot be empty")
	}

	data, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	block, err := aes.NewCipher(encryptionKey)
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
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return string(plaintext), nil
}
