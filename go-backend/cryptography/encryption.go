package cryptography

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var encryptionKey []byte

// InitializeEncryptionKey initializes the encryption key from the master secret
// This should be called once during application startup
func InitializeEncryptionKey(masterSecret string) error {
	if masterSecret == "" {
		return fmt.Errorf("master secret cannot be empty")
	}

	salt := []byte("projektKomunikator-encryption-v1") // Application-specific salt
	info := []byte("sensitive-data-encryption")
	hkdfReader := hkdf.New(sha256.New, []byte(masterSecret), salt, info)

	encryptionKey = make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, encryptionKey); err != nil {
		return fmt.Errorf("failed to derive encryption key: %w", err)
	}

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

// EncryptWithKey encrypts data with a provided key using AES-256-GCM
func EncryptWithKey(plaintext string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes for AES-256")
	}

	if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}

	block, err := aes.NewCipher(key)
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

// DecryptWithKey decrypts data with a provided key using AES-256-GCM
func DecryptWithKey(ciphertextB64 string, key []byte) (string, error) {
	if len(key) != 32 {
		return "", fmt.Errorf("key must be 32 bytes for AES-256")
	}

	if ciphertextB64 == "" {
		return "", fmt.Errorf("ciphertext cannot be empty")
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
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return string(plaintext), nil
}
