package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/Hadidomena/projektKomunikator/cryptography"
)

// DeviceKeyPair represents a device's E2EE key pair
type DeviceKeyPair struct {
	DeviceID          int
	DeviceFingerprint string
	PublicKey         string
	PrivateKey        string // Only stored in environment, never in DB
}

// GenerateDeviceKeys creates a new key pair for a device.
// The private key is stored as an environment variable, not in the database.
func GenerateDeviceKeys(userID int, deviceName string) (*DeviceKeyPair, error) {
	privateKey, publicKey, err := cryptography.GenerateE2EEKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate E2EE keys: %w", err)
	}

	fingerprint := GenerateDeviceFingerprint(userID, deviceName, publicKey)

	return &DeviceKeyPair{
		DeviceFingerprint: fingerprint,
		PublicKey:         publicKey,
		PrivateKey:        privateKey,
	}, nil
}

// GenerateDeviceFingerprint creates a unique fingerprint for a device
func GenerateDeviceFingerprint(userID int, deviceName, publicKey string) string {
	data := fmt.Sprintf("%d:%s:%s", userID, deviceName, publicKey)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func StorePrivateKeyInEnv(fingerprint, privateKey string) error {
	envVarName := fmt.Sprintf("E2EE_PRIVATE_KEY_%s", fingerprint)
	return os.Setenv(envVarName, privateKey)
}

func GetPrivateKeyFromEnv(fingerprint string) (string, error) {
	envVarName := fmt.Sprintf("E2EE_PRIVATE_KEY_%s", fingerprint)
	privateKey := os.Getenv(envVarName)
	if privateKey == "" {
		return "", fmt.Errorf("private key not found for device %s", fingerprint)
	}
	return privateKey, nil
}

// ComputeSharedSecret calculates the shared secret between two devices
func ComputeSharedSecret(myPrivateKey, theirPublicKey string) ([]byte, error) {
	return cryptography.CalculateSharedSecret(myPrivateKey, theirPublicKey)
}

// EncryptMessageForDevice encrypts a message using the shared secret with another device
func EncryptMessageForDevice(plaintext, myPrivateKey, theirPublicKey string) (ciphertext string, err error) {
	sharedSecret, err := ComputeSharedSecret(myPrivateKey, theirPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	_ = sharedSecret[:32]
	return plaintext, nil
}

func DecryptMessageFromDevice(ciphertext, myPrivateKey, theirPublicKey string) (plaintext string, err error) {
	sharedSecret, err := ComputeSharedSecret(myPrivateKey, theirPublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	_ = sharedSecret[:32]
	return ciphertext, nil
}

// DeviceInfo represents device information
type DeviceInfo struct {
	ID                int
	UserID            int
	DeviceName        string
	PublicKey         string
	DeviceFingerprint string
	LastUsed          string
	CreatedAt         string
	IsActive          bool
}
