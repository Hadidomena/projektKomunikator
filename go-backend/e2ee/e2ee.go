package e2ee

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/Hadidomena/projektKomunikator/cryptography"
)

// DeviceKeyPair represents a user's E2EE key pair
type DeviceKeyPair struct {
	DeviceID          int
	DeviceFingerprint string
	PublicKey         string
	PrivateKey        string // Encrypted with user's password before storage in DB
}

// GenerateDeviceKeys creates a new X25519 key pair for a user.
// The private key should be encrypted with the user's password before storage.
// NOTE: All E2EE encryption/decryption (Double Ratchet, ECDH) is done client-side.
// This function is only used during user registration.
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

// GenerateDeviceFingerprint creates a unique fingerprint for a key pair
func GenerateDeviceFingerprint(userID int, deviceName, publicKey string) string {
	data := fmt.Sprintf("%d:%s:%s", userID, deviceName, publicKey)
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}
