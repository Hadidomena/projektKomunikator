package e2ee

import (
	"testing"
)

func TestGenerateDeviceKeys(t *testing.T) {
	userID := 123
	deviceName := "iPhone 15"

	keys, err := GenerateDeviceKeys(userID, deviceName)
	if err != nil {
		t.Fatalf("Failed to generate device keys: %v", err)
	}

	if keys.PublicKey == "" {
		t.Error("Public key should not be empty")
	}

	if keys.PrivateKey == "" {
		t.Error("Private key should not be empty")
	}

	if keys.DeviceFingerprint == "" {
		t.Error("Device fingerprint should not be empty")
	}

	// Fingerprint should be consistent
	fingerprint2 := GenerateDeviceFingerprint(userID, deviceName, keys.PublicKey)
	if keys.DeviceFingerprint != fingerprint2 {
		t.Error("Device fingerprint should be consistent")
	}
}

func TestGenerateDeviceFingerprint(t *testing.T) {
	userID := 1
	deviceName := "Desktop"
	publicKey := "test_public_key"

	fingerprint1 := GenerateDeviceFingerprint(userID, deviceName, publicKey)
	fingerprint2 := GenerateDeviceFingerprint(userID, deviceName, publicKey)

	if fingerprint1 != fingerprint2 {
		t.Error("Fingerprint should be deterministic")
	}

	if len(fingerprint1) != 64 { // SHA-256 produces 64 hex characters
		t.Errorf("Expected fingerprint length 64, got %d", len(fingerprint1))
	}

	// Different inputs should produce different fingerprints
	fingerprint3 := GenerateDeviceFingerprint(userID, "Mobile", publicKey)
	if fingerprint1 == fingerprint3 {
		t.Error("Different device names should produce different fingerprints")
	}
}

// NOTE: ComputeSharedSecret was removed - E2EE encryption/decryption is now done client-side

func TestDeviceKeyPairStructure(t *testing.T) {
	keys := &DeviceKeyPair{
		DeviceID:          1,
		DeviceFingerprint: "abc123",
		PublicKey:         "public_key_data",
		PrivateKey:        "private_key_data",
	}

	if keys.DeviceID != 1 {
		t.Error("DeviceID not set correctly")
	}

	if keys.DeviceFingerprint != "abc123" {
		t.Error("DeviceFingerprint not set correctly")
	}

	if keys.PublicKey != "public_key_data" {
		t.Error("PublicKey not set correctly")
	}

	if keys.PrivateKey != "private_key_data" {
		t.Error("PrivateKey not set correctly")
	}
}
