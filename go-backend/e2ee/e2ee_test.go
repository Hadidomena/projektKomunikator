package e2ee

import (
	"os"
	"testing"

	"github.com/Hadidomena/projektKomunikator/cryptography"
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

func TestStoreAndRetrievePrivateKey(t *testing.T) {
	fingerprint := "test_fingerprint_12345"
	privateKey := "test_private_key_abc123"

	if err := cryptography.InitializeEncryptionKey("test_master_secret"); err != nil {
		t.Fatalf("Failed to initialize encryption key: %v", err)
	}

	// Store the key
	err := StorePrivateKeyInEnv(fingerprint, privateKey)
	if err != nil {
		t.Fatalf("Failed to store private key: %v", err)
	}

	// Retrieve the key
	retrieved, err := GetPrivateKeyFromEnv(fingerprint)
	if err != nil {
		t.Fatalf("Failed to retrieve private key: %v", err)
	}

	if retrieved != privateKey {
		t.Errorf("Expected %s, got %s", privateKey, retrieved)
	}

	// Clean up
	envVarName := "E2EE_PRIVATE_KEY_" + fingerprint
	os.Unsetenv(envVarName)
}

func TestGetPrivateKeyFromEnv_NotFound(t *testing.T) {
	fingerprint := "nonexistent_fingerprint"

	_, err := GetPrivateKeyFromEnv(fingerprint)
	if err == nil {
		t.Error("Expected error when retrieving non-existent private key")
	}
}

func TestComputeSharedSecret(t *testing.T) {
	// Generate two key pairs
	keys1, err := GenerateDeviceKeys(1, "Device1")
	if err != nil {
		t.Fatalf("Failed to generate keys for device 1: %v", err)
	}

	keys2, err := GenerateDeviceKeys(2, "Device2")
	if err != nil {
		t.Fatalf("Failed to generate keys for device 2: %v", err)
	}

	// Compute shared secret from device 1's perspective
	secret1, err := ComputeSharedSecret(keys1.PrivateKey, keys2.PublicKey)
	if err != nil {
		t.Fatalf("Failed to compute shared secret from device 1: %v", err)
	}

	// Compute shared secret from device 2's perspective
	secret2, err := ComputeSharedSecret(keys2.PrivateKey, keys1.PublicKey)
	if err != nil {
		t.Fatalf("Failed to compute shared secret from device 2: %v", err)
	}

	// Both shared secrets should be identical
	if len(secret1) != len(secret2) {
		t.Errorf("Shared secret lengths differ: %d vs %d", len(secret1), len(secret2))
	}

	for i := range secret1 {
		if secret1[i] != secret2[i] {
			t.Error("Shared secrets do not match")
			break
		}
	}

	// Shared secret should be 32 bytes (X25519 output)
	if len(secret1) != 32 {
		t.Errorf("Expected shared secret length 32, got %d", len(secret1))
	}
}

func TestComputeSharedSecret_InvalidKeys(t *testing.T) {
	_, err := ComputeSharedSecret("invalid_private_key", "invalid_public_key")
	if err == nil {
		t.Error("Expected error when computing shared secret with invalid keys")
	}
}

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

func TestDeviceInfoStructure(t *testing.T) {
	info := &DeviceInfo{
		ID:                1,
		UserID:            100,
		DeviceName:        "TestDevice",
		PublicKey:         "test_public_key",
		DeviceFingerprint: "test_fingerprint",
		LastUsed:          "2026-01-15T10:00:00Z",
		CreatedAt:         "2026-01-01T10:00:00Z",
		IsActive:          true,
	}

	if info.ID != 1 || info.UserID != 100 {
		t.Error("DeviceInfo IDs not set correctly")
	}

	if info.DeviceName != "TestDevice" {
		t.Error("DeviceName not set correctly")
	}

	if !info.IsActive {
		t.Error("IsActive should be true")
	}
}
