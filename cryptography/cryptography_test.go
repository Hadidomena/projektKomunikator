package cryptography

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testInput := "Hello World"

	// Test encryption and decryption
	encrypted := cryptography.Encrypt(testInput)
	// Test encryption and decryption
	encrypted := Encrypt(testInput)
	decrypted := Decrypt(encrypted)
		t.Errorf("Expected %s, but got %s", testInput, decrypted)
	}
	// Ensure encrypted text is different from original
	if encrypted == testInput {
		t.Errorf("Encrypted text should be different from original text")
	}
}
