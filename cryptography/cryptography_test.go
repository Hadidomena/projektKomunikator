package cryptography

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	testInput := "Hello World"
	encrypted := Encrypt(testInput)
	decrypted := Decrypt(encrypted)

	if decrypted != testInput {
		t.Errorf("Expected %s, but got %s", testInput, decrypted)
	}
	// Ensure encrypted text is different from original
	if encrypted == testInput {
		t.Errorf("Encrypted text should be different from original text")
	}
}
