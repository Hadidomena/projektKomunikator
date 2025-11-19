package message_utils

import (
	"crypto/sha256"
	"testing"

	"github.com/Hadidomena/projektKomunikator/cryptography"
)

func TestEncryptedShouldNotBeTheSame(t *testing.T) {
	plaintext := "Short example text"

	chainKey := []byte("test-chain-key-0000000000000000000000")
	msgKey, _ := cryptography.DeriveMessageKeyFromChainKey(chainKey, sha256.New)

	encrypted, err := EncryptMessage(plaintext, msgKey)
	if err != nil {
		t.Fatalf("EncryptMessage returned error: %v", err)
	}

	if encrypted == plaintext {
		t.Errorf("encrypted output should not equal plaintext")
	}
}

func TestEncryptDecryptShouldReturnOriginal(t *testing.T) {
	plaintext := "Short example text"

	chainKey := []byte("another-test-chain-key-00000000000000")
	msgKey, _ := cryptography.DeriveMessageKeyFromChainKey(chainKey, sha256.New)

	encrypted, err := EncryptMessage(plaintext, msgKey)
	if err != nil {
		t.Fatalf("EncryptMessage returned error: %v", err)
	}

	decrypted, err := DecryptMessage(encrypted, msgKey)
	if err != nil {
		t.Fatalf("DecryptMessage returned error: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("decrypted message does not match original: got %q want %q", decrypted, plaintext)
	}
}

func TestRatchetingDerivationProducesDifferentKeys(t *testing.T) {
	// Start with an initial chain key and perform two sequential derivations
	chainKey := []byte("ratchet-chain-key-initial-000000000000")

	// First message key and next chain key
	msgKey1, nextChain := cryptography.DeriveMessageKeyFromChainKey(chainKey, sha256.New)

	// Second message key derived from nextChain
	msgKey2, _ := cryptography.DeriveMessageKeyFromChainKey(nextChain, sha256.New)

	if string(msgKey1) == string(msgKey2) {
		t.Errorf("message keys from successive ratchet steps should differ")
	}

	// Encrypt two messages with different message keys and ensure they decrypt correctly
	m1 := "first"
	m2 := "second"

	e1, err := EncryptMessage(m1, msgKey1)
	if err != nil {
		t.Fatalf("EncryptMessage m1 error: %v", err)
	}
	e2, err := EncryptMessage(m2, msgKey2)
	if err != nil {
		t.Fatalf("EncryptMessage m2 error: %v", err)
	}

	d1, err := DecryptMessage(e1, msgKey1)
	if err != nil {
		t.Fatalf("DecryptMessage m1 error: %v", err)
	}
	d2, err := DecryptMessage(e2, msgKey2)
	if err != nil {
		t.Fatalf("DecryptMessage m2 error: %v", err)
	}

	if d1 != m1 {
		t.Errorf("decrypted first message mismatch: got %q want %q", d1, m1)
	}
	if d2 != m2 {
		t.Errorf("decrypted second message mismatch: got %q want %q", d2, m2)
	}
}

func 