package message_utils

import (
	"crypto/sha256"
	"encoding/base64"
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

func TestEncryptDecryptMessageWithAttachments(t *testing.T) {
	// Create a test message with attachments
	msg := MessageWithAttachments{
		Content: "Test message with attachments",
		Attachments: []Attachment{
			{
				Filename:    "test.txt",
				ContentType: "text/plain",
				Size:        100,
				Data:        "SGVsbG8gV29ybGQh", // "Hello World!" in base64
			},
			{
				Filename:    "image.png",
				ContentType: "image/png",
				Size:        2048,
				Data:        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
			},
		},
	}

	// Generate a test key (32 bytes for AES-256)
	key := []byte("12345678901234567890123456789012")

	// Encrypt the message
	encrypted, err := EncryptMessageWithAttachments(msg, key)
	if err != nil {
		t.Fatalf("EncryptMessageWithAttachments failed: %v", err)
	}

	// Ensure encrypted is not empty
	if encrypted == "" {
		t.Error("encrypted message should not be empty")
	}

	// Decrypt the message
	decrypted, err := DecryptMessageWithAttachments(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptMessageWithAttachments failed: %v", err)
	}

	// Verify content
	if decrypted.Content != msg.Content {
		t.Errorf("content mismatch: got %q, want %q", decrypted.Content, msg.Content)
	}

	// Verify attachments count
	if len(decrypted.Attachments) != len(msg.Attachments) {
		t.Errorf("attachments count mismatch: got %d, want %d", len(decrypted.Attachments), len(msg.Attachments))
	}

	// Verify each attachment
	for i := range msg.Attachments {
		if decrypted.Attachments[i].Filename != msg.Attachments[i].Filename {
			t.Errorf("attachment %d filename mismatch: got %q, want %q", i, decrypted.Attachments[i].Filename, msg.Attachments[i].Filename)
		}
		if decrypted.Attachments[i].ContentType != msg.Attachments[i].ContentType {
			t.Errorf("attachment %d content type mismatch: got %q, want %q", i, decrypted.Attachments[i].ContentType, msg.Attachments[i].ContentType)
		}
		if decrypted.Attachments[i].Size != msg.Attachments[i].Size {
			t.Errorf("attachment %d size mismatch: got %d, want %d", i, decrypted.Attachments[i].Size, msg.Attachments[i].Size)
		}
		if decrypted.Attachments[i].Data != msg.Attachments[i].Data {
			t.Errorf("attachment %d data mismatch", i)
		}
	}
}

func TestEncryptDecryptMessageWithoutAttachments(t *testing.T) {
	// Test message without attachments
	msg := MessageWithAttachments{
		Content:     "Simple message without attachments",
		Attachments: nil,
	}

	key := []byte("12345678901234567890123456789012")

	encrypted, err := EncryptMessageWithAttachments(msg, key)
	if err != nil {
		t.Fatalf("EncryptMessageWithAttachments failed: %v", err)
	}

	decrypted, err := DecryptMessageWithAttachments(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptMessageWithAttachments failed: %v", err)
	}

	if decrypted.Content != msg.Content {
		t.Errorf("content mismatch: got %q, want %q", decrypted.Content, msg.Content)
	}

	if len(decrypted.Attachments) != 0 {
		t.Errorf("expected no attachments, got %d", len(decrypted.Attachments))
	}
}

func TestBackwardCompatibilityWithPlainText(t *testing.T) {
	// Test backward compatibility: old encrypted messages (plain text) should still decrypt
	plaintext := "Old style message without JSON structure"
	key := []byte("12345678901234567890123456789012")

	// Encrypt using old method
	encrypted, err := EncryptMessage(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptMessage failed: %v", err)
	}

	// Decrypt using new method should fall back to plain text
	decrypted, err := DecryptMessageWithAttachments(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptMessageWithAttachments failed: %v", err)
	}

	if decrypted.Content != plaintext {
		t.Errorf("content mismatch: got %q, want %q", decrypted.Content, plaintext)
	}

	if len(decrypted.Attachments) != 0 {
		t.Errorf("expected no attachments for plain text message, got %d", len(decrypted.Attachments))
	}
}

func TestInvalidKeySize(t *testing.T) {
	msg := MessageWithAttachments{
		Content: "Test message",
	}

	// Test with invalid key size (not 32 bytes)
	invalidKey := []byte("short")

	_, err := EncryptMessageWithAttachments(msg, invalidKey)
	if err == nil {
		t.Error("expected error with invalid key size, got nil")
	}

	// Test decryption with invalid key
	encrypted, _ := EncryptMessageWithAttachments(msg, []byte("12345678901234567890123456789012"))
	_, err = DecryptMessageWithAttachments(encrypted, invalidKey)
	if err == nil {
		t.Error("expected error with invalid key size during decryption, got nil")
	}
}

func TestLargeAttachment(t *testing.T) {
	// Test with a reasonably sized attachment
	largeData := make([]byte, 1024*10) // 10KB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Encode as base64 (as it should be for binary data in JSON)
	largeDataB64 := base64.StdEncoding.EncodeToString(largeData)

	msg := MessageWithAttachments{
		Content: "Message with large attachment",
		Attachments: []Attachment{
			{
				Filename:    "large_file.bin",
				ContentType: "application/octet-stream",
				Size:        int64(len(largeData)),
				Data:        largeDataB64,
			},
		},
	}

	key := []byte("12345678901234567890123456789012")

	encrypted, err := EncryptMessageWithAttachments(msg, key)
	if err != nil {
		t.Fatalf("EncryptMessageWithAttachments with large attachment failed: %v", err)
	}

	decrypted, err := DecryptMessageWithAttachments(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptMessageWithAttachments with large attachment failed: %v", err)
	}

	if len(decrypted.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(decrypted.Attachments))
	}

	if decrypted.Attachments[0].Size != msg.Attachments[0].Size {
		t.Errorf("attachment size mismatch: got %d, want %d", decrypted.Attachments[0].Size, msg.Attachments[0].Size)
	}

	if decrypted.Attachments[0].Filename != msg.Attachments[0].Filename {
		t.Errorf("attachment filename mismatch: got %s, want %s", decrypted.Attachments[0].Filename, msg.Attachments[0].Filename)
	}

	if decrypted.Attachments[0].Data != largeDataB64 {
		t.Error("large attachment data mismatch after encryption/decryption")
	}
}
