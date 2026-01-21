package message_auth

import (
	"crypto/rand"
	"testing"
)

func TestGenerateMessageMAC(t *testing.T) {
	message := "Hello, this is a test message"
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	mac, err := GenerateMessageMAC(message, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate MAC: %v", err)
	}

	if mac == "" {
		t.Error("Generated MAC should not be empty")
	}

	// MAC should be base64 encoded
	if len(mac) == 0 {
		t.Error("MAC length should be greater than 0")
	}
}

func TestVerifyMessageMAC(t *testing.T) {
	message := "Hello, this is a test message"
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	// Generate MAC
	mac, err := GenerateMessageMAC(message, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate MAC: %v", err)
	}

	// Verify MAC with correct message and secret
	valid, err := VerifyMessageMAC(message, mac, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to verify MAC: %v", err)
	}

	if !valid {
		t.Error("MAC should be valid for correct message and secret")
	}
}

func TestVerifyMessageMAC_InvalidMessage(t *testing.T) {
	message := "Hello, this is a test message"
	tamperedMessage := "Hello, this is a tampered message"
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	// Generate MAC for original message
	mac, err := GenerateMessageMAC(message, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate MAC: %v", err)
	}

	// Verify MAC with tampered message
	valid, err := VerifyMessageMAC(tamperedMessage, mac, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to verify MAC: %v", err)
	}

	if valid {
		t.Error("MAC should be invalid for tampered message")
	}
}

func TestVerifyMessageMAC_InvalidSecret(t *testing.T) {
	message := "Hello, this is a test message"
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")
	wrongSecret := []byte("wrong-shared-secret-key-32-bytes")

	// Generate MAC with correct secret
	mac, err := GenerateMessageMAC(message, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate MAC: %v", err)
	}

	// Verify MAC with wrong secret
	valid, err := VerifyMessageMAC(message, mac, wrongSecret)
	if err != nil {
		t.Fatalf("Failed to verify MAC: %v", err)
	}

	if valid {
		t.Error("MAC should be invalid with wrong secret")
	}
}

func TestGenerateMessageSignature(t *testing.T) {
	messageID := 123
	senderEmail := "sender@example.com"
	content := "Test message content"
	timestamp := int64(1234567890)
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	signature, err := GenerateMessageSignature(messageID, senderEmail, content, timestamp, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate message signature: %v", err)
	}

	if signature == "" {
		t.Error("Generated signature should not be empty")
	}
}

func TestVerifyMessageSignature(t *testing.T) {
	messageID := 123
	senderEmail := "sender@example.com"
	content := "Test message content"
	timestamp := int64(1234567890)
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	// Generate signature
	signature, err := GenerateMessageSignature(messageID, senderEmail, content, timestamp, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate message signature: %v", err)
	}

	// Verify signature with correct parameters
	valid, err := VerifyMessageSignature(messageID, senderEmail, content, timestamp, signature, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to verify message signature: %v", err)
	}

	if !valid {
		t.Error("Signature should be valid for correct parameters")
	}
}

func TestVerifyMessageSignature_TamperedContent(t *testing.T) {
	messageID := 123
	senderEmail := "sender@example.com"
	content := "Test message content"
	tamperedContent := "Tampered message content"
	timestamp := int64(1234567890)
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	// Generate signature for original content
	signature, err := GenerateMessageSignature(messageID, senderEmail, content, timestamp, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to generate message signature: %v", err)
	}

	// Verify signature with tampered content
	valid, err := VerifyMessageSignature(messageID, senderEmail, tamperedContent, timestamp, signature, sharedSecret)
	if err != nil {
		t.Fatalf("Failed to verify message signature: %v", err)
	}

	if valid {
		t.Error("Signature should be invalid for tampered content")
	}
}

func TestGenerateMessageMAC_EmptySecret(t *testing.T) {
	message := "Test message"
	emptySecret := []byte{}

	_, err := GenerateMessageMAC(message, emptySecret)
	if err == nil {
		t.Error("Should return error for empty shared secret")
	}
}

func TestVerifyMessageMAC_EmptySecret(t *testing.T) {
	message := "Test message"
	mac := "some-mac-value"
	emptySecret := []byte{}

	_, err := VerifyMessageMAC(message, mac, emptySecret)
	if err == nil {
		t.Error("Should return error for empty shared secret")
	}
}

func TestVerifyMessageMAC_InvalidBase64(t *testing.T) {
	message := "Test message"
	invalidMAC := "not-valid-base64!!!"
	sharedSecret := []byte("test-shared-secret-key-32-bytes!")

	_, err := VerifyMessageMAC(message, invalidMAC, sharedSecret)
	if err == nil {
		t.Error("Should return error for invalid base64 MAC")
	}
}

func BenchmarkGenerateMessageMAC(b *testing.B) {
	message := "This is a benchmark test message"
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateMessageMAC(message, sharedSecret)
	}
}

func BenchmarkVerifyMessageMAC(b *testing.B) {
	message := "This is a benchmark test message"
	sharedSecret := make([]byte, 32)
	rand.Read(sharedSecret)

	mac, _ := GenerateMessageMAC(message, sharedSecret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyMessageMAC(message, mac, sharedSecret)
	}
}
