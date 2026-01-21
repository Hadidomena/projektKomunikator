package message_auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GenerateMessageMAC(message string, sharedSecret []byte) (string, error) {
	if len(sharedSecret) == 0 {
		return "", fmt.Errorf("shared secret cannot be empty")
	}

	h := hmac.New(sha256.New, sharedSecret)
	_, err := h.Write([]byte(message))
	if err != nil {
		return "", fmt.Errorf("failed to generate MAC: %w", err)
	}

	mac := h.Sum(nil)
	return base64.StdEncoding.EncodeToString(mac), nil
}

func VerifyMessageMAC(message string, providedMAC string, sharedSecret []byte) (bool, error) {
	if len(sharedSecret) == 0 {
		return false, fmt.Errorf("shared secret cannot be empty")
	}

	decodedProvidedMAC, err := base64.StdEncoding.DecodeString(providedMAC)
	if err != nil {
		return false, fmt.Errorf("failed to decode provided MAC: %w", err)
	}

	h := hmac.New(sha256.New, sharedSecret)
	_, err = h.Write([]byte(message))
	if err != nil {
		return false, fmt.Errorf("failed to generate expected MAC: %w", err)
	}

	expectedMAC := h.Sum(nil)
	return hmac.Equal(decodedProvidedMAC, expectedMAC), nil
}

func GenerateMessageSignature(messageID int, senderEmail string, content string, timestamp int64, sharedSecret []byte) (string, error) {
	canonical := fmt.Sprintf("%d|%s|%s|%d", messageID, senderEmail, content, timestamp)
	return GenerateMessageMAC(canonical, sharedSecret)
}

func VerifyMessageSignature(messageID int, senderEmail string, content string, timestamp int64, signature string, sharedSecret []byte) (bool, error) {
	canonical := fmt.Sprintf("%d|%s|%s|%d", messageID, senderEmail, content, timestamp)
	return VerifyMessageMAC(canonical, signature, sharedSecret)
}
