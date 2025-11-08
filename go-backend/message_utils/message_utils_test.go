package message_utils

import "testing"

func TestAfterEncryptionShouldNotBeTheSame(t *testing.T) {
	// Should not return same text after encryption
	message := "Short example text"
	encrypted, _ := EncryptMessage(message)

	if encrypted == message {
		t.Errorf("Password should not be the same after encryption")
	}
}

func TestShouldCorrectlyDecrypt(t *testing.T) {
	message := "Short example text"
	encrypted, _ := EncryptMessage(message)
	decrypted, _ := DecryptMessage(encrypted)

	if decrypted != message {
		t.Errorf("Password should be the same as before decryption")
	}
}
