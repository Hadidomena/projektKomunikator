package cryptography

import (
	"testing"
)

func TestHashPassword(t *testing.T) {
	testInput := "Hello World"
	hashed, _ := HashPassword(testInput)
	secondHash, _ := HashPassword(testInput)

	if hashed == secondHash {
		t.Errorf("First hash %s should be different from second hash %s", testInput, secondHash)
	}
	if hashed == testInput {
		t.Errorf("Hashed text should be different from original text")
	}

	// Test with empty password
	_, err := HashPassword("")
	if err == nil {
		t.Errorf("Should return error on empty password")
	}
}
func TestVerifyPassword(t *testing.T) {
	testPassword := "Hello World"
	hashed, _ := HashPassword(testPassword)
	isVerified, _ := VerifyPassword(testPassword, hashed)

	if !isVerified {
		t.Errorf("Password should be verified positively")
	}

	isVerified, _ = VerifyPassword("Wrong Password", hashed)
	if isVerified {
		t.Errorf("Password should be verified negatively")
	}

	_, err := VerifyPassword(testPassword, "invalid hash")
	if err == nil {
		t.Errorf("Should return error on malformed hash")
	}

	// Test with empty password
	isVerified, err = VerifyPassword("", hashed)
	if isVerified || err != nil {
		t.Errorf("Should return false and no error on empty password")
	}
}

func Test_decodeHash(t *testing.T) {
	// Test case 1: Valid hash
	password := "password123"
	encodedHash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	_, _, _, err = decodeHash(encodedHash)
	if err != nil {
		t.Errorf("decodeHash() failed with valid hash: %v", err)
	}

	// Test case 2: Invalid hash format (not enough parts)
	invalidHash := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ"
	_, _, _, err = decodeHash(invalidHash)
	if err == nil {
		t.Errorf("decodeHash() should have failed with invalid hash format")
	}

	// Test case 3: Unsupported hash type
	unsupportedHash := "$argon2i$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZXNhbHQ"
	_, _, _, err = decodeHash(unsupportedHash)
	if err == nil {
		t.Errorf("decodeHash() should have failed with unsupported hash type")
	}

	// Test case 4: Incompatible version
	incompatibleVersionHash := "$argon2id$v=18$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZXNhbHQ"
	_, _, _, err = decodeHash(incompatibleVersionHash)
	if err == nil {
		t.Errorf("decodeHash() should have failed with incompatible version")
	}

	// Test case 5: Invalid parameters
	invalidParamsHash := "$argon2id$v=19$m=65536,t=,p=2$c29tZXNhbHQ$c29tZXNhbHQ"
	_, _, _, err = decodeHash(invalidParamsHash)
	if err == nil {
		t.Errorf("decodeHash() should have failed with invalid parameters")
	}

	// Test case 6: Invalid base64 salt
	invalidSaltHash := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ-$c29tZXNhbHQ"
	_, _, _, err = decodeHash(invalidSaltHash)
	if err == nil {
		t.Errorf("decodeHash() should have failed with invalid base64 salt")
	}

	// Test case 7: Invalid base64 hash
	invalidB64Hash := "$argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$c29tZXNhbHQ-"
	_, _, _, err = decodeHash(invalidB64Hash)
	if err == nil {
		t.Errorf("decodeHash() should have failed with invalid base64 hash")
	}
}

func TestGenerateE2EEKeys(t *testing.T) {
	// Test case keys should be generated
	priv, pub, err := GenerateE2EEKeys()
	if err != nil {
		t.Errorf("Failed to generate keys: %v", err)
	}
	if priv == "" || pub == "" {
		t.Errorf("Generated keys should not be empty")
	}
	if priv == pub {
		t.Errorf("Generated keys should not be the same")
	}

	priv2, pub2, err := GenerateE2EEKeys()
	if priv2 == priv || pub2 == pub {
		t.Errorf("Generated keys should not be the same between two generations")
	}
}

func TestDeriveKeyFromPassword(t *testing.T) {
	key1, err := DeriveKeyFromPassword("testPassword123", 1)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	if len(key1) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(key1))
	}

	key2, err := DeriveKeyFromPassword("testPassword123", 1)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	for i := range key1 {
		if key1[i] != key2[i] {
			t.Errorf("Same inputs should produce same key")
			break
		}
	}

	key3, err := DeriveKeyFromPassword("testPassword123", 2)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	same := true
	for i := range key1 {
		if key1[i] != key3[i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("Different userID should produce different key")
	}

	key4, err := DeriveKeyFromPassword("differentPassword", 1)
	if err != nil {
		t.Fatalf("Failed to derive key: %v", err)
	}
	same = true
	for i := range key1 {
		if key1[i] != key4[i] {
			same = false
			break
		}
	}
	if same {
		t.Errorf("Different password should produce different key")
	}

	_, err = DeriveKeyFromPassword("", 1)
	if err == nil {
		t.Errorf("Empty password should return error")
	}
}

func TestEncryptDecryptForUser(t *testing.T) {
	err := InitializeEncryptionKey("test-master-secret-for-testing-purposes")
	if err != nil {
		t.Fatalf("Failed to initialize encryption key: %v", err)
	}

	password := "userPassword123"
	userID := 42
	plaintext := "This is a secret private key or TOTP secret"

	encrypted, err := EncryptForUser(plaintext, password, userID)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}
	if encrypted == plaintext {
		t.Errorf("Encrypted data should differ from plaintext")
	}

	decrypted, err := DecryptForUser(encrypted, password, userID)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("Decrypted data should match original plaintext")
	}

	_, err = DecryptForUser(encrypted, "wrongPassword", userID)
	if err == nil {
		t.Errorf("Decryption with wrong password should fail")
	}

	_, err = DecryptForUser(encrypted, password, 999)
	if err == nil {
		t.Errorf("Decryption with wrong userID should fail")
	}

	_, err = EncryptForUser("", password, userID)
	if err == nil {
		t.Errorf("Encryption of empty plaintext should fail")
	}

	_, err = EncryptForUser(plaintext, "", userID)
	if err == nil {
		t.Errorf("Encryption with empty password should fail")
	}
}
