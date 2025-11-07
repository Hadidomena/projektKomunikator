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
