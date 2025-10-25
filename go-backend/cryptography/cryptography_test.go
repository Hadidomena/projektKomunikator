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
}
func TestVerifyPassword(t *testing.T) {
	testPassword := "Hello World"
	hashed, _ := HashPassword(testPassword)
	isVerified, _ := VerifyPassword(testPassword, hashed)

	if !isVerified {
		t.Errorf("Password should be verified positively")
	}
}
