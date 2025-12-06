package email

import (
	"testing"
)

func TestEmailVerification(t *testing.T) {
	notEmail := "somestring"
	email := "carlos@gmail.com"
	if VerifyEmail(notEmail) {
		t.Errorf("Unreal Email passed verification")
	}
	if !VerifyEmail(email) {
		t.Errorf("Real email did not pass")
	}
}

func TestCodeGeneration(t *testing.T) {
	expectedLen := 12
	code, err := generateVerificationCode()
	if err != nil {
		t.Fatalf("Error during Code generation: %v", err)
	}
	if len(code) != expectedLen {
		t.Errorf("Code should be of length %d", expectedLen)
	}

	secondCode, err := generateVerificationCode()
	if err != nil {
		t.Fatalf("Error during Code generation: %v", err)
	}
	if code == secondCode {
		t.Errorf("First code %s, and second code %s should not be the same", code, secondCode)
	}
}
