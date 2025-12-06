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

func TestIntGenerator(t *testing.T) {
	validMax, invalidMax := int64(100), int64(-10)
	i, err := secureInt(validMax)
	if err != nil {
		t.Fatalf("Error during Int generation: %v", err)
	}
	if i < 0 || i > validMax {
		t.Errorf("reached invalid i from secureInt: %d", i)
	}
	i, err = secureInt(invalidMax)
	if err != nil {
		t.Fatalf("Error during Int generation: %v", err)
	}
	if i != 0 {
		t.Errorf("Invalid Max returned something different to 0: %d", i)
	}
}
