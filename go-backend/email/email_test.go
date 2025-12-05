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
