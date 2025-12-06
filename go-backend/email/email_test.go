package email

import (
	"errors"
	"testing"

	"github.com/jordan-wright/email"
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

func TestSendEmail_UsesSendFunc(t *testing.T) {
	orig := sendFunc
	defer func() { sendFunc = orig }()

	var got *email.Email
	// mock sendFunc captures the email and returns nil or error
	sendFunc = func(e *email.Email) error {
		got = e
		return nil
	}

	recips := []string{"alice@example.com"}
	body := "hello unit test"
	if err := SendEmail(recips, body); err != nil {
		t.Fatalf("SendEmail returned error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected sendFunc to be called")
	}
	if got.Subject != "Test" {
		t.Fatalf("unexpected subject: %q", got.Subject)
	}
	if len(got.To) != 1 || got.To[0] != recips[0] {
		t.Fatalf("unexpected recipients: %#v", got.To)
	}
	if string(got.Text) != body {
		t.Fatalf("unexpected body: %q", string(got.Text))
	}

	// test error path
	sendFunc = func(e *email.Email) error { return errors.New("smtp fail") }
	if err := SendEmail(recips, body); err == nil {
		t.Fatalf("expected error when sendFunc fails")
	}
}
