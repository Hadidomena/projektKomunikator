package email

import (
	"errors"
	"testing"

	"github.com/jordan-wright/email"
)

func TestSendEmail_UsesSendFunc(t *testing.T) {
	orig := sendFunc
	defer func() { sendFunc = orig }()

	var got *email.Email
	sendFunc = func(e *email.Email) error {
		got = e
		return nil
	}

	recips := []string{"alice@example.com"}
	body := "hello unit test"
	if err := SendEmail("Test Subject", recips, body); err != nil {
		t.Fatalf("SendEmail returned error: %v", err)
	}
	if got == nil {
		t.Fatalf("expected sendFunc to be called")
	}
	if got.Subject != "Test Subject" {
		t.Fatalf("unexpected subject: %q", got.Subject)
	}
	if len(got.To) != 1 || got.To[0] != recips[0] {
		t.Fatalf("unexpected recipients: %#v", got.To)
	}
	if string(got.Text) != body {
		t.Fatalf("unexpected body: %q", string(got.Text))
	}

	sendFunc = func(e *email.Email) error { return errors.New("smtp fail") }
	if err := SendEmail("Test Subject", recips, body); err == nil {
		t.Fatalf("expected error when sendFunc fails")
	}
}
