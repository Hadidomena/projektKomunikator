package honeypot

import (
	"testing"
)

func TestCheckHoneypot(t *testing.T) {
	tests := []struct {
		value string
		isBot bool
	}{
		{"", false},
		{"http://spam.com", true},
		{"any value", true},
	}

	for _, test := range tests {
		result := CheckHoneypot(test.value)
		if result != test.isBot {
			t.Errorf("CheckHoneypot(%q) = %v, expected %v", test.value, result, test.isBot)
		}
	}
}

func TestHoneypotFieldName(t *testing.T) {
	if HoneypotFieldName == "" {
		t.Error("Honeypot field name should not be empty")
	}

	if HoneypotFieldName == "email" || HoneypotFieldName == "password" {
		t.Error("Honeypot field name should not match common form fields")
	}
}
