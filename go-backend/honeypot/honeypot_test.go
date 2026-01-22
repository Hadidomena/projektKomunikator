package honeypot

import (
	"testing"
	"time"
)

func TestCheckHoneypot(t *testing.T) {
	tests := []struct {
		name  string
		value string
		isBot bool
	}{
		{"empty value is not a bot", "", false},
		{"url value is a bot", "http://spam.com", true},
		{"any text value is a bot", "any value", true},
		{"space value is a bot", " ", true},
		{"https url is a bot", "https://malicious.com", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := CheckHoneypot(test.value)
			if result != test.isBot {
				t.Errorf("CheckHoneypot(%q) = %v, expected %v", test.value, result, test.isBot)
			}
		})
	}
}

func TestHoneypotFieldName(t *testing.T) {
	if HoneypotFieldName == "" {
		t.Error("Honeypot field name should not be empty")
	}

	if HoneypotFieldName == "email" || HoneypotFieldName == "password" {
		t.Error("Honeypot field name should not match common form fields")
	}

	expectedFieldName := "website"
	if HoneypotFieldName != expectedFieldName {
		t.Errorf("HoneypotFieldName = %q, expected %q", HoneypotFieldName, expectedFieldName)
	}
}

func TestHoneypotAttemptStructure(t *testing.T) {
	attempt := &HoneypotAttempt{
		IPAddress:     "192.168.1.1",
		UserAgent:     "Mozilla/5.0",
		HoneypotField: "website",
		HoneypotValue: "http://spam.com",
		SubmittedData: map[string]interface{}{
			"username": "testuser",
			"email":    "test@example.com",
		},
		AttemptTime: time.Now(),
		Blocked:     true,
	}

	if attempt.IPAddress == "" {
		t.Error("IPAddress should not be empty")
	}
	if attempt.HoneypotField != "website" {
		t.Error("HoneypotField should be 'website'")
	}
	if !attempt.Blocked {
		t.Error("Blocked should be true")
	}
	if len(attempt.SubmittedData) != 2 {
		t.Errorf("SubmittedData should have 2 entries, got %d", len(attempt.SubmittedData))
	}
}
