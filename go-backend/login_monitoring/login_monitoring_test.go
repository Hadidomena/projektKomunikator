package login_monitoring

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateDeviceFingerprint(t *testing.T) {
	ip := "192.168.1.1"
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

	fp1 := GenerateDeviceFingerprint(ip, ua)
	fp2 := GenerateDeviceFingerprint(ip, ua)

	if fp1 != fp2 {
		t.Error("Same input should generate same fingerprint")
	}

	if len(fp1) != 64 {
		t.Errorf("Fingerprint should be 64 characters (SHA256 hex), got %d", len(fp1))
	}

	// Check if fingerprint is valid hex
	for _, c := range fp1 {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("Fingerprint contains invalid hex character: %c", c)
		}
	}
}

func TestGenerateDeviceFingerprint_Different(t *testing.T) {
	fp1 := GenerateDeviceFingerprint("192.168.1.1", "Mozilla/5.0")
	fp2 := GenerateDeviceFingerprint("192.168.1.2", "Mozilla/5.0")
	fp3 := GenerateDeviceFingerprint("192.168.1.1", "Chrome/91.0")

	if fp1 == fp2 {
		t.Error("Different IPs should generate different fingerprints")
	}

	if fp1 == fp3 {
		t.Error("Different user agents should generate different fingerprints")
	}
}

func TestNormalizeUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"Mozilla user agent", "Mozilla/5.0 (Windows NT 10.0)", "mozilla/5.0"},
		{"Chrome user agent", "Chrome/91.0.4472.124", "chrome/91.0.4472.124"},
		{"Empty user agent", "", ""},
		{"Single word", "CustomBot", "custombot"},
		{"Multiple spaces", "Mozilla   5.0", "mozilla"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := normalizeUserAgent(test.input)
			if result != test.expected {
				t.Errorf("normalizeUserAgent(%q) = %q, expected %q", test.input, result, test.expected)
			}
		})
	}
}

func TestLoginAttemptStructure(t *testing.T) {
	attempt := LoginAttempt{
		UserID:            1,
		IPAddress:         "192.168.1.1",
		UserAgent:         "Mozilla/5.0",
		DeviceFingerprint: "abc123",
		Success:           true,
		NewDevice:         false,
		LoginTime:         time.Now(),
		Country:           "US",
		City:              "New York",
	}

	if attempt.UserID != 1 {
		t.Errorf("UserID should be 1, got %d", attempt.UserID)
	}
	if attempt.IPAddress != "192.168.1.1" {
		t.Errorf("IPAddress should be 192.168.1.1, got %s", attempt.IPAddress)
	}
	if !attempt.Success {
		t.Error("Success should be true")
	}
	if attempt.NewDevice {
		t.Error("NewDevice should be false")
	}
}

func TestGenerateDeviceFingerprint_EmptyInputs(t *testing.T) {
	fp1 := GenerateDeviceFingerprint("", "")
	fp2 := GenerateDeviceFingerprint("", "")

	if fp1 != fp2 {
		t.Error("Same empty inputs should generate same fingerprint")
	}

	if len(fp1) != 64 {
		t.Errorf("Fingerprint should be 64 characters even with empty inputs, got %d", len(fp1))
	}
}
