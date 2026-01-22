package login_monitoring

import (
	"testing"
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
		input    string
		expected string
	}{
		{"Mozilla/5.0 (Windows NT 10.0)", "mozilla/5.0"},
		{"Chrome/91.0.4472.124", "chrome/91.0.4472.124"},
		{"", ""},
	}

	for _, test := range tests {
		result := normalizeUserAgent(test.input)
		if result != test.expected {
			t.Errorf("normalizeUserAgent(%q) = %q, expected %q", test.input, result, test.expected)
		}
	}
}
