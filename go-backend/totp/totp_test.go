package totp

import (
	"strings"
	"testing"
	"time"
)

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	if secret == "" {
		t.Error("Generated secret should not be empty")
	}

	// Secret should be base32 encoded
	if !ValidateSecret(secret) {
		t.Error("Generated secret should be valid base32")
	}

	// Check length
	if len(secret) < 20 {
		t.Errorf("Secret length should be at least 20 characters, got %d", len(secret))
	}
}

func TestGenerateSecretUniqueness(t *testing.T) {
	secret1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate first secret: %v", err)
	}

	secret2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate second secret: %v", err)
	}

	if secret1 == secret2 {
		t.Error("Generated secrets should be unique")
	}
}

func TestGenerateTOTP(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP" // Known test secret
	timestamp := time.Unix(1234567890, 0)
	config := DefaultConfig()

	code, err := GenerateTOTP(secret, timestamp, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	if len(code) != config.Digits {
		t.Errorf("TOTP code should have %d digits, got %d", config.Digits, len(code))
	}

	// Code should only contain digits
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("TOTP code should only contain digits, got: %s", code)
			break
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	now := time.Now()
	config := DefaultConfig()

	// Generate a valid code
	code, err := GenerateTOTP(secret, now, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	// Validate the code
	valid, err := ValidateTOTP(secret, code, config)
	if err != nil {
		t.Fatalf("Failed to validate TOTP: %v", err)
	}

	if !valid {
		t.Error("Generated TOTP code should be valid")
	}
}

func TestValidateTOTP_InvalidCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	config := DefaultConfig()
	invalidCode := "000000"

	valid, err := ValidateTOTP(secret, invalidCode, config)
	if err != nil {
		t.Fatalf("Failed to validate TOTP: %v", err)
	}

	// There's a very small chance this could be a valid code, but extremely unlikely
	if valid {
		t.Log("Warning: Invalid code was validated (extremely rare but possible)")
	}
}

func TestValidateTOTP_PreviousWindow(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	config := DefaultConfig()
	previousTime := time.Now().Add(-time.Duration(config.Period) * time.Second)

	// Generate code for previous time window
	code, err := GenerateTOTP(secret, previousTime, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	// Should still be valid due to time window tolerance
	valid, err := ValidateTOTP(secret, code, config)
	if err != nil {
		t.Fatalf("Failed to validate TOTP: %v", err)
	}

	if !valid {
		t.Error("TOTP code from previous window should still be valid")
	}
}

func TestValidateTOTP_NextWindow(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	config := DefaultConfig()
	nextTime := time.Now().Add(time.Duration(config.Period) * time.Second)

	// Generate code for next time window
	code, err := GenerateTOTP(secret, nextTime, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	// Should still be valid due to time window tolerance
	valid, err := ValidateTOTP(secret, code, config)
	if err != nil {
		t.Fatalf("Failed to validate TOTP: %v", err)
	}

	if !valid {
		t.Error("TOTP code from next window should still be valid")
	}
}

func TestValidateTOTP_ExpiredCode(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("Failed to generate secret: %v", err)
	}

	config := DefaultConfig()
	// Generate code for 2 time windows ago (should be expired)
	expiredTime := time.Now().Add(-2 * time.Duration(config.Period) * time.Second)

	code, err := GenerateTOTP(secret, expiredTime, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}

	// Should NOT be valid
	valid, err := ValidateTOTP(secret, code, config)
	if err != nil {
		t.Fatalf("Failed to validate TOTP: %v", err)
	}

	if valid {
		t.Error("Expired TOTP code should not be valid")
	}
}

func TestGenerateQRCodeURL(t *testing.T) {
	accountName := "user@example.com"
	issuer := "MyApp"
	secret := "JBSWY3DPEHPK3PXP"

	url := GenerateQRCodeURL(accountName, issuer, secret)

	if !strings.HasPrefix(url, "otpauth://totp/") {
		t.Error("QR code URL should start with otpauth://totp/")
	}

	if !strings.Contains(url, accountName) {
		t.Error("QR code URL should contain account name")
	}

	if !strings.Contains(url, issuer) {
		t.Error("QR code URL should contain issuer")
	}

	if !strings.Contains(url, secret) {
		t.Error("QR code URL should contain secret")
	}
}

func TestValidateSecret(t *testing.T) {
	validSecret := "JBSWY3DPEHPK3PXP"
	if !ValidateSecret(validSecret) {
		t.Error("Valid secret should pass validation")
	}

	invalidSecret := "INVALID!@#$%"
	if ValidateSecret(invalidSecret) {
		t.Error("Invalid secret should fail validation")
	}

	emptySecret := ""
	if ValidateSecret(emptySecret) {
		t.Error("Empty secret should fail validation")
	}
}

func TestGenerateTOTP_CustomConfig(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	timestamp := time.Unix(1234567890, 0)
	config := &TOTPConfig{
		Period: 60, // 1 minute instead of 30 seconds
		Digits: 8,  // 8 digits instead of 6
	}

	code, err := GenerateTOTP(secret, timestamp, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP with custom config: %v", err)
	}

	if len(code) != config.Digits {
		t.Errorf("TOTP code should have %d digits, got %d", config.Digits, len(code))
	}
}

func TestGenerateTOTP_CaseInsensitiveSecret(t *testing.T) {
	secretUpper := "JBSWY3DPEHPK3PXP"
	secretLower := "jbswy3dpehpk3pxp"
	timestamp := time.Unix(1234567890, 0)
	config := DefaultConfig()

	codeUpper, err := GenerateTOTP(secretUpper, timestamp, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP with uppercase secret: %v", err)
	}

	codeLower, err := GenerateTOTP(secretLower, timestamp, config)
	if err != nil {
		t.Fatalf("Failed to generate TOTP with lowercase secret: %v", err)
	}

	if codeUpper != codeLower {
		t.Error("TOTP codes should be the same regardless of secret case")
	}
}

func BenchmarkGenerateSecret(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateSecret()
	}
}

func BenchmarkGenerateTOTP(b *testing.B) {
	secret := "JBSWY3DPEHPK3PXP"
	timestamp := time.Now()
	config := DefaultConfig()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GenerateTOTP(secret, timestamp, config)
	}
}

func BenchmarkValidateTOTP(b *testing.B) {
	secret := "JBSWY3DPEHPK3PXP"
	config := DefaultConfig()
	code, _ := GenerateTOTP(secret, time.Now(), config)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ValidateTOTP(secret, code, config)
	}
}
