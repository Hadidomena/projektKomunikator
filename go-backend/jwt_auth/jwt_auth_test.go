package jwt_auth

import (
	"os"
	"testing"
)

func TestInitJWT(t *testing.T) {
	// Save original env variable
	originalSecret := os.Getenv("JWT_SECRET")
	defer os.Setenv("JWT_SECRET", originalSecret)

	tests := []struct {
		name        string
		secret      string
		expectError bool
	}{
		{
			name:        "Valid secret",
			secret:      "this-is-a-very-secure-secret-key-for-testing-purposes",
			expectError: false,
		},
		{
			name:        "Too short secret",
			secret:      "short",
			expectError: true,
		},
		{
			name:        "Empty secret returns error",
			secret:      "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("JWT_SECRET", tt.secret)
			jwtSecret = nil // Reset

			err := InitJWT()

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

func TestGenerateToken(t *testing.T) {
	// Initialize JWT with test secret
	os.Setenv("JWT_SECRET", "test-secret-key-for-unit-testing-purposes-123")
	err := InitJWT()
	if err != nil {
		t.Fatalf("Failed to initialize JWT: %v", err)
	}

	userID := 123
	email := "test@example.com"

	token, err := GenerateToken(userID, email)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Generated token is empty")
	}

	// Token should be a valid JWT format (header.payload.signature)
	if len(token) < 50 {
		t.Error("Generated token seems too short")
	}
}

func TestValidateToken(t *testing.T) {
	// Initialize JWT with test secret
	os.Setenv("JWT_SECRET", "test-secret-key-for-unit-testing-purposes-123")
	err := InitJWT()
	if err != nil {
		t.Fatalf("Failed to initialize JWT: %v", err)
	}

	userID := 456
	email := "validate@example.com"

	// Generate a valid token
	token, err := GenerateToken(userID, email)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	// Validate the token
	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	if claims.UserID != userID {
		t.Errorf("Expected user ID %d, got %d", userID, claims.UserID)
	}

	if claims.Email != email {
		t.Errorf("Expected email %s, got %s", email, claims.Email)
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	// Initialize JWT
	os.Setenv("JWT_SECRET", "test-secret-key-for-unit-testing-purposes-123")
	err := InitJWT()
	if err != nil {
		t.Fatalf("Failed to initialize JWT: %v", err)
	}

	invalidTokens := []string{
		"invalid.token.here",
		"",
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.invalid",
	}

	for _, invalidToken := range invalidTokens {
		t.Run(invalidToken, func(t *testing.T) {
			_, err := ValidateToken(invalidToken)
			if err == nil {
				t.Error("Expected error for invalid token but got none")
			}
		})
	}
}

func TestGenerateToken_UninitializedJWT(t *testing.T) {
	// Reset JWT secret
	jwtSecret = nil

	_, err := GenerateToken(123, "test@example.com")
	if err == nil {
		t.Error("Expected error when JWT is not initialized")
	}
}

func TestValidateToken_UninitializedJWT(t *testing.T) {
	// Reset JWT secret
	jwtSecret = nil

	_, err := ValidateToken("some.token.here")
	if err == nil {
		t.Error("Expected error when JWT is not initialized")
	}
}

func TestTokenClaims(t *testing.T) {
	// Initialize JWT
	os.Setenv("JWT_SECRET", "test-secret-key-for-unit-testing-purposes-123")
	err := InitJWT()
	if err != nil {
		t.Fatalf("Failed to initialize JWT: %v", err)
	}

	userID := 111
	email := "claims@example.com"

	token, err := GenerateToken(userID, email)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	claims, err := ValidateToken(token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Check all claims
	if claims.UserID != userID {
		t.Errorf("UserID mismatch: expected %d, got %d", userID, claims.UserID)
	}

	if claims.Email != email {
		t.Errorf("Email mismatch: expected %s, got %s", email, claims.Email)
	}

	if claims.Issuer != "projektKomunikator" {
		t.Errorf("Issuer mismatch: expected 'projektKomunikator', got '%s'", claims.Issuer)
	}

	if claims.ExpiresAt == nil {
		t.Error("ExpiresAt should not be nil")
	}

	if claims.IssuedAt == nil {
		t.Error("IssuedAt should not be nil")
	}

	if claims.NotBefore == nil {
		t.Error("NotBefore should not be nil")
	}
}
