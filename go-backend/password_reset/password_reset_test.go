package password_reset

import (
	"testing"
	"time"
)

func TestGenerateResetToken(t *testing.T) {
	userID := 123
	token, err := GenerateResetToken(userID)

	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token.UserID != userID {
		t.Errorf("Expected user ID %d, got %d", userID, token.UserID)
	}

	if token.Token == "" {
		t.Error("Token should not be empty")
	}

	if len(token.Token) < 40 {
		t.Errorf("Token too short: %d characters", len(token.Token))
	}

	if token.Used {
		t.Error("New token should not be marked as used")
	}

	expectedExpiry := time.Now().Add(TokenExpiration)
	timeDiff := token.ExpiresAt.Sub(expectedExpiry).Abs()
	if timeDiff > time.Second {
		t.Errorf("Token expiry time incorrect, diff: %v", timeDiff)
	}
}

func TestGenerateResetToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool)

	for i := 0; i < 100; i++ {
		token, err := GenerateResetToken(1)
		if err != nil {
			t.Fatalf("Failed to generate token: %v", err)
		}

		if tokens[token.Token] {
			t.Error("Duplicate token generated")
		}
		tokens[token.Token] = true
	}
}

func TestValidateToken_Valid(t *testing.T) {
	token, _ := GenerateResetToken(1)

	err := ValidateToken(token.Token, token)
	if err != nil {
		t.Errorf("Valid token should pass validation: %v", err)
	}
}

func TestValidateToken_Used(t *testing.T) {
	token, _ := GenerateResetToken(1)
	token.Used = true

	err := ValidateToken(token.Token, token)
	if err == nil {
		t.Error("Used token should fail validation")
	}
}

func TestValidateToken_Expired(t *testing.T) {
	token, _ := GenerateResetToken(1)
	token.ExpiresAt = time.Now().Add(-1 * time.Hour)

	err := ValidateToken(token.Token, token)
	if err == nil {
		t.Error("Expired token should fail validation")
	}
}

func TestHashToken(t *testing.T) {
	token := "test-reset-token-123"
	hash1 := HashToken(token)
	hash2 := HashToken(token)

	if hash1 == "" {
		t.Error("Hash should not be empty")
	}

	if hash1 != hash2 {
		t.Error("Hash should be deterministic")
	}

	if hash1 == token {
		t.Error("Hash should not equal the original token")
	}

	hash3 := HashToken("different-token")
	if hash1 == hash3 {
		t.Error("Different tokens should produce different hashes")
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	token, _ := GenerateResetToken(1)

	err := ValidateToken("wrong-token", token)
	if err == nil {
		t.Error("Invalid token should fail validation")
	}
}
