package csrf

import (
	"fmt"
	"testing"
	"time"
)

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	if token == "" {
		t.Error("Generated token should not be empty")
	}

	if len(token) < 20 {
		t.Errorf("Token length should be at least 20 characters, got %d", len(token))
	}
}

func TestGenerateToken_Uniqueness(t *testing.T) {
	token1, err := GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate first token: %v", err)
	}

	token2, err := GenerateToken()
	if err != nil {
		t.Fatalf("Failed to generate second token: %v", err)
	}

	if token1 == token2 {
		t.Error("Generated tokens should be unique")
	}
}

func TestNewTokenStore(t *testing.T) {
	store := NewTokenStore()
	if store == nil {
		t.Error("NewTokenStore should not return nil")
	}

	if store.ValidateToken("user123", "any-token") {
		t.Error("New token store should be empty")
	}
}

func TestCreateToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	token, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if token == "" {
		t.Error("Created token should not be empty")
	}

	if !store.ValidateToken(userID, token) {
		t.Error("Created token should be retrievable via validation")
	}
}

func TestValidateToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	token, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if !store.ValidateToken(userID, token) {
		t.Error("Valid token should pass validation")
	}
}

func TestValidateToken_InvalidToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	_, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	invalidToken := "invalid-token-value"
	if store.ValidateToken(userID, invalidToken) {
		t.Error("Invalid token should fail validation")
	}
}

func TestValidateToken_NonExistentUser(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	token, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	if store.ValidateToken("different-user", token) {
		t.Error("Token for different user should fail validation")
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	token, err := store.CreateToken(userID, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	if store.ValidateToken(userID, token) {
		t.Error("Expired token should fail validation")
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := NewTokenStore()

	type created struct {
		userID string
		token  string
	}
	tokens := make(chan created, 10)
	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			userID := fmt.Sprintf("user%d", id)
			token, err := store.CreateToken(userID, DefaultExpiration)
			if err != nil {
				t.Errorf("Failed to create token: %v", err)
			}
			tokens <- created{userID: userID, token: token}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
	close(tokens)

	count := 0
	for c := range tokens {
		count++
		if !store.ValidateToken(c.userID, c.token) {
			t.Errorf("Token for %s should validate", c.userID)
		}
	}
	if count != 10 {
		t.Errorf("Expected 10 tokens, got %d", count)
	}
}

func BenchmarkGenerateToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateToken()
	}
}

func BenchmarkCreateToken(b *testing.B) {
	store := NewTokenStore()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		userID := fmt.Sprintf("user%d", i)
		_, _ = store.CreateToken(userID, DefaultExpiration)
	}
}

func BenchmarkValidateToken(b *testing.B) {
	store := NewTokenStore()
	userID := "benchuser"
	token, _ := store.CreateToken(userID, DefaultExpiration)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = store.ValidateToken(userID, token)
	}
}
