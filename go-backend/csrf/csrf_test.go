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

	// Token should be base64 URL encoded
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

	if store.Count() != 0 {
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

	if store.Count() != 1 {
		t.Errorf("Store should contain 1 token, got %d", store.Count())
	}
}

func TestValidateToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	token, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Valid token should pass validation
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

	// Invalid token should fail validation
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

	// Token for different user should fail validation
	if store.ValidateToken("different-user", token) {
		t.Error("Token for different user should fail validation")
	}
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	// Create token with very short expiration
	token, err := store.CreateToken(userID, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	// Expired token should fail validation
	if store.ValidateToken(userID, token) {
		t.Error("Expired token should fail validation")
	}
}

func TestRefreshToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	_, err := store.CreateToken(userID, 1*time.Second)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Refresh token with longer expiration
	err = store.RefreshToken(userID, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	// Token should still be valid
	token, exists := store.GetToken(userID)
	if !exists {
		t.Error("Refreshed token should still exist")
	}

	if token == "" {
		t.Error("Refreshed token should not be empty")
	}
}

func TestRefreshToken_NonExistent(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	// Try to refresh non-existent token
	err := store.RefreshToken(userID, DefaultExpiration)
	if err == nil {
		t.Error("Refreshing non-existent token should return error")
	}
}

func TestDeleteToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	_, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Delete token
	store.DeleteToken(userID)

	if store.Count() != 0 {
		t.Error("Store should be empty after deletion")
	}

	// Token should no longer be valid
	_, exists := store.GetToken(userID)
	if exists {
		t.Error("Deleted token should not exist")
	}
}

func TestGetToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	createdToken, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	retrievedToken, exists := store.GetToken(userID)
	if !exists {
		t.Error("Token should exist")
	}

	if retrievedToken != createdToken {
		t.Error("Retrieved token should match created token")
	}
}

func TestGetToken_NonExistent(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	_, exists := store.GetToken(userID)
	if exists {
		t.Error("Non-existent token should not exist")
	}
}

func TestGetToken_Expired(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	_, err := store.CreateToken(userID, 1*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Wait for token to expire
	time.Sleep(10 * time.Millisecond)

	_, exists := store.GetToken(userID)
	if exists {
		t.Error("Expired token should not be returned")
	}
}

func TestValidateAndConsume(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	token, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// First validation should succeed and consume the token
	if !store.ValidateAndConsume(userID, token) {
		t.Error("First validation should succeed")
	}

	// Second validation should fail (token consumed)
	if store.ValidateAndConsume(userID, token) {
		t.Error("Second validation should fail (token consumed)")
	}

	// Token should no longer exist
	if store.Count() != 0 {
		t.Error("Store should be empty after consumption")
	}
}

func TestValidateAndConsume_InvalidToken(t *testing.T) {
	store := NewTokenStore()
	userID := "user123"

	_, err := store.CreateToken(userID, DefaultExpiration)
	if err != nil {
		t.Fatalf("Failed to create token: %v", err)
	}

	// Invalid token should not be consumed
	invalidToken := "invalid-token"
	if store.ValidateAndConsume(userID, invalidToken) {
		t.Error("Invalid token should not validate")
	}

	// Original token should still exist
	if store.Count() != 1 {
		t.Error("Store should still contain the original token")
	}
}

func TestCount(t *testing.T) {
	store := NewTokenStore()

	if store.Count() != 0 {
		t.Error("Initial count should be 0")
	}

	store.CreateToken("user1", DefaultExpiration)
	if store.Count() != 1 {
		t.Error("Count should be 1 after creating one token")
	}

	store.CreateToken("user2", DefaultExpiration)
	if store.Count() != 2 {
		t.Error("Count should be 2 after creating two tokens")
	}

	store.DeleteToken("user1")
	if store.Count() != 1 {
		t.Error("Count should be 1 after deleting one token")
	}
}

func TestConcurrentAccess(t *testing.T) {
	store := NewTokenStore()
	done := make(chan bool)

	// Concurrent writes
	for i := 0; i < 10; i++ {
		go func(id int) {
			userID := fmt.Sprintf("user%d", id)
			_, err := store.CreateToken(userID, DefaultExpiration)
			if err != nil {
				t.Errorf("Failed to create token: %v", err)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	if store.Count() != 10 {
		t.Errorf("Expected 10 tokens, got %d", store.Count())
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
