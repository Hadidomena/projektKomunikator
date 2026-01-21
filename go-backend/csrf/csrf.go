package csrf

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

const (
	TokenLength       = 32
	DefaultExpiration = 1 * time.Hour
	CleanupInterval   = 5 * time.Minute
)

// Token represents a CSRF token with its expiration time
type Token struct {
	Value      string
	Expiration time.Time
}

// TokenStore manages CSRF tokens in memory
type TokenStore struct {
	tokens map[string]*Token // key: session ID or user ID
	mu     sync.RWMutex
}

// NewTokenStore creates a new CSRF token store
func NewTokenStore() *TokenStore {
	store := &TokenStore{
		tokens: make(map[string]*Token),
	}

	go store.cleanupExpiredTokens()

	return store
}

// GenerateToken generates a new cryptographically secure CSRF token
func GenerateToken() (string, error) {
	bytes := make([]byte, TokenLength)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random token: %w", err)
	}

	return base64.URLEncoding.EncodeToString(bytes), nil
}

// CreateToken creates a new CSRF token for a user/session and stores it
func (ts *TokenStore) CreateToken(userID string, expiration time.Duration) (string, error) {
	if expiration == 0 {
		expiration = DefaultExpiration
	}

	token, err := GenerateToken()
	if err != nil {
		return "", err
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.tokens[userID] = &Token{
		Value:      token,
		Expiration: time.Now().Add(expiration),
	}

	return token, nil
}

// ValidateToken validates a CSRF token for a user/session
func (ts *TokenStore) ValidateToken(userID string, providedToken string) bool {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	storedToken, exists := ts.tokens[userID]
	if !exists {
		return false
	}

	if time.Now().After(storedToken.Expiration) {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(storedToken.Value), []byte(providedToken)) == 1
}

// RefreshToken refreshes the expiration time of an existing token
func (ts *TokenStore) RefreshToken(userID string, expiration time.Duration) error {
	if expiration == 0 {
		expiration = DefaultExpiration
	}

	ts.mu.Lock()
	defer ts.mu.Unlock()

	token, exists := ts.tokens[userID]
	if !exists {
		return fmt.Errorf("no token found for user: %s", userID)
	}

	token.Expiration = time.Now().Add(expiration)
	return nil
}

// DeleteToken removes a token from the store
func (ts *TokenStore) DeleteToken(userID string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	delete(ts.tokens, userID)
}

// GetToken retrieves the current token for a user (if it exists and hasn't expired)
func (ts *TokenStore) GetToken(userID string) (string, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	token, exists := ts.tokens[userID]
	if !exists {
		return "", false
	}

	if time.Now().After(token.Expiration) {
		return "", false
	}

	return token.Value, true
}

// cleanupExpiredTokens periodically removes expired tokens
func (ts *TokenStore) cleanupExpiredTokens() {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		ts.mu.Lock()
		now := time.Now()
		for userID, token := range ts.tokens {
			if now.After(token.Expiration) {
				delete(ts.tokens, userID)
			}
		}
		ts.mu.Unlock()
	}
}

// Count returns the number of tokens currently stored
func (ts *TokenStore) Count() int {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	return len(ts.tokens)
}

// ValidateAndConsume validates a token and removes it (for one-time use tokens)
func (ts *TokenStore) ValidateAndConsume(userID string, providedToken string) bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	storedToken, exists := ts.tokens[userID]
	if !exists {
		return false
	}

	if time.Now().After(storedToken.Expiration) {
		delete(ts.tokens, userID)
		return false
	}

	valid := subtle.ConstantTimeCompare([]byte(storedToken.Value), []byte(providedToken)) == 1

	if valid {
		delete(ts.tokens, userID)
	}

	return valid
}
