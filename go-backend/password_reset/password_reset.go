package password_reset

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"
)

const (
	TokenLength      = 32
	TokenExpiration  = 1 * time.Hour
	MaxResetAttempts = 3
	ResetCooldown    = 24 * time.Hour
)

type ResetToken struct {
	Token     string
	UserID    int
	ExpiresAt time.Time
	Used      bool
	CreatedAt time.Time
}

func GenerateResetToken(userID int) (*ResetToken, error) {
	tokenBytes := make([]byte, TokenLength)
	_, err := rand.Read(tokenBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}

	token := base64.URLEncoding.EncodeToString(tokenBytes)

	return &ResetToken{
		Token:     token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(TokenExpiration),
		Used:      false,
		CreatedAt: time.Now(),
	}, nil
}

func ValidateToken(token string, storedToken *ResetToken) error {
	if storedToken.Used {
		return fmt.Errorf("token already used")
	}

	if time.Now().After(storedToken.ExpiresAt) {
		return fmt.Errorf("token expired")
	}

	if storedToken.Token != token {
		return fmt.Errorf("invalid token")
	}

	return nil
}
