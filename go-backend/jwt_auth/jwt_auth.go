package jwt_auth

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	jwtSecret       []byte
	tokenExpiration = 1 * time.Hour
)

// Claims represents the JWT claims
type Claims struct {
	UserID int    `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

// InitJWT initializes the JWT secret from environment variable
func InitJWT() error {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return errors.New("JWT_SECRET environment variable not set")
	}

	if len(secret) < 32 {
		return errors.New("JWT_SECRET must be at least 32 characters long")
	}

	jwtSecret = []byte(secret)
	return nil
}

// GenerateToken generates a new JWT token for a user
func GenerateToken(userID int, email string) (string, error) {
	if len(jwtSecret) == 0 {
		return "", errors.New("JWT not initialized")
	}

	now := time.Now()
	claims := Claims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiration)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "projektKomunikator",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the claims
func ValidateToken(tokenString string) (*Claims, error) {
	if len(jwtSecret) == 0 {
		return nil, errors.New("JWT not initialized")
	}

	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}

// RefreshToken generates a new token if the current one is still valid but close to expiration
func RefreshToken(tokenString string) (string, error) {
	claims, err := ValidateToken(tokenString)
	if err != nil {
		return "", err
	}

	if time.Until(claims.ExpiresAt.Time) > time.Hour {
		return "", errors.New("token does not need refresh yet")
	}

	return GenerateToken(claims.UserID, claims.Email)
}

// GetTokenExpiration returns the token expiration duration
func GetTokenExpiration() time.Duration {
	return tokenExpiration
}

// SetTokenExpiration sets the token expiration duration (for testing purposes)
func SetTokenExpiration(duration time.Duration) {
	tokenExpiration = duration
}
