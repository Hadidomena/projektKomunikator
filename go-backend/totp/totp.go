package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"math"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultPeriod = 30
	DefaultDigits = 6
	SecretLength  = 20
)

type TOTPConfig struct {
	Period int // Time period in seconds
	Digits int
}

func DefaultConfig() *TOTPConfig {
	return &TOTPConfig{
		Period: DefaultPeriod,
		Digits: DefaultDigits,
	}
}

func GenerateSecret() (string, error) {
	secret := make([]byte, SecretLength)
	_, err := rand.Read(secret)
	if err != nil {
		return "", fmt.Errorf("failed to generate random secret: %w", err)
	}

	encoded := base32.StdEncoding.EncodeToString(secret)
	encoded = strings.TrimRight(encoded, "=")

	return encoded, nil
}

func GenerateTOTP(secret string, timestamp time.Time, config *TOTPConfig) (string, error) {
	if config == nil {
		config = DefaultConfig()
	}

	secret = strings.ToUpper(secret)
	if m := len(secret) % 8; m != 0 {
		secret += strings.Repeat("=", 8-m)
	}

	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}

	counter := uint64(timestamp.Unix()) / uint64(config.Period)
	return generateHOTP(key, counter, config.Digits), nil
}

// It checks the current time window and adjacent windows to account for clock skew
func ValidateTOTP(secret string, code string, config *TOTPConfig) (bool, error) {
	if config == nil {
		config = DefaultConfig()
	}

	now := time.Now()

	currentCode, err := GenerateTOTP(secret, now, config)
	if err != nil {
		return false, err
	}

	if code == currentCode {
		return true, nil
	}

	previousTime := now.Add(-time.Duration(config.Period) * time.Second)
	previousCode, err := GenerateTOTP(secret, previousTime, config)
	if err != nil {
		return false, err
	}

	if code == previousCode {
		return true, nil
	}

	nextTime := now.Add(time.Duration(config.Period) * time.Second)
	nextCode, err := GenerateTOTP(secret, nextTime, config)
	if err != nil {
		return false, err
	}

	if code == nextCode {
		return true, nil
	}

	return false, nil
}

func generateHOTP(key []byte, counter uint64, digits int) string {
	counterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(counterBytes, counter)

	h := hmac.New(sha1.New, key)
	h.Write(counterBytes)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	truncated := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	code := truncated % uint32(math.Pow10(digits))

	format := fmt.Sprintf("%%0%dd", digits)
	return fmt.Sprintf(format, code)
}

func GenerateQRCodeURL(accountName, issuer, secret string) string {
	label := url.PathEscape(issuer + ":" + accountName)
	return fmt.Sprintf(
		"otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		label,
		url.QueryEscape(secret),
		url.QueryEscape(issuer),
	)
}
