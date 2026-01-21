package validation

import (
	"database/sql"
	"fmt"
	"net/mail"
	"sync"
	"time"
)

// LoginAttempt represents a single login attempt with its timestamp
type LoginAttempt struct {
	Timestamp time.Time
	IP        string
}

// AccountStatus represents the current status of an account regarding login attempts
type AccountStatus struct {
	FailedAttempts []LoginAttempt
	LockedUntil    time.Time
	IsBlocked      bool
	mu             sync.RWMutex
}

// LoginAttemptTracker manages login attempts for all accounts
type LoginAttemptTracker struct {
	accounts map[string]*AccountStatus
	mu       sync.RWMutex
}

// NewLoginAttemptTracker creates a new login attempt tracker
func NewLoginAttemptTracker() *LoginAttemptTracker {
	return &LoginAttemptTracker{
		accounts: make(map[string]*AccountStatus),
	}
}

// RecordFailedAttempt records a failed login attempt and returns whether the account is locked/blocked
// Returns (isLocked bool, lockDuration time.Duration, isBlocked bool, error)
func (t *LoginAttemptTracker) RecordFailedAttempt(email, ip string) (bool, time.Duration, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.accounts[email] == nil {
		t.accounts[email] = &AccountStatus{
			FailedAttempts: make([]LoginAttempt, 0),
		}
	}

	status := t.accounts[email]
	status.mu.Lock()
	defer status.mu.Unlock()

	if status.IsBlocked {
		return true, 0, true, fmt.Errorf("account is permanently blocked")
	}

	status.FailedAttempts = append(status.FailedAttempts, LoginAttempt{
		Timestamp: time.Now(),
		IP:        ip,
	})

	cutoff := time.Now().Add(-10 * time.Minute)
	validAttempts := make([]LoginAttempt, 0)
	for _, attempt := range status.FailedAttempts {
		if attempt.Timestamp.After(cutoff) {
			validAttempts = append(validAttempts, attempt)
		}
	}
	status.FailedAttempts = validAttempts

	attemptCount := len(status.FailedAttempts)

	var lockDuration time.Duration
	var isLocked bool

	switch {
	case attemptCount >= 5:
		status.IsBlocked = true
		return true, 0, true, fmt.Errorf("account permanently blocked after 5 failed attempts")
	case attemptCount >= 3:
		lockDuration = 5 * time.Minute
		status.LockedUntil = time.Now().Add(lockDuration)
		isLocked = true
	case attemptCount >= 1:
		lockDuration = 1 * time.Minute
		status.LockedUntil = time.Now().Add(lockDuration)
		isLocked = true
	}

	return isLocked, lockDuration, false, nil
}

// CheckAccountStatus checks if an account is currently locked or blocked
// Returns (isLocked bool, remainingTime time.Duration, isBlocked bool)
func (t *LoginAttemptTracker) CheckAccountStatus(email string) (bool, time.Duration, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	status := t.accounts[email]
	if status == nil {
		return false, 0, false
	}

	status.mu.RLock()
	defer status.mu.RUnlock()

	if status.IsBlocked {
		return true, 0, true
	}

	if time.Now().Before(status.LockedUntil) {
		return true, time.Until(status.LockedUntil), false
	}

	return false, 0, false
}

func (t *LoginAttemptTracker) ResetAttempts(email string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.accounts[email] != nil {
		status := t.accounts[email]
		status.mu.Lock()
		defer status.mu.Unlock()

		status.FailedAttempts = make([]LoginAttempt, 0)
		status.LockedUntil = time.Time{}
	}
}

// GetAttemptCount returns the current number of failed attempts for an account
func (t *LoginAttemptTracker) GetAttemptCount(email string) int {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.accounts[email] == nil {
		return 0
	}

	status := t.accounts[email]
	status.mu.RLock()
	defer status.mu.RUnlock()

	return len(status.FailedAttempts)
}

// ValidateEmail checks if the email format is valid
func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}

	_, err := mail.ParseAddress(email)
	return err == nil
}

// CheckEmailExists checks if an email already exists in the database
func CheckEmailExists(db *sql.DB, email string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM Users WHERE email = $1)"
	err := db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}
	return exists, nil
}

// GetSanitizedError returns a generic error message to prevent information leakage.
func GetSanitizedError(errorType string) string {
	switch errorType {
	case "login_failed":
		return "Invalid credentials"
	case "registration_failed":
		return "Registration failed. Please check your input and try again"
	case "account_locked":
		return "Access temporarily restricted. Please try again later"
	case "account_blocked":
		return "Account access restricted. Please contact support"
	case "validation_failed":
		return "Invalid input provided"
	default:
		return "An error occurred. Please try again"
	}
}

// ValidationError represents a validation error with limited information
type ValidationError struct {
	Type    string
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// NewValidationError creates a new validation error with sanitized message
func NewValidationError(errorType string) *ValidationError {
	return &ValidationError{
		Type:    errorType,
		Message: GetSanitizedError(errorType),
	}
}
