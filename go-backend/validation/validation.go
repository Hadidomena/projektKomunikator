package validation

import (
	"database/sql"
	"fmt"
	"net/mail"
	"sync"
	"time"
)

type LoginAttempt struct {
	Timestamp time.Time
	IP        string
}

type AccountStatus struct {
	FailedAttempts []LoginAttempt
	LockedUntil    time.Time
	IsBlocked      bool
	mu             sync.RWMutex
}

type LoginAttemptTracker struct {
	accounts map[string]*AccountStatus
	mu       sync.RWMutex
	db       *sql.DB
}

func NewLoginAttemptTracker() *LoginAttemptTracker {
	return &LoginAttemptTracker{
		accounts: make(map[string]*AccountStatus),
	}
}

func (t *LoginAttemptTracker) SetDB(db *sql.DB) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.db = db
}

func (t *LoginAttemptTracker) RecordFailedAttempt(email, ip string) (bool, time.Duration, bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.db != nil {
		return recordFailedAttemptDB(t.db, email)
	}

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

func (t *LoginAttemptTracker) CheckAccountStatus(email string) (bool, time.Duration, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.db != nil {
		return checkAccountStatusDB(t.db, email)
	}

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

	if t.db != nil {
		resetAttemptsDB(t.db, email)
		return
	}

	if t.accounts[email] != nil {
		status := t.accounts[email]
		status.mu.Lock()
		defer status.mu.Unlock()

		status.FailedAttempts = make([]LoginAttempt, 0)
		status.LockedUntil = time.Time{}
	}
}

func checkAccountStatusDB(db *sql.DB, email string) (bool, time.Duration, bool) {
	var isBlocked bool
	var lockedUntil sql.NullTime
	err := db.QueryRow(
		"SELECT is_blocked, locked_until FROM Users WHERE email = $1",
		email,
	).Scan(&isBlocked, &lockedUntil)
	if err != nil {
		return false, 0, false
	}

	if isBlocked {
		return true, 0, true
	}

	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return true, time.Until(lockedUntil.Time), false
	}

	return false, 0, false
}

func recordFailedAttemptDB(db *sql.DB, email string) (bool, time.Duration, bool, error) {
	var attempts int
	var isBlocked bool
	var lockedUntil sql.NullTime
	err := db.QueryRow(
		"SELECT failed_login_attempts, is_blocked, locked_until FROM Users WHERE email = $1",
		email,
	).Scan(&attempts, &isBlocked, &lockedUntil)
	if err != nil {
		return false, 0, false, err
	}

	if isBlocked {
		return true, 0, true, fmt.Errorf("account is permanently blocked")
	}

	attempts++
	now := time.Now()
	var lockDuration time.Duration

	switch {
	case attempts >= 5:
		db.Exec(
			"UPDATE Users SET failed_login_attempts = $1, is_blocked = TRUE, locked_until = NULL WHERE email = $2",
			attempts, email,
		)
		return true, 0, true, fmt.Errorf("account permanently blocked after 5 failed attempts")
	case attempts >= 3:
		lockDuration = 5 * time.Minute
	default:
		lockDuration = 1 * time.Minute
	}

	_, err = db.Exec(
		"UPDATE Users SET failed_login_attempts = $1, locked_until = $2 WHERE email = $3",
		attempts, now.Add(lockDuration), email,
	)
	return true, lockDuration, false, err
}

func resetAttemptsDB(db *sql.DB, email string) {
	db.Exec("UPDATE Users SET failed_login_attempts = 0, locked_until = NULL WHERE email = $1", email)
}

func ValidateEmail(email string) bool {
	if email == "" {
		return false
	}

	_, err := mail.ParseAddress(email)
	return err == nil
}

func CheckEmailExists(db *sql.DB, email string) (bool, error) {
	var exists bool
	query := "SELECT EXISTS(SELECT 1 FROM Users WHERE email = $1)"
	err := db.QueryRow(query, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check email existence: %w", err)
	}
	return exists, nil
}

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
