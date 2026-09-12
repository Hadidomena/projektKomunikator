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
	dbMu     sync.RWMutex
	db       *sql.DB
}

func NewLoginAttemptTracker() *LoginAttemptTracker {
	return &LoginAttemptTracker{
		accounts: make(map[string]*AccountStatus),
	}
}

func (t *LoginAttemptTracker) SetDB(db *sql.DB) {
	t.dbMu.Lock()
	defer t.dbMu.Unlock()
	t.db = db
}

func (t *LoginAttemptTracker) getDB() *sql.DB {
	t.dbMu.RLock()
	defer t.dbMu.RUnlock()
	return t.db
}

func (t *LoginAttemptTracker) RecordFailedAttempt(email, ip string) (bool, time.Duration, bool, error) {
	if db := t.getDB(); db != nil {
		return recordFailedAttemptDB(db, email)
	}

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

func (t *LoginAttemptTracker) CheckAccountStatus(email string) (bool, time.Duration, bool, error) {
	if db := t.getDB(); db != nil {
		return checkAccountStatusDB(db, email)
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	status := t.accounts[email]
	if status == nil {
		return false, 0, false, nil
	}

	status.mu.RLock()
	defer status.mu.RUnlock()

	if status.IsBlocked {
		return true, 0, true, nil
	}

	if time.Now().Before(status.LockedUntil) {
		return true, time.Until(status.LockedUntil), false, nil
	}

	return false, 0, false, nil
}

func (t *LoginAttemptTracker) ResetAttempts(email string) error {
	if db := t.getDB(); db != nil {
		return resetAttemptsDB(db, email)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if t.accounts[email] != nil {
		status := t.accounts[email]
		status.mu.Lock()
		defer status.mu.Unlock()

		status.FailedAttempts = make([]LoginAttempt, 0)
		status.LockedUntil = time.Time{}
	}

	return nil
}

func checkAccountStatusDB(db *sql.DB, email string) (bool, time.Duration, bool, error) {
	var isBlocked bool
	var lockedUntil sql.NullTime
	err := db.QueryRow(
		"SELECT is_blocked, locked_until FROM Users WHERE email = $1",
		email,
	).Scan(&isBlocked, &lockedUntil)
	if err != nil {
		if err == sql.ErrNoRows {
			return false, 0, false, nil
		}
		return false, 0, false, err
	}

	if isBlocked {
		return true, 0, true, nil
	}

	if lockedUntil.Valid && time.Now().Before(lockedUntil.Time) {
		return true, time.Until(lockedUntil.Time), false, nil
	}

	return false, 0, false, nil
}

func recordFailedAttemptDB(db *sql.DB, email string) (bool, time.Duration, bool, error) {
	now := time.Now()

	var attempts int
	var isBlocked bool
	err := db.QueryRow(`
		UPDATE Users
		SET failed_login_attempts = CASE
				WHEN locked_until IS NULL OR locked_until <= $1 THEN 1
				ELSE failed_login_attempts + 1
			END,
			locked_until = CASE
				WHEN locked_until IS NULL OR locked_until <= $1 THEN $2
				WHEN failed_login_attempts + 1 >= 5 THEN NULL
				WHEN failed_login_attempts + 1 >= 3 THEN $3
				ELSE $2
			END,
			is_blocked = CASE
				WHEN NOT (locked_until IS NULL OR locked_until <= $1) AND failed_login_attempts + 1 >= 5 THEN TRUE
				ELSE is_blocked
			END
		WHERE email = $4 AND is_blocked = FALSE
		RETURNING failed_login_attempts, is_blocked`,
		now, now.Add(1*time.Minute), now.Add(5*time.Minute), email,
	).Scan(&attempts, &isBlocked)
	if err != nil {
		if err == sql.ErrNoRows {
			return true, 0, true, fmt.Errorf("account is permanently blocked or does not exist")
		}
		return false, 0, false, err
	}

	if isBlocked {
		return true, 0, true, fmt.Errorf("account permanently blocked after 5 failed attempts")
	}

	var lockDuration time.Duration
	if attempts >= 3 {
		lockDuration = 5 * time.Minute
	} else {
		lockDuration = 1 * time.Minute
	}

	return true, lockDuration, false, nil
}

func resetAttemptsDB(db *sql.DB, email string) error {
	_, err := db.Exec("UPDATE Users SET failed_login_attempts = 0, locked_until = NULL WHERE email = $1", email)
	return err
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
