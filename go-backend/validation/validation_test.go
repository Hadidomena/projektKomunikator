package validation

import (
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestValidateEmail tests email validation
func TestValidateEmail(t *testing.T) {
	tests := []struct {
		name     string
		email    string
		expected bool
	}{
		{"Valid email", "user@example.com", true},
		{"Valid email with subdomain", "user@mail.example.com", true},
		{"Valid email with plus", "user+tag@example.com", true},
		{"Valid email with dots", "first.last@example.com", true},
		{"Empty email", "", false},
		{"Missing @", "userexample.com", false},
		{"Missing domain", "user@", false},
		{"Missing local part", "@example.com", false},
		{"Invalid format", "user@.com", false},
		{"Multiple @", "user@@example.com", false},
		{"Spaces in email", "user @example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateEmail(tt.email)
			if result != tt.expected {
				t.Errorf("ValidateEmail(%q) = %v, want %v", tt.email, result, tt.expected)
			}
		})
	}
}

// TestCheckEmailExists tests email existence check in database
func TestCheckEmailExists(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	tests := []struct {
		name          string
		email         string
		mockReturn    bool
		mockError     error
		expectedExist bool
		expectError   bool
	}{
		{
			name:          "Email exists",
			email:         "existing@example.com",
			mockReturn:    true,
			mockError:     nil,
			expectedExist: true,
			expectError:   false,
		},
		{
			name:          "Email does not exist",
			email:         "new@example.com",
			mockReturn:    false,
			mockError:     nil,
			expectedExist: false,
			expectError:   false,
		},
		{
			name:          "Database error",
			email:         "error@example.com",
			mockReturn:    false,
			mockError:     fmt.Errorf("database error"),
			expectedExist: false,
			expectError:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"exists"}).AddRow(tt.mockReturn)

			if tt.mockError != nil {
				mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
					WithArgs(tt.email).
					WillReturnError(tt.mockError)
			} else {
				mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
					WithArgs(tt.email).
					WillReturnRows(rows)
			}

			exists, err := CheckEmailExists(db, tt.email)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if exists != tt.expectedExist {
				t.Errorf("CheckEmailExists() = %v, want %v", exists, tt.expectedExist)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestLoginAttemptTracker_FirstAttempt tests the first failed login attempt
func TestLoginAttemptTracker_FirstAttempt(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"
	ip := "192.168.1.1"

	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt(email, ip)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !isLocked {
		t.Error("Expected account to be locked after first attempt")
	}
	if isBlocked {
		t.Error("Account should not be blocked after first attempt")
	}
	if lockDuration != 1*time.Minute {
		t.Errorf("Expected lock duration of 1 minute, got %v", lockDuration)
	}
	if tracker.GetAttemptCount(email) != 1 {
		t.Errorf("Expected 1 attempt, got %d", tracker.GetAttemptCount(email))
	}
}

// TestLoginAttemptTracker_ThreeAttempts tests three failed login attempts
func TestLoginAttemptTracker_ThreeAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"
	ip := "192.168.1.1"

	// First attempt
	tracker.RecordFailedAttempt(email, ip)

	// Second attempt
	tracker.RecordFailedAttempt(email, ip)

	// Third attempt
	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt(email, ip)

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if !isLocked {
		t.Error("Expected account to be locked after third attempt")
	}
	if isBlocked {
		t.Error("Account should not be blocked after third attempt")
	}
	if lockDuration != 5*time.Minute {
		t.Errorf("Expected lock duration of 5 minutes, got %v", lockDuration)
	}
	if tracker.GetAttemptCount(email) != 3 {
		t.Errorf("Expected 3 attempts, got %d", tracker.GetAttemptCount(email))
	}
}

// TestLoginAttemptTracker_FiveAttempts tests five failed login attempts leading to permanent block
func TestLoginAttemptTracker_FiveAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"
	ip := "192.168.1.1"

	// Record 4 attempts
	for i := 0; i < 4; i++ {
		tracker.RecordFailedAttempt(email, ip)
	}

	// Fifth attempt should block permanently
	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt(email, ip)

	if err == nil {
		t.Error("Expected error for blocked account")
	}
	if !isLocked {
		t.Error("Expected account to be locked")
	}
	if !isBlocked {
		t.Error("Account should be permanently blocked after 5 attempts")
	}
	if lockDuration != 0 {
		t.Error("Lock duration should be 0 for permanent block")
	}
	if tracker.GetAttemptCount(email) != 5 {
		t.Errorf("Expected 5 attempts, got %d", tracker.GetAttemptCount(email))
	}
}

// TestLoginAttemptTracker_CheckAccountStatus tests checking account status
func TestLoginAttemptTracker_CheckAccountStatus(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"
	ip := "192.168.1.1"

	// Initially, account should not be locked
	isLocked, remainingTime, isBlocked := tracker.CheckAccountStatus(email)
	if isLocked || isBlocked {
		t.Error("New account should not be locked or blocked")
	}

	// After one failed attempt, should be locked
	tracker.RecordFailedAttempt(email, ip)
	isLocked, remainingTime, isBlocked = tracker.CheckAccountStatus(email)
	if !isLocked {
		t.Error("Account should be locked after failed attempt")
	}
	if isBlocked {
		t.Error("Account should not be blocked after one attempt")
	}
	if remainingTime <= 0 || remainingTime > 1*time.Minute {
		t.Errorf("Expected remaining time around 1 minute, got %v", remainingTime)
	}

	// After 5 attempts, should be blocked
	for i := 0; i < 4; i++ {
		tracker.RecordFailedAttempt(email, ip)
	}
	isLocked, remainingTime, isBlocked = tracker.CheckAccountStatus(email)
	if !isLocked {
		t.Error("Account should be locked")
	}
	if !isBlocked {
		t.Error("Account should be permanently blocked after 5 attempts")
	}
	if remainingTime != 0 {
		t.Error("Remaining time should be 0 for permanent block")
	}
}

// TestLoginAttemptTracker_ResetAttempts tests resetting attempts on successful login
func TestLoginAttemptTracker_ResetAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"
	ip := "192.168.1.1"

	// Record some failed attempts
	tracker.RecordFailedAttempt(email, ip)
	tracker.RecordFailedAttempt(email, ip)

	if tracker.GetAttemptCount(email) != 2 {
		t.Errorf("Expected 2 attempts, got %d", tracker.GetAttemptCount(email))
	}

	// Reset attempts
	tracker.ResetAttempts(email)

	if tracker.GetAttemptCount(email) != 0 {
		t.Errorf("Expected 0 attempts after reset, got %d", tracker.GetAttemptCount(email))
	}

	// Check status should show unlocked
	isLocked, _, _ := tracker.CheckAccountStatus(email)
	if isLocked {
		t.Error("Account should not be locked after reset")
	}
}

// TestLoginAttemptTracker_ConcurrentAccess tests thread-safe concurrent access
func TestLoginAttemptTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	done := make(chan bool)

	// Launch multiple goroutines that try to record attempts
	for i := 0; i < 10; i++ {
		go func(id int) {
			ip := fmt.Sprintf("192.168.1.%d", id)
			tracker.RecordFailedAttempt(email, ip)
			tracker.CheckAccountStatus(email)
			tracker.GetAttemptCount(email)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Just verify no panic occurred and we can still query the tracker
	count := tracker.GetAttemptCount(email)
	if count < 0 || count > 10 {
		t.Errorf("Unexpected attempt count: %d", count)
	}
}

// TestLoginAttemptTracker_MultipleAccounts tests tracking multiple accounts independently
func TestLoginAttemptTracker_MultipleAccounts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email1 := "user1@example.com"
	email2 := "user2@example.com"
	ip := "192.168.1.1"

	// Record different number of attempts for different accounts
	tracker.RecordFailedAttempt(email1, ip)
	tracker.RecordFailedAttempt(email2, ip)
	tracker.RecordFailedAttempt(email2, ip)

	count1 := tracker.GetAttemptCount(email1)
	count2 := tracker.GetAttemptCount(email2)

	if count1 != 1 {
		t.Errorf("Expected 1 attempt for email1, got %d", count1)
	}
	if count2 != 2 {
		t.Errorf("Expected 2 attempts for email2, got %d", count2)
	}

	// Check status for each account
	isLocked1, _, _ := tracker.CheckAccountStatus(email1)
	isLocked2, _, _ := tracker.CheckAccountStatus(email2)

	if !isLocked1 || !isLocked2 {
		t.Error("Both accounts should be locked")
	}
}

// TestGetSanitizedError tests sanitized error messages
func TestGetSanitizedError(t *testing.T) {
	tests := []struct {
		errorType        string
		shouldContain    string
		shouldNotContain []string
	}{
		{
			errorType:        "login_failed",
			shouldContain:    "Invalid",
			shouldNotContain: []string{"email", "password", "exists", "not found"},
		},
		{
			errorType:        "registration_failed",
			shouldContain:    "Registration failed",
			shouldNotContain: []string{"email exists", "duplicate", "already taken"},
		},
		{
			errorType:        "account_locked",
			shouldContain:    "try again later",
			shouldNotContain: []string{"1 minute", "5 minutes", "attempts"},
		},
		{
			errorType:        "account_blocked",
			shouldContain:    "restricted",
			shouldNotContain: []string{"5 attempts", "failed", "blocked permanently"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.errorType, func(t *testing.T) {
			message := GetSanitizedError(tt.errorType)

			// Check if message is not empty
			if message == "" {
				t.Error("Sanitized error message should not be empty")
			}

			// Message should not contain specific technical details
			for _, forbidden := range tt.shouldNotContain {
				if containsIgnoreCase(message, forbidden) {
					t.Errorf("Error message should not contain '%s': %s", forbidden, message)
				}
			}
		})
	}
}

// TestNewValidationError tests validation error creation
func TestNewValidationError(t *testing.T) {
	tests := []string{
		"login_failed",
		"registration_failed",
		"account_locked",
		"account_blocked",
		"validation_failed",
	}

	for _, errorType := range tests {
		t.Run(errorType, func(t *testing.T) {
			err := NewValidationError(errorType)

			if err.Type != errorType {
				t.Errorf("Expected type %s, got %s", errorType, err.Type)
			}

			if err.Message == "" {
				t.Error("Error message should not be empty")
			}

			if err.Error() != err.Message {
				t.Error("Error() should return the message")
			}
		})
	}
}

// TestLoginAttemptTracker_ExpiredAttempts tests that old attempts are cleaned up
func TestLoginAttemptTracker_ExpiredAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"
	ip := "192.168.1.1"

	// Record an attempt
	tracker.RecordFailedAttempt(email, ip)

	// Manually set the attempt timestamp to be old (more than 10 minutes ago)
	if status := tracker.accounts[email]; status != nil {
		status.mu.Lock()
		status.FailedAttempts[0].Timestamp = time.Now().Add(-15 * time.Minute)
		status.mu.Unlock()
	}

	// Record a new attempt, which should clean up the old one
	tracker.RecordFailedAttempt(email, ip)

	// Should only have 1 attempt now (the new one)
	count := tracker.GetAttemptCount(email)
	if count != 1 {
		t.Errorf("Expected 1 attempt after cleanup, got %d", count)
	}
}

// Helper function to check if a string contains a substring (case-insensitive)
func containsIgnoreCase(s, substr string) bool {
	s = toLower(s)
	substr = toLower(substr)
	return contains(s, substr)
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c = c + ('a' - 'A')
		}
		result[i] = c
	}
	return string(result)
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexOf(s, substr) >= 0)
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
