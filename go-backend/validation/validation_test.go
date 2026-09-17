package validation

import (
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

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

func TestLoginAttemptTracker_FirstAttempt(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt(email)

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
}

func TestLoginAttemptTracker_ThreeAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	tracker.RecordFailedAttempt(email)

	tracker.RecordFailedAttempt(email)

	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt(email)

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
}

func TestLoginAttemptTracker_FiveAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	for i := 0; i < 4; i++ {
		tracker.RecordFailedAttempt(email)
	}

	isLocked, lockDuration, isBlocked, err := tracker.RecordFailedAttempt(email)

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
}

func TestLoginAttemptTracker_CheckAccountStatus(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	isLocked, _, isBlocked, _ := tracker.CheckAccountStatus(email)
	if isLocked || isBlocked {
		t.Error("New account should not be locked or blocked")
	}

	tracker.RecordFailedAttempt(email)
	isLocked, remainingTime, isBlocked, _ := tracker.CheckAccountStatus(email)
	if !isLocked {
		t.Error("Account should be locked after failed attempt")
	}
	if isBlocked {
		t.Error("Account should not be blocked after one attempt")
	}
	if remainingTime <= 0 || remainingTime > 1*time.Minute {
		t.Errorf("Expected remaining time around 1 minute, got %v", remainingTime)
	}

	for i := 0; i < 4; i++ {
		tracker.RecordFailedAttempt(email)
	}
	isLocked, remainingTime, isBlocked, _ = tracker.CheckAccountStatus(email)
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

func TestLoginAttemptTracker_ResetAttempts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	tracker.RecordFailedAttempt(email)
	tracker.RecordFailedAttempt(email)

	isLocked, _, _, _ := tracker.CheckAccountStatus(email)
	if !isLocked {
		t.Error("Account should be locked after failed attempts")
	}

	tracker.ResetAttempts(email)

	isLocked, _, _, _ = tracker.CheckAccountStatus(email)
	if isLocked {
		t.Error("Account should not be locked after reset")
	}
}

func TestLoginAttemptTracker_ConcurrentAccess(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email := "test@example.com"

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			tracker.RecordFailedAttempt(email)
			tracker.CheckAccountStatus(email)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	isLocked, _, _, _ := tracker.CheckAccountStatus(email)
	if !isLocked {
		t.Error("Account should be locked after concurrent attempts")
	}
}

func TestLoginAttemptTracker_MultipleAccounts(t *testing.T) {
	tracker := NewLoginAttemptTracker()
	email1 := "user1@example.com"
	email2 := "user2@example.com"

	tracker.RecordFailedAttempt(email1)
	tracker.RecordFailedAttempt(email2)
	tracker.RecordFailedAttempt(email2)

	isLocked1, _, _, _ := tracker.CheckAccountStatus(email1)
	isLocked2, _, _, _ := tracker.CheckAccountStatus(email2)

	if !isLocked1 || !isLocked2 {
		t.Error("Both accounts should be locked")
	}
}

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

			if message == "" {
				t.Error("Sanitized error message should not be empty")
			}

			for _, forbidden := range tt.shouldNotContain {
				if containsIgnoreCase(message, forbidden) {
					t.Errorf("Error message should not contain '%s': %s", forbidden, message)
				}
			}
		})
	}
}

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
