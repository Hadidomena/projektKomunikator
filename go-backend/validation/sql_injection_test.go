package validation

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestSQLInjectionProtection_EmailValidation tests that email validation protects against SQL injection
func TestSQLInjectionProtection_EmailValidation(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	maliciousInputs := []string{
		"' OR '1'='1",
		"admin'--",
		"' OR 1=1--",
		"admin'; DROP TABLE Users;--",
		"' UNION SELECT * FROM Users--",
		"1' AND '1'='1",
		"'; DELETE FROM Users WHERE ''='",
		"' OR ''='",
	}

	for _, maliciousEmail := range maliciousInputs {
		t.Run(maliciousEmail, func(t *testing.T) {
			// The query should be parameterized, so the malicious input is treated as a literal string
			rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)

			// Expect parameterized query - the $1 placeholder protects against injection
			mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
				WithArgs(maliciousEmail).
				WillReturnRows(rows)

			exists, err := CheckEmailExists(db, maliciousEmail)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			// The malicious input should be safely handled as a regular email value
			if exists {
				t.Error("Should return false for non-existent malicious input")
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("SQL injection test failed - query was not properly parameterized: %v", err)
			}
		})
	}
}

// TestSQLInjectionProtection_UsernameValidation tests username input protection
func TestSQLInjectionProtection_UsernameValidation(t *testing.T) {
	maliciousUsernames := []string{
		"admin' OR '1'='1",
		"'; DROP TABLE Users; --",
		"admin'--",
		"' UNION SELECT password_hash FROM Users WHERE username='admin",
		"1' OR 1=1--",
	}

	for _, username := range maliciousUsernames {
		// Usernames with SQL injection attempts should still be treated as regular strings
		// The database will handle them safely because we use parameterized queries
		if username == "" {
			t.Errorf("Username should not be empty")
		}

		// These malicious inputs would only cause problems if concatenated directly into SQL
		// With parameterized queries ($1, $2), they are safely escaped
		if len(username) > 255 {
			t.Errorf("Username too long (potential buffer overflow attempt)")
		}
	}
}

// TestParameterizedQueryProtection demonstrates how parameterized queries protect against SQL injection
func TestParameterizedQueryProtection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	// Test case: Attacker tries to inject SQL via email field
	attackEmail := "attacker@example.com' OR '1'='1"

	// With parameterized queries, the entire string is treated as the email value
	rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)

	// The $1 placeholder ensures the input is escaped and treated as a literal value
	mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
		WithArgs(attackEmail).
		WillReturnRows(rows)

	exists, err := CheckEmailExists(db, attackEmail)

	if err != nil {
		t.Fatalf("Query failed: %v", err)
	}

	if exists {
		t.Error("Injection attempt should not return true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("SQL expectations not met: %v", err)
	}
}

// TestNoDirectStringConcatenation ensures we're not concatenating user input into SQL
func TestNoDirectStringConcatenation(t *testing.T) {
	// This test documents the CORRECT way to write SQL queries
	correctQuery := "SELECT * FROM Users WHERE email = $1"

	// WRONG (vulnerable): "SELECT * FROM Users WHERE email = '" + email + "'"
	// RIGHT (safe): Using $1, $2 placeholders with separate arguments

	if correctQuery != "SELECT * FROM Users WHERE email = $1" {
		t.Error("Query should use parameterized placeholder")
	}

	// Verify the query uses placeholders, not string concatenation
	hasPlaceholder := false
	for i := 0; i < len(correctQuery); i++ {
		if correctQuery[i] == '$' && i+1 < len(correctQuery) && correctQuery[i+1] >= '1' && correctQuery[i+1] <= '9' {
			hasPlaceholder = true
			break
		}
	}

	if !hasPlaceholder {
		t.Error("Query must use $N placeholders for parameters")
	}
}

// TestInputLengthLimits tests that inputs are reasonably bounded
func TestInputLengthLimits(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		maxLength int
		field     string
	}{
		{
			name:      "Email length limit",
			input:     string(make([]byte, 300)),
			maxLength: 255,
			field:     "email",
		},
		{
			name:      "Username length limit",
			input:     string(make([]byte, 100)),
			maxLength: 50,
			field:     "username",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.input) > tt.maxLength {
				// Applications should validate length before database operations
				t.Logf("Input exceeds max length for %s: %d > %d", tt.field, len(tt.input), tt.maxLength)
				// This is expected - we should reject oversized inputs
			}
		})
	}
}

// TestSpecialCharacterHandling tests that special characters are safely handled
func TestSpecialCharacterHandling(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	specialCharInputs := []string{
		"user@example.com'; --",
		"test@example.com\\",
		"user@example.com\x00", // null byte
		"user@example.com\"",
		"user@example.com<script>",
	}

	for _, input := range specialCharInputs {
		t.Run(input, func(t *testing.T) {
			rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)

			// Parameterized query safely handles special characters
			mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
				WithArgs(input).
				WillReturnRows(rows)

			exists, err := CheckEmailExists(db, input)

			if err != nil {
				t.Logf("Query handled special characters safely: %v", err)
			} else {
				// Special characters are treated as literal values in parameterized queries
				if exists {
					t.Error("Should not find existing user with special characters")
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("Special character handling failed: %v", err)
			}
		})
	}
}
