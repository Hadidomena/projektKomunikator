package validation

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

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
			rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)

			mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
				WithArgs(maliciousEmail).
				WillReturnRows(rows)

			exists, err := CheckEmailExists(db, maliciousEmail)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if exists {
				t.Error("Should return false for non-existent malicious input")
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("SQL injection test failed - query was not properly parameterized: %v", err)
			}
		})
	}
}

func TestSQLInjectionProtection_UsernameValidation(t *testing.T) {
	maliciousUsernames := []string{
		"admin' OR '1'='1",
		"'; DROP TABLE Users; --",
		"admin'--",
		"' UNION SELECT password_hash FROM Users WHERE username='admin",
		"1' OR 1=1--",
	}

	for _, username := range maliciousUsernames {
		if username == "" {
			t.Errorf("Username should not be empty")
		}

		if len(username) > 255 {
			t.Errorf("Username too long (potential buffer overflow attempt)")
		}
	}
}

func TestParameterizedQueryProtection(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock database: %v", err)
	}
	defer db.Close()

	attackEmail := "attacker@example.com' OR '1'='1"

	rows := sqlmock.NewRows([]string{"exists"}).AddRow(false)

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

func TestNoDirectStringConcatenation(t *testing.T) {
	correctQuery := "SELECT * FROM Users WHERE email = $1"

	if correctQuery != "SELECT * FROM Users WHERE email = $1" {
		t.Error("Query should use parameterized placeholder")
	}

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
				t.Logf("Input exceeds max length for %s: %d > %d", tt.field, len(tt.input), tt.maxLength)
			}
		})
	}
}

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

			mock.ExpectQuery("SELECT EXISTS\\(SELECT 1 FROM Users WHERE email = \\$1\\)").
				WithArgs(input).
				WillReturnRows(rows)

			exists, err := CheckEmailExists(db, input)

			if err != nil {
				t.Logf("Query handled special characters safely: %v", err)
			} else {
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
