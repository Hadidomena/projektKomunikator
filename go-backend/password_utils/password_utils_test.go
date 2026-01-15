package passwordutils

import "testing"

func init() {
	// Load common passwords for tests
	LoadCommonPasswords()
}

func TestCalculatingPasswordStrength(t *testing.T) {
	password1 := "1234"
	password2 := "A1B2./deadline"

	if calculatePasswordStrength(password1) > calculatePasswordStrength(password2) {
		t.Errorf("More complicated password should have higher strength")
	}
}

func TestFindingCommonPassword(t *testing.T) {
	password := "1234"
	if !isCommonPassword(password) {
		t.Errorf("Password '1234' should be recognized as common")
	}
}

func TestTooShortPasword(t *testing.T) {
	password := "123"
	if IsViablePassword(password) != 1 {
		t.Errorf("Password should be too short to pass")
	}
}

func TestThereShouldBeViablePasswords(t *testing.T) {
	password := "A1B2./deadline2137"
	switch IsViablePassword(password) {
	case 1:
		t.Errorf("Password should be long enough")
	case 2:
		t.Errorf("Password should not be common")
	case 3:
		t.Errorf("Password should be strong enough")
	}

}

func TestGetPasswordStrength(t *testing.T) {
	tests := []struct {
		name          string
		password      string
		expectedLevel string
		minScore      float64
		shouldHaveAll bool
	}{
		{
			name:          "Very weak password",
			password:      "abc",
			expectedLevel: "weak",
			minScore:      0,
			shouldHaveAll: false,
		},
		{
			name:          "Common password",
			password:      "password123",
			expectedLevel: "weak",
			minScore:      0,
			shouldHaveAll: false,
		},
		{
			name:          "Short password",
			password:      "Ab1!",
			expectedLevel: "weak",
			minScore:      0,
			shouldHaveAll: false,
		},
		{
			name:          "Strong password",
			password:      "MyS3cure!Pass2024",
			expectedLevel: "fair",
			minScore:      400,
			shouldHaveAll: true,
		},
		{
			name:          "Very strong password",
			password:      "X9#mK2$pL5@qR8&vN4!",
			expectedLevel: "good",
			minScore:      600,
			shouldHaveAll: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength := GetPasswordStrength(tt.password)

			if strength.Level != tt.expectedLevel {
				t.Errorf("Expected level %s, got %s", tt.expectedLevel, strength.Level)
			}

			if strength.Score < tt.minScore {
				t.Errorf("Expected minimum score %.2f, got %.2f", tt.minScore, strength.Score)
			}

			if strength.Length != len(tt.password) {
				t.Errorf("Expected length %d, got %d", len(tt.password), strength.Length)
			}

			if tt.shouldHaveAll {
				if !strength.HasUpper {
					t.Errorf("Expected password to have uppercase letters")
				}
				if !strength.HasLower {
					t.Errorf("Expected password to have lowercase letters")
				}
				if !strength.HasNumbers {
					t.Errorf("Expected password to have numbers")
				}
				if !strength.HasSymbols {
					t.Errorf("Expected password to have symbols")
				}
			}

			if strength.Feedback == "" {
				t.Errorf("Expected feedback message, got empty string")
			}
		})
	}
}

func TestGetPasswordStrength_CharacterTypes(t *testing.T) {
	tests := []struct {
		name       string
		password   string
		hasUpper   bool
		hasLower   bool
		hasNumbers bool
		hasSymbols bool
	}{
		{
			name:       "Only lowercase",
			password:   "abcdefghijklm",
			hasUpper:   false,
			hasLower:   true,
			hasNumbers: false,
			hasSymbols: false,
		},
		{
			name:       "Mixed case",
			password:   "AbCdEfGhIjKlM",
			hasUpper:   true,
			hasLower:   true,
			hasNumbers: false,
			hasSymbols: false,
		},
		{
			name:       "With numbers",
			password:   "AbC123456789",
			hasUpper:   true,
			hasLower:   true,
			hasNumbers: true,
			hasSymbols: false,
		},
		{
			name:       "All character types",
			password:   "AbC123!@#$%^",
			hasUpper:   true,
			hasLower:   true,
			hasNumbers: true,
			hasSymbols: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			strength := GetPasswordStrength(tt.password)

			if strength.HasUpper != tt.hasUpper {
				t.Errorf("Expected HasUpper=%v, got %v", tt.hasUpper, strength.HasUpper)
			}
			if strength.HasLower != tt.hasLower {
				t.Errorf("Expected HasLower=%v, got %v", tt.hasLower, strength.HasLower)
			}
			if strength.HasNumbers != tt.hasNumbers {
				t.Errorf("Expected HasNumbers=%v, got %v", tt.hasNumbers, strength.HasNumbers)
			}
			if strength.HasSymbols != tt.hasSymbols {
				t.Errorf("Expected HasSymbols=%v, got %v", tt.hasSymbols, strength.HasSymbols)
			}
		})
	}
}
