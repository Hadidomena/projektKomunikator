package passwordutils

import (
	"bufio"
	"math"
	"os"
	"strings"
	"sync"
)

var (
	// commonPasswords holds the loaded common passwords in memory
	commonPasswords map[string]struct{}
	// mu protects the commonPasswords map
	mu sync.RWMutex
	// loaded tracks if passwords have been loaded
	loaded bool
)

// LoadCommonPasswords loads the common passwords file into memory at startup
// This should be called once during application initialization
func LoadCommonPasswords() error {
	mu.Lock()
	defer mu.Unlock()

	if loaded {
		return nil
	}

	// Try multiple possible paths for the password file
	possiblePaths := []string{
		"100k-most-used-passwords-NCSC.txt",
		"../100k-most-used-passwords-NCSC.txt",
		"./go-backend/100k-most-used-passwords-NCSC.txt",
	}

	var file *os.File
	var err error

	for _, path := range possiblePaths {
		file, err = os.Open(path)
		if err == nil {
			break
		}
	}

	if file == nil {
		return err
	}
	defer file.Close()

	commonPasswords = make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := strings.TrimSpace(scanner.Text())
		if password != "" {
			commonPasswords[password] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	loaded = true
	return nil
}

func countSymbols(password string) []float64 {
	uppercase, lowercase, numbers, symbols := 0, 0, 0, 0
	for _, char := range password {
		switch {
		case char >= 'A' && char <= 'Z':
			uppercase++
		case char >= 'a' && char <= 'z':
			lowercase++
		case char >= '0' && char <= '9':
			numbers++
		default:
			symbols++
		}
	}
	return []float64{float64(uppercase), float64(lowercase), float64(numbers), float64(symbols)}
}

func shannonEntropy(password string) float64 {
	entropy := 0.0
	symbols := make(map[rune]int)
	for _, char := range password {
		symbols[char]++
	}
	for _, count := range symbols {
		probability := float64(count) / float64(len(password))
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

func calculatePasswordStrength(password string) float64 {
	// Bonuses
	strength := float64(len(password) * 4)
	symbols := countSymbols(password)
	strength += symbols[0] * 2
	strength += symbols[1] * 2
	strength += symbols[2] * 4
	strength += symbols[3] * 6
	strength *= shannonEntropy(password)

	// Deductions
	for _, symbol := range symbols {
		if symbol == 0 {
			strength -= float64(len(password) * 2)
		}
	}
	return strength
}

func isCommonPassword(password string) bool {
	mu.RLock()
	defer mu.RUnlock()

	// If passwords aren't loaded, try to load them on the fly
	if !loaded {
		mu.RUnlock()
		if err := LoadCommonPasswords(); err != nil {
			mu.RLock()
			return false
		}
		mu.RLock()
	}

	_, exists := commonPasswords[password]
	return exists
}

// PasswordStrength represents the strength analysis of a password
type PasswordStrength struct {
	Score      float64 `json:"score"`       // Raw strength score
	Level      string  `json:"level"`       // weak, fair, good, strong, very_strong
	IsCommon   bool    `json:"is_common"`   // Is it a commonly used password?
	Length     int     `json:"length"`      // Password length
	HasUpper   bool    `json:"has_upper"`   // Contains uppercase letters
	HasLower   bool    `json:"has_lower"`   // Contains lowercase letters
	HasNumbers bool    `json:"has_numbers"` // Contains numbers
	HasSymbols bool    `json:"has_symbols"` // Contains special symbols
	Feedback   string  `json:"feedback"`    // User-friendly feedback message
}

// GetPasswordStrength returns detailed password strength analysis
func GetPasswordStrength(password string) PasswordStrength {
	result := PasswordStrength{
		Length:   len(password),
		IsCommon: isCommonPassword(password),
	}

	// Count character types
	symbols := countSymbols(password)
	result.HasUpper = symbols[0] > 0
	result.HasLower = symbols[1] > 0
	result.HasNumbers = symbols[2] > 0
	result.HasSymbols = symbols[3] > 0

	// Calculate strength score
	result.Score = calculatePasswordStrength(password)

	// Determine level and feedback
	switch {
	case result.Length < 12:
		result.Level = "weak"
		result.Feedback = "Password too short (minimum 12 characters)"
	case result.IsCommon:
		result.Level = "weak"
		result.Feedback = "This is a commonly used password"
	case result.Score < 400:
		result.Level = "weak"
		result.Feedback = "Password is too weak"
	case result.Score < 600:
		result.Level = "fair"
		result.Feedback = "Password strength is fair"
	case result.Score < 800:
		result.Level = "good"
		result.Feedback = "Password strength is good"
	case result.Score < 1000:
		result.Level = "strong"
		result.Feedback = "Password is strong"
	default:
		result.Level = "very_strong"
		result.Feedback = "Password is very strong"
	}

	// Add specific suggestions
	if !result.HasUpper || !result.HasLower || !result.HasNumbers || !result.HasSymbols {
		if result.Level != "weak" {
			result.Feedback += " (consider adding "
			missing := []string{}
			if !result.HasUpper {
				missing = append(missing, "uppercase")
			}
			if !result.HasLower {
				missing = append(missing, "lowercase")
			}
			if !result.HasNumbers {
				missing = append(missing, "numbers")
			}
			if !result.HasSymbols {
				missing = append(missing, "symbols")
			}
			result.Feedback += strings.Join(missing, ", ") + ")"
		}
	}

	return result
}

// Externally provided function to check validity of password
// returns 1 for too short a password,
// 2 for password from common list
// 3 for not strong enough password
func IsViablePassword(password string) int {
	if len(password) < 12 {
		return 1
	}
	if isCommonPassword(password) {
		return 2
	}

	if calculatePasswordStrength(password) < 400 {
		return 3
	}

	return 0
}
