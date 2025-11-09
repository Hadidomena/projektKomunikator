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
