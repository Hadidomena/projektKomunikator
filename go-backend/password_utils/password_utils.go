package passwordutils

import (
	"math"
	"os"
	"strings"
)

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
func isCommonPasword(password string) bool {
	data, err := os.ReadFile("100k-most-used-passwords-NCSC.txt")
	if err != nil {
		return false
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == password {
			return true
		}
	}
	return false
}

func IsViablePassword(password string) int {
	if len(password) < 12 {
		return 1
	}
	if isCommonPasword(password) {
		return 2
	}

	if calculatePasswordStrength(password) < 400 {
		return 3
	}
	return 0
}
