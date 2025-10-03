package cryptography

func beaufortCharacter(char, keyChar rune) rune {
	if char >= 'A' && char <= 'Z' {
		// Beaufort cipher: result = (key - text) mod 26
		result := (keyChar - 'A') - (char - 'A')
		result = ((result % 26) + 26) % 26 // Handle negative results
		return 'A' + rune(result)
	}
	if char >= 'a' && char <= 'z' {
		// Beaufort cipher: result = (key - text) mod 26
		result := (keyChar - 'a') - (char - 'a')
		result = ((result % 26) + 26) % 26 // Handle negative results
		return 'a' + rune(result)
	}
	return char
}

func beaufortEncryption(text, key string) string {
	encrypted := []rune{}
	keyRunes := []rune(key)
	for i, char := range text {
		encrypted = append(encrypted, beaufortCharacter(char, keyRunes[i%len(keyRunes)]))
	}
	return string(encrypted)
}

func Encrypt(input string) string {
	key := "abcdef"
	input = beaufortEncryption(input, key)
	return hedgeCipher(4, input)
}

func Decrypt(input string) string {
	key := "abcdef"
	input = hedgeDecipher(4, input)
	return beaufortEncryption(input, key)
}

func hedgeCipher(numRows int, input string) string {
	rows := make([][]rune, numRows)
	for i, char := range input {
		rows[i%numRows] = append(rows[i%numRows], char)
	}
	var result []rune
	for _, row := range rows {
		result = append(result, row...)
	}
	return string(result)
}

func hedgeDecipher(numRows int, input string) string {
	if len(input) == 0 || numRows <= 0 {
		return input
	}

	inputRunes := []rune(input)
	result := make([]rune, len(inputRunes))
	colCount := len(inputRunes) / numRows
	remainder := len(inputRunes) % numRows

	sourceIndex := 0
	for row := 0; row < numRows; row++ {
		charsInRow := colCount
		if row < remainder {
			charsInRow++
		}
		for col := 0; col < charsInRow; col++ {
			originalPos := col*numRows + row
			if originalPos < len(result) {
				result[originalPos] = inputRunes[sourceIndex]
				sourceIndex++
			}
		}
	}

	return string(result)
}
