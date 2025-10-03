package cryptography

func beaufortCharacter(char, keyChar rune) rune {
	if char >= 'A' && char <= 'Z' {
		return 'A' + (25-(keyChar-'A')-(char-'A'))%26
	}
	if char >= 'a' && char <= 'z' {
		return 'a' + (25-(keyChar-'a')-(char-'a'))%26
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
