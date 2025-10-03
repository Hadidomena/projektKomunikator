package main

import "fmt"

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
func beaufortDecryption(text, key string) string {
	decrypted := []rune{}
	keyRunes := []rune(key)
	for i, char := range text {
		decrypted = append(decrypted, beaufortCharacter(char, keyRunes[i%len(keyRunes)]))
	}
	return string(decrypted)
}
func encrypt(input string) string {
	key := "abcdef"
	return beaufortEncryption(input, key)
}
func decrypt(input string) string {
	key := "abcdef"
	return beaufortDecryption(input, key)
}
func main() {
	encrypted := encrypt("something")
	fmt.Println(encrypted)
	fmt.Println(decrypt(encrypted))
}
