package main

import (
	"fmt"

	"github.com/Hadidomena/projektKomunikator/cryptography"
)

func main() {
	encrypted := cryptography.Encrypt("some thing")
	fmt.Println(encrypted)
	fmt.Println(cryptography.Decrypt(encrypted))
}
