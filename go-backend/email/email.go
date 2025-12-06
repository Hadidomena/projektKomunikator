package email

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net/mail"
	"net/smtp"

	"github.com/jordan-wright/email"
)

func secureInt(max int64) (int64, error) {
	if max <= 0 {
		return 0, nil
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		return 0, err
	}
	return n.Int64(), nil
}
func VerifyEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func SendEmail(recipient, template string) error {
	e := email.NewEmail()
	e.From = "Sender Name <sender@example.com>"
	e.To = []string{recipient}
	e.Subject = "Test"
	e.Text = []byte("Hello from Go")

	auth := smtp.PlainAuth("", "smtp-user", "smtp-pass", "smtp.example.com")
	err := e.SendWithTLS("smtp.example.com:587", auth, &tls.Config{InsecureSkipVerify: false, ServerName: "smtp.example.com"})
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}
	return nil
}

func generateVerificationCode() (string, error) {
	characterSet := "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ1234567890"
	lenOfSet := int64(len(characterSet))
	code := []rune{}
	for x := 0; x < 12; x++ {
		random, err := secureInt(lenOfSet)
		if err != nil {
			return "", err
		}
		code = append(code, []rune(characterSet)[random])
	}
	return string(code), nil
}
