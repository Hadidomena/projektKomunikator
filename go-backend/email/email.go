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

var (
	// default SMTP configuration (can be overridden in tests)
	smtpAddr      = "smtp.example.com:587"
	smtpHost      = "smtp.example.com"
	smtpUser      = "smtp-user"
	smtpPass      = "smtp-pass"
	tlsServerName = "smtp.example.com"
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

var sendFunc = func(e *email.Email) error {
	auth := smtp.PlainAuth("", smtpUser, smtpPass, smtpHost)
	return e.SendWithTLS(smtpAddr, auth, &tls.Config{InsecureSkipVerify: false, ServerName: tlsServerName})
}

func SendEmail(recipient []string, template string) error {
	e := email.NewEmail()
	e.From = "Sender Name <sender@example.com>"
	e.To = recipient
	e.Subject = "Test"
	e.Text = []byte(template)

	if err := sendFunc(e); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
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
