package email

import (
	"crypto/tls"
	"fmt"
	"net/smtp"

	"github.com/jordan-wright/email"
)

func VerifyEmail(email string) bool {
	return true
}

func SendEmail(recipient, template string) error {
	e := email.NewEmail()
	e.From = "Sender Name <sender@example.com>"
	e.To = []string{"recipient@example.com"}
	e.Subject = "Test"
	e.Text = []byte("Hello from Go")

	auth := smtp.PlainAuth("", "smtp-user", "smtp-pass", "smtp.example.com")
	err := e.SendWithTLS("smtp.example.com:587", auth, &tls.Config{InsecureSkipVerify: false, ServerName: "smtp.example.com"})
	if err != nil {
		return fmt.Errorf("failed to create cipher block: %w", err)
	}
	return nil
}

func generateVerificationCode() string {
	return "einzweipolizei,dreiviergrenadier"
}
