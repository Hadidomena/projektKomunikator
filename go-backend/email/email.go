package email

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net/mail"
	"net/smtp"
	"os"

	"github.com/jordan-wright/email"
)

var (
	smtpAddr      string
	smtpHost      string
	smtpUser      string
	smtpPass      string
	tlsServerName string
	fromEmail     string
	fromName      string
)

func init() {
	// Load email configuration from environment variables
	smtpAddr = os.Getenv("SMTP_ADDR")
	if smtpAddr == "" {
		smtpAddr = "smtp.example.com:587"
	}

	smtpHost = os.Getenv("SMTP_HOST")
	if smtpHost == "" {
		smtpHost = "smtp.example.com"
	}

	smtpUser = os.Getenv("SMTP_USER")
	if smtpUser == "" {
		smtpUser = "smtp-user"
	}

	smtpPass = os.Getenv("SMTP_PASS")
	if smtpPass == "" {
		smtpPass = "smtp-pass"
	}

	tlsServerName = os.Getenv("SMTP_TLS_SERVER_NAME")
	if tlsServerName == "" {
		tlsServerName = smtpHost
	}

	fromEmail = os.Getenv("SMTP_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@example.com"
	}

	fromName = os.Getenv("SMTP_FROM_NAME")
	if fromName == "" {
		fromName = "Komunikator"
	}
}

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
	e.From = fmt.Sprintf("%s <%s>", fromName, fromEmail)
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

func SendPasswordResetEmail(recipientEmail, token string) {
	resetLink := fmt.Sprintf("http://localhost:3000/reset-password?token=%s", token)
	_ = fmt.Sprintf("Password Reset Request")
	_ = fmt.Sprintf("Click the following link to reset your password: %s\n\nThis link will expire in 1 hour.", resetLink)

	fmt.Printf("Password reset email to %s: %s\n", recipientEmail, resetLink)
}

func SendNewDeviceEmail(recipientEmail, ip, userAgent string) {
	_ = fmt.Sprintf("New Device Login Detected")
	_ = fmt.Sprintf("A new login was detected from:\nIP: %s\nDevice: %s\n\nIf this wasn't you, please secure your account immediately.", ip, userAgent)

	fmt.Printf("New device alert to %s from IP %s\n", recipientEmail, ip)
}
