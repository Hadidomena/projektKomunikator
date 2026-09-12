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

func SendEmail(subject string, recipient []string, body string) error {
	e := email.NewEmail()
	e.From = fmt.Sprintf("%s <%s>", fromName, fromEmail)
	e.To = recipient
	e.Subject = subject
	e.Text = []byte(body)

	if err := sendFunc(e); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}
	return nil
}

func generateVerificationCode() (string, error) {
	characterSet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	lenOfSet := int64(len(characterSet))
	code := []rune{}
	for range 12 {
		random, err := secureInt(lenOfSet)
		if err != nil {
			return "", err
		}
		code = append(code, []rune(characterSet)[random])
	}
	return string(code), nil
}

func SendPasswordResetEmail(recipientEmail, token string) {
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:4321"
	}
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", frontendURL, token)
	body := fmt.Sprintf("Click the following link to reset your password: %s\n\nThis link will expire in 1 hour.", resetLink)

	if err := SendEmail("Password Reset Request", []string{recipientEmail}, body); err != nil {
		fmt.Printf("Failed to send password reset email to %s: %v\n", recipientEmail, err)
	}
}

func SendNewDeviceEmail(recipientEmail, ip, userAgent string) {
	body := fmt.Sprintf("A new login was detected from:\nIP: %s\nDevice: %s\n\nIf this wasn't you, please secure your account immediately.", ip, userAgent)

	if err := SendEmail("New Device Login Detected", []string{recipientEmail}, body); err != nil {
		fmt.Printf("Failed to send new device alert to %s: %v\n", recipientEmail, err)
	}
}
