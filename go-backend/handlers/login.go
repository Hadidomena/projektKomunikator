package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/email"
	"github.com/Hadidomena/projektKomunikator/honeypot"
	jwt_auth "github.com/Hadidomena/projektKomunikator/jwt_auth"
	"github.com/Hadidomena/projektKomunikator/login_monitoring"
	"github.com/Hadidomena/projektKomunikator/validation"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	if loginHoneypotTriggered(w, r, req.Email, req.Website, req.Phone, req.MiddleName, "Login") {
		return
	}

	if !validation.ValidateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	emailAddr := strings.ToLower(req.Email)

	isLocked, remainingTime, isBlocked, err := ctx.LoginTracker.CheckAccountStatus(emailAddr)
	if err != nil {
		log.Printf("Error checking account status for %s: %v", emailAddr, err)
		writeError(w, http.StatusServiceUnavailable, "Service temporarily unavailable. Please try again later")
		return
	}

	if isBlocked {
		writeError(w, http.StatusForbidden, validation.GetSanitizedError("account_blocked"))
		return
	}

	if isLocked {
		writeJSON(w, http.StatusTooManyRequests, ErrorResponse{
			Message: validation.GetSanitizedError("account_locked"),
		})
		log.Printf("Login attempt for locked account: %s, remaining time: %v", emailAddr, remainingTime)
		return
	}

	ctx2, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var storedHash string
	var userID int
	var totpEnabled bool
	var publicKey, privateKeyEncrypted string
	err = ctx.DB.QueryRowContext(ctx2,
		"SELECT id, password_hash, totp_enabled, COALESCE(e2ee_public_key, ''), COALESCE(e2ee_private_key_encrypted, '') FROM Users WHERE email = $1",
		emailAddr).Scan(&userID, &storedHash, &totpEnabled, &publicKey, &privateKeyEncrypted)

	if err != nil {
		if err == sql.ErrNoRows {
			_, _, _, _ = ctx.LoginTracker.RecordFailedAttempt(emailAddr)

			writeError(w, http.StatusUnauthorized, validation.GetSanitizedError("login_failed"))
			return
		}

		log.Printf("Database error during login: %v", err)
		writeError(w, http.StatusInternalServerError, validation.GetSanitizedError("login_failed"))
		return
	}

	passwordValid, err := cryptography.VerifyPassword(req.Password, storedHash)
	if err != nil {
		log.Printf("Error verifying password: %v", err)
		writeError(w, http.StatusInternalServerError, validation.GetSanitizedError("login_failed"))
		return
	}

	if !passwordValid {
		recordFailedLogin(w, r, emailAddr, "Failed login attempt", validation.GetSanitizedError("login_failed"))
		return
	}

	if err := ctx.LoginTracker.ResetAttempts(emailAddr); err != nil {
		log.Printf("Failed to reset login attempts for %s: %v", emailAddr, err)
	}

	ip := GetClientIP(r)
	userAgent := r.UserAgent()
	deviceFingerprint := login_monitoring.GenerateDeviceFingerprint(ip, userAgent)

	isNewDevice, err := login_monitoring.IsNewDevice(ctx.DB, userID, deviceFingerprint)
	if err != nil {
		log.Printf("Error checking device: %v", err)
	}

	loginAttempt := &login_monitoring.LoginAttempt{
		UserID:            userID,
		IPAddress:         ip,
		UserAgent:         userAgent,
		DeviceFingerprint: deviceFingerprint,
		Success:           true,
		NewDevice:         isNewDevice,
	}

	if err := login_monitoring.RecordLoginAttempt(ctx.DB, loginAttempt); err != nil {
		log.Printf("Error recording login attempt: %v", err)
	}

	if isNewDevice {
		log.Printf("New device login detected for user %s from IP %s", emailAddr, ip)
		go email.SendNewDeviceEmail(emailAddr, ip, userAgent)
	}

	if totpEnabled {
		log.Printf("2FA required for user: %s", emailAddr)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"message":       "2FA verification required",
			"requires_totp": true,
		})
		return
	}

	token, err := jwt_auth.GenerateToken(userID, emailAddr)
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to complete login")
		return
	}

	log.Printf("Successful login for user: %s", emailAddr)

	writeJSON(w, http.StatusOK, loginResponse(userID, emailAddr, token, publicKey, privateKeyEncrypted))
}

func loginResponse(userID int, email, token, publicKey, privateKeyEncrypted string) map[string]interface{} {
	response := map[string]interface{}{
		"message":    "Login successful",
		"token":      token,
		"user_id":    userID,
		"email":      email,
		"expires_in": jwt_auth.GetTokenExpiration().Seconds(),
	}
	if publicKey != "" {
		response["e2ee_public_key"] = publicKey
	}
	if privateKeyEncrypted != "" {
		response["e2ee_private_key_encrypted"] = privateKeyEncrypted
	}
	return response
}

func loginHoneypotTriggered(w http.ResponseWriter, r *http.Request, email, website, phone, middleName, label string) bool {
	if !honeypot.CheckHoneypot(website) && !honeypot.CheckHoneypot(phone) && !honeypot.CheckHoneypot(middleName) {
		return false
	}

	ip := GetClientIP(r)
	honeypotValue := website
	if phone != "" {
		honeypotValue = phone
	} else if middleName != "" {
		honeypotValue = middleName
	}

	_ = honeypot.RecordHoneypotAttempt(ctx.DB, &honeypot.HoneypotAttempt{
		IPAddress:     ip,
		UserAgent:     r.UserAgent(),
		HoneypotField: "login_honeypot",
		HoneypotValue: honeypotValue,
		SubmittedData: map[string]interface{}{
			"email":       email,
			"website":     website,
			"phone":       phone,
			"middle_name": middleName,
		},
		Blocked: true,
	})
	log.Printf("%s honeypot triggered from IP: %s, email: %s", label, ip, email)

	time.Sleep(500 * time.Millisecond)
	writeError(w, http.StatusUnauthorized, validation.GetSanitizedError("login_failed"))
	return true
}

func recordFailedLogin(w http.ResponseWriter, r *http.Request, email, logLabel, unauthorizedMsg string) {
	isLocked, lockDuration, isBlocked, _ := ctx.LoginTracker.RecordFailedAttempt(email)

	log.Printf("%s for user: %s from IP: %s", logLabel, email, GetClientIP(r))

	if isBlocked {
		writeError(w, http.StatusForbidden, validation.GetSanitizedError("account_blocked"))
		return
	}

	if isLocked {
		writeJSON(w, http.StatusTooManyRequests, ErrorResponse{
			Message: validation.GetSanitizedError("account_locked"),
		})
		log.Printf("Account locked: %s, duration: %v", email, lockDuration)
		return
	}

	writeError(w, http.StatusUnauthorized, unauthorizedMsg)
}
