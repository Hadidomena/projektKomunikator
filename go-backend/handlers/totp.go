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
	jwt_auth "github.com/Hadidomena/projektKomunikator/jwt_auth"
	"github.com/Hadidomena/projektKomunikator/totp"
	"github.com/Hadidomena/projektKomunikator/validation"
)

type TOTPSetupRequest struct {
	CSRFToken string `json:"csrf_token"`
	Password  string `json:"password"`
}

type TOTPVerifyRequest struct {
	Code      string `json:"code"`
	TOTPCode  string `json:"totp_code"`
	CSRFToken string `json:"csrf_token"`
}

type TOTPValidateRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Code     string `json:"totp_code"`
	honeypotFields
}

func TOTPStatusHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, _, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var totpEnabled bool
	var totpSecret sql.NullString
	err := ctx.DB.QueryRow(`SELECT totp_enabled, totp_secret FROM Users WHERE id = $1`, userID).Scan(&totpEnabled, &totpSecret)
	if err != nil {
		log.Printf("Failed to get 2FA status for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to get 2FA status")
		return
	}

	setupInProgress := totpSecret.Valid && totpSecret.String != "" && !totpEnabled

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"enabled":           totpEnabled,
		"setup_in_progress": setupInProgress,
	})
}

func TOTPSetupHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	userID, userEmail, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req TOTPSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "Password is required to secure the 2FA secret")
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		writeError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		log.Printf("Failed to generate TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to generate 2FA secret")
		return
	}

	encryptedSecretForDB, err := cryptography.EncryptSensitiveData(secret)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to setup 2FA")
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET totp_secret = $1 WHERE id = $2`, encryptedSecretForDB, userID)
	if err != nil {
		log.Printf("Failed to store TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to setup 2FA")
		return
	}

	encryptedSecretForUser, err := cryptography.EncryptForUser(secret, req.Password, userID)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for transmission to user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to setup 2FA")
		return
	}

	qrCodeURL := totp.GenerateQRCodeURL(userEmail, "Komunikator", secret)

	writeJSON(w, http.StatusOK, map[string]string{
		"secret":           secret,
		"encrypted_secret": encryptedSecretForUser,
		"qr_code":          qrCodeURL,
	})
}

func TOTPVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	userID, userEmail, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		writeError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}

	var encryptedTotpSecret string
	err := ctx.DB.QueryRow(`SELECT totp_secret FROM Users WHERE id = $1`, userID).Scan(&encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to retrieve TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "2FA not setup")
		return
	}

	if encryptedTotpSecret == "" {
		writeError(w, http.StatusBadRequest, "Please setup 2FA first")
		return
	}

	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to verify 2FA")
		return
	}

	verificationCode := req.Code
	if verificationCode == "" {
		verificationCode = req.TOTPCode
	}

	if verificationCode == "" {
		writeError(w, http.StatusBadRequest, "Verification code is required")
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, verificationCode, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Validation failed")
		return
	}

	if !valid {
		writeError(w, http.StatusUnauthorized, "Invalid 2FA code")
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET totp_enabled = TRUE, totp_verified_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		log.Printf("Failed to enable 2FA for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to enable 2FA")
		return
	}

	writeMessage(w, http.StatusOK, "2FA enabled successfully")
}

func TOTPDisableHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	userID, userEmail, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		writeError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}

	verificationCode := req.Code
	if verificationCode == "" {
		verificationCode = req.TOTPCode
	}
	if verificationCode == "" {
		writeError(w, http.StatusBadRequest, "TOTP code is required to disable 2FA")
		return
	}

	var encryptedTotpSecret string
	err := ctx.DB.QueryRow(`SELECT totp_secret FROM Users WHERE id = $1`, userID).Scan(&encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to retrieve TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to disable 2FA")
		return
	}

	if encryptedTotpSecret == "" {
		writeError(w, http.StatusBadRequest, "2FA not enabled")
		return
	}

	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to disable 2FA")
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, verificationCode, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Validation failed")
		return
	}

	if !valid {
		writeError(w, http.StatusUnauthorized, "Invalid TOTP code")
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, userID)
	if err != nil {
		log.Printf("Failed to disable 2FA for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to disable 2FA")
		return
	}

	writeMessage(w, http.StatusOK, "2FA disabled successfully")
}

func TOTPValidateHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var req TOTPValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if loginHoneypotTriggered(w, r, req.Email, req.Website, req.Phone, req.MiddleName, "2FA login") {
		return
	}

	if !validation.ValidateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
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
		log.Printf("2FA login attempt for locked account: %s, remaining time: %v", emailAddr, remainingTime)
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var userID int
	var encryptedTotpSecret string
	var totpEnabled bool
	var passwordHash string
	err = ctx.DB.QueryRowContext(ctxDB, `SELECT id, password_hash, totp_secret, totp_enabled FROM Users WHERE email = $1`, emailAddr).
		Scan(&userID, &passwordHash, &encryptedTotpSecret, &totpEnabled)
	if err != nil {
		if err == sql.ErrNoRows {
			_, _, _, _ = ctx.LoginTracker.RecordFailedAttempt(emailAddr)

			writeError(w, http.StatusUnauthorized, "Invalid credentials")
			return
		}

		log.Printf("Database error during 2FA login: %v", err)
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	passwordValid, err := cryptography.VerifyPassword(req.Password, passwordHash)
	if err != nil {
		log.Printf("Error verifying password during 2FA login: %v", err)
		writeError(w, http.StatusInternalServerError, validation.GetSanitizedError("login_failed"))
		return
	}

	if !passwordValid {
		recordFailedLogin(w, r, emailAddr, "Failed 2FA login attempt", "Invalid credentials")
		return
	}

	if !totpEnabled || encryptedTotpSecret == "" {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Validation failed")
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, req.Code, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Validation failed")
		return
	}

	if !valid {
		recordFailedLogin(w, r, emailAddr, "Invalid 2FA code", "Invalid 2FA code")
		return
	}

	if err := ctx.LoginTracker.ResetAttempts(emailAddr); err != nil {
		log.Printf("Failed to reset login attempts for %s: %v", emailAddr, err)
	}

	token, err := jwt_auth.GenerateToken(userID, emailAddr)
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to complete login")
		return
	}

	var publicKey, privateKeyEncrypted string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, ''), COALESCE(e2ee_private_key_encrypted, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey, &privateKeyEncrypted)
	if err != nil {
		log.Printf("Failed to get E2EE keys for user %d during 2FA login: %v", userID, err)
	}

	log.Printf("Successful 2FA login for user: %s", emailAddr)

	writeJSON(w, http.StatusOK, loginResponse(userID, emailAddr, token, publicKey, privateKeyEncrypted))
}
