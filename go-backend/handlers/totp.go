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
	"github.com/Hadidomena/projektKomunikator/honeypot"
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
	Email      string `json:"email"`
	Password   string `json:"password"`
	Code       string `json:"totp_code"`
	Website    string `json:"website,omitempty"`     // Honeypot field 1
	Phone      string `json:"phone,omitempty"`       // Honeypot field 2
	MiddleName string `json:"middle_name,omitempty"` // Honeypot field 3
}

func TOTPStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	var totpEnabled bool
	var totpSecret sql.NullString
	err = ctx.DB.QueryRow(`SELECT totp_enabled, totp_secret FROM Users WHERE id = $1`, userID).Scan(&totpEnabled, &totpSecret)
	if err != nil {
		log.Printf("Failed to get 2FA status for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to get 2FA status"})
		return
	}

	setupInProgress := totpSecret.Valid && totpSecret.String != "" && !totpEnabled

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":           totpEnabled,
		"setup_in_progress": setupInProgress,
	})
}

func TOTPSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	var req TOTPSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request body"})
		return
	}

	if req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Password is required to secure the 2FA secret"})
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		log.Printf("Failed to generate TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to generate 2FA secret"})
		return
	}

	encryptedSecretForDB, err := cryptography.EncryptSensitiveData(secret)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET totp_secret = $1 WHERE id = $2`, encryptedSecretForDB, userID)
	if err != nil {
		log.Printf("Failed to store TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	encryptedSecretForUser, err := cryptography.EncryptForUser(secret, req.Password, userID)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for transmission to user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	qrCodeURL := totp.GenerateQRCodeURL(userEmail, "Komunikator", secret)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"secret":           secret,
		"encrypted_secret": encryptedSecretForUser,
		"qr_code":          qrCodeURL,
	})
}

func TOTPVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request body"})
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	var encryptedTotpSecret string
	err = ctx.DB.QueryRow(`SELECT totp_secret FROM Users WHERE id = $1`, userID).Scan(&encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to retrieve TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "2FA not setup"})
		return
	}

	if encryptedTotpSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Please setup 2FA first"})
		return
	}

	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to verify 2FA"})
		return
	}

	verificationCode := req.Code
	if verificationCode == "" {
		verificationCode = req.TOTPCode
	}

	if verificationCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Verification code is required"})
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, verificationCode, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Validation failed"})
		return
	}

	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid 2FA code"})
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET totp_enabled = TRUE, totp_verified_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		log.Printf("Failed to enable 2FA for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to enable 2FA"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA enabled successfully"})
}

func TOTPDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request body"})
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	verificationCode := req.Code
	if verificationCode == "" {
		verificationCode = req.TOTPCode
	}
	if verificationCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "TOTP code is required to disable 2FA"})
		return
	}

	var encryptedTotpSecret string
	err = ctx.DB.QueryRow(`SELECT totp_secret FROM Users WHERE id = $1`, userID).Scan(&encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to retrieve TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to disable 2FA"})
		return
	}

	if encryptedTotpSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "2FA not enabled"})
		return
	}

	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to disable 2FA"})
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, verificationCode, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Validation failed"})
		return
	}

	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid TOTP code"})
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, userID)
	if err != nil {
		log.Printf("Failed to disable 2FA for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to disable 2FA"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA disabled successfully"})
}

func TOTPValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	var req TOTPValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request body"})
		return
	}

	// Check honeypot fields - if any are filled, it's likely a bot
	honeypotTriggered := honeypot.CheckHoneypot(req.Website) ||
		honeypot.CheckHoneypot(req.Phone) ||
		honeypot.CheckHoneypot(req.MiddleName)

	if honeypotTriggered {
		ip := GetClientIP(r)
		honeypotValue := req.Website
		if req.Phone != "" {
			honeypotValue = req.Phone
		} else if req.MiddleName != "" {
			honeypotValue = req.MiddleName
		}

		honeypotAttempt := &honeypot.HoneypotAttempt{
			IPAddress:     ip,
			UserAgent:     r.UserAgent(),
			HoneypotField: "login_honeypot",
			HoneypotValue: honeypotValue,
			SubmittedData: map[string]interface{}{
				"email":       req.Email,
				"website":     req.Website,
				"phone":       req.Phone,
				"middle_name": req.MiddleName,
			},
			Blocked: true,
		}

		honeypot.RecordHoneypotAttempt(ctx.DB, honeypotAttempt)
		log.Printf("2FA login honeypot triggered from IP: %s, email: %s", ip, req.Email)

		// Return fake success to confuse bots - with a small delay
		time.Sleep(500 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid email format"})
		return
	}

	emailAddr := strings.ToLower(req.Email)

	isLocked, remainingTime, isBlocked := ctx.LoginTracker.CheckAccountStatus(emailAddr)

	if isBlocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("account_blocked")})
		return
	}

	if isLocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(ErrorResponse{
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
	err := ctx.DB.QueryRowContext(ctxDB, `SELECT id, password_hash, totp_secret, totp_enabled FROM Users WHERE email = $1`, emailAddr).
		Scan(&userID, &passwordHash, &encryptedTotpSecret, &totpEnabled)
	if err != nil {
		if err == sql.ErrNoRows {
			ip := GetClientIP(r)
			ctx.LoginTracker.RecordFailedAttempt(emailAddr, ip)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
			return
		}

		log.Printf("Database error during 2FA login: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
		return
	}

	passwordValid, err := cryptography.VerifyPassword(req.Password, passwordHash)
	if err != nil {
		log.Printf("Error verifying password during 2FA login: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	if !passwordValid {
		ip := GetClientIP(r)
		isLocked, lockDuration, isBlocked, _ := ctx.LoginTracker.RecordFailedAttempt(emailAddr, ip)

		log.Printf("Failed 2FA login attempt for user: %s from IP: %s", emailAddr, ip)

		if isBlocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("account_blocked")})
			return
		}

		if isLocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(ErrorResponse{
				Message: validation.GetSanitizedError("account_locked"),
			})
			log.Printf("Account locked after failed 2FA login: %s, duration: %v", emailAddr, lockDuration)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
		return
	}

	if !totpEnabled || encryptedTotpSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
		return
	}

	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Validation failed"})
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, req.Code, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Validation failed"})
		return
	}

	if !valid {
		ip := GetClientIP(r)
		isLocked, lockDuration, isBlocked, _ := ctx.LoginTracker.RecordFailedAttempt(emailAddr, ip)

		log.Printf("Invalid 2FA code for user: %s from IP: %s", emailAddr, ip)

		if isBlocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("account_blocked")})
			return
		}

		if isLocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(ErrorResponse{
				Message: validation.GetSanitizedError("account_locked"),
			})
			log.Printf("Account locked after invalid 2FA code: %s, duration: %v", emailAddr, lockDuration)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid 2FA code"})
		return
	}

	ctx.LoginTracker.ResetAttempts(emailAddr)

	token, err := jwt_auth.GenerateToken(userID, emailAddr)
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to complete login"})
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

	response := map[string]interface{}{
		"message":    "Login successful",
		"token":      token,
		"user_id":    userID,
		"email":      emailAddr,
		"expires_in": jwt_auth.GetTokenExpiration().Seconds(),
	}

	// Include E2EE keys if they exist
	if publicKey != "" {
		response["e2ee_public_key"] = publicKey
	}
	if privateKeyEncrypted != "" {
		response["e2ee_private_key_encrypted"] = privateKeyEncrypted
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
