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
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
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
		log.Printf("Login honeypot triggered from IP: %s, email: %s", ip, req.Email)

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
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
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
		log.Printf("Login attempt for locked account: %s, remaining time: %v", emailAddr, remainingTime)
		return
	}

	ctx2, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var storedHash string
	var userID int
	var totpEnabled bool
	err := ctx.DB.QueryRowContext(ctx2, "SELECT id, password_hash, totp_enabled FROM Users WHERE email = $1", emailAddr).Scan(&userID, &storedHash, &totpEnabled)

	if err != nil {
		if err == sql.ErrNoRows {
			ip := r.RemoteAddr
			ctx.LoginTracker.RecordFailedAttempt(emailAddr, ip)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
			return
		}

		log.Printf("Database error during login: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	passwordValid, err := cryptography.VerifyPassword(req.Password, storedHash)
	if err != nil {
		log.Printf("Error verifying password: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	if !passwordValid {
		ip := r.RemoteAddr
		isLocked, lockDuration, isBlocked, _ := ctx.LoginTracker.RecordFailedAttempt(emailAddr, ip)

		log.Printf("Failed login attempt for user: %s from IP: %s", emailAddr, ip)

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
			log.Printf("Account locked: %s, duration: %v", emailAddr, lockDuration)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	ctx.LoginTracker.ResetAttempts(emailAddr)

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

	// Check if 2FA is enabled
	if totpEnabled {
		log.Printf("2FA required for user: %s", emailAddr)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":       "2FA verification required",
			"requires_totp": true,
		})
		return
	}

	token, err := jwt_auth.GenerateToken(userID, emailAddr)
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to complete login"})
		return
	}

	log.Printf("Successful login for user: %s", emailAddr)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Login successful",
		"token":      token,
		"user_id":    userID,
		"email":      emailAddr,
		"expires_in": jwt_auth.GetTokenExpiration().Seconds(),
	})
}
