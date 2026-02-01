package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/e2ee"
	"github.com/Hadidomena/projektKomunikator/honeypot"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/validation"
	"github.com/lib/pq"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if honeypot.CheckHoneypot(req.Website) {
		ip := GetClientIP(r)
		honeypotAttempt := &honeypot.HoneypotAttempt{
			IPAddress:     ip,
			UserAgent:     r.UserAgent(),
			HoneypotField: "website",
			HoneypotValue: req.Website,
			SubmittedData: map[string]interface{}{
				"username": req.Username,
				"email":    req.Email,
			},
			Blocked: true,
		}

		honeypot.RecordHoneypotAttempt(ctx.DB, honeypotAttempt)

		log.Printf("Honeypot triggered from IP: %s, email: %s", ip, req.Email)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	ctx2, cancel2 := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel2()

	emailExists, err := validation.CheckEmailExists(ctx.DB, req.Email)
	if err != nil {
		log.Printf("Error checking email existence: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	if emailExists {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	if passwordutils.IsViablePassword(req.Password) != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	ctx2, cancel2 = context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel2()

	type hashResult struct {
		hash string
		err  error
	}
	hashChan := make(chan hashResult, 1)

	go func() {
		hashedPassword, err := cryptography.HashPassword(req.Password)
		hashChan <- hashResult{hash: hashedPassword, err: err}
	}()

	var hashedPassword string
	select {
	case <-ctx2.Done():
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		log.Printf("Password hashing timeout")
		return
	case result := <-hashChan:
		if result.err != nil {
			log.Printf("Error hashing password: %v", result.err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
			return
		}
		hashedPassword = result.hash
	}

	// Generate E2EE keys for the user
	deviceKeys, err := e2ee.GenerateDeviceKeys(0, "user-keys")
	if err != nil {
		log.Printf("Failed to generate E2EE keys: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	// First insert user to get the real userID (without E2EE keys)
	var userID int
	err = ctx.DB.QueryRowContext(ctx2,
		"INSERT INTO Users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
		req.Username, strings.ToLower(req.Email), hashedPassword).Scan(&userID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
			return
		}

		if ctx2.Err() == context.DeadlineExceeded {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestTimeout)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
			log.Printf("Database operation timeout: %v", err)
			return
		}

		log.Printf("Failed to insert user into database: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	encryptedPrivateKey, err := cryptography.EncryptForUser(deviceKeys.PrivateKey, req.Password, userID)
	if err != nil {
		ctx.DB.ExecContext(ctx2, "DELETE FROM Users WHERE id = $1", userID)
		log.Printf("Failed to encrypt private key: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	_, err = ctx.DB.ExecContext(ctx2,
		"UPDATE Users SET e2ee_public_key = $1, e2ee_private_key_encrypted = $2 WHERE id = $3",
		deviceKeys.PublicKey, encryptedPrivateKey, userID)
	if err != nil {
		ctx.DB.ExecContext(ctx2, "DELETE FROM Users WHERE id = $1", userID)
		log.Printf("Failed to update user with E2EE keys: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func CheckPasswordStrengthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request"})
		return
	}

	strength := passwordutils.GetPasswordStrength(req.Password)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(strength)
}
