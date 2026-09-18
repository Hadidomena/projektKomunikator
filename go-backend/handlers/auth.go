package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/honeypot"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/validation"
	"github.com/lib/pq"
)

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var req RegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
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

		writeMessage(w, http.StatusCreated, "User registered successfully")
		return
	}

	if req.Username == "" || req.Email == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	if !validation.ValidateEmail(req.Email) {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	emailExists, err := validation.CheckEmailExists(ctx.DB, req.Email)
	if err != nil {
		log.Printf("Error checking email existence: %v", err)
		writeError(w, http.StatusInternalServerError, validation.GetSanitizedError("registration_failed"))
		return
	}

	if emailExists {
		writeError(w, http.StatusConflict, validation.GetSanitizedError("registration_failed"))
		return
	}

	if passwordutils.IsViablePassword(req.Password) != 0 {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	ctx2, cancel2 := context.WithTimeout(r.Context(), 10*time.Second)
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
		writeError(w, http.StatusRequestTimeout, validation.GetSanitizedError("registration_failed"))
		log.Printf("Password hashing timeout")
		return
	case result := <-hashChan:
		if result.err != nil {
			log.Printf("Error hashing password: %v", result.err)
			writeError(w, http.StatusInternalServerError, validation.GetSanitizedError("registration_failed"))
			return
		}
		hashedPassword = result.hash
	}

	publicKey := req.E2EEPublicKey
	privateKeyEncrypted := req.E2EEPrivateKeyEncrypted
	if publicKey == "" {
		log.Printf("Warning: No E2EE public key provided during registration for %s", req.Email)
	}
	if privateKeyEncrypted == "" {
		log.Printf("Warning: No E2EE private key provided during registration for %s", req.Email)
	}

	var userID int
	err = ctx.DB.QueryRowContext(ctx2,
		"INSERT INTO Users (username, email, password_hash, e2ee_public_key, e2ee_private_key_encrypted) VALUES ($1, $2, $3, $4, $5) RETURNING id",
		req.Username, strings.ToLower(req.Email), hashedPassword, publicKey, privateKeyEncrypted).Scan(&userID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			writeError(w, http.StatusConflict, validation.GetSanitizedError("registration_failed"))
			return
		}

		if ctx2.Err() == context.DeadlineExceeded {
			writeError(w, http.StatusRequestTimeout, validation.GetSanitizedError("registration_failed"))
			log.Printf("Database operation timeout: %v", err)
			return
		}

		log.Printf("Failed to insert user into database: %v", err)
		writeError(w, http.StatusInternalServerError, validation.GetSanitizedError("registration_failed"))
		return
	}

	log.Printf("User registered successfully: %s (ID: %d)", req.Email, userID)

	writeMessage(w, http.StatusCreated, "User registered successfully")
}

func CheckPasswordStrengthHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	var req struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	strength := passwordutils.GetPasswordStrength(req.Password)

	writeJSON(w, http.StatusOK, strength)
}
