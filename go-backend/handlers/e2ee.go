package handlers

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/validation"
)

type E2EEKeysResponse struct {
	PublicKey           string `json:"public_key"`
	PrivateKeyEncrypted string `json:"private_key_encrypted"`
}

type CSRFTokenResponse struct {
	Token string `json:"csrf_token"`
}

func GetE2EEKeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey, privateKeyEncrypted string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, ''), COALESCE(e2ee_private_key_encrypted, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey, &privateKeyEncrypted)
	if err != nil {
		log.Printf("Failed to get E2EE keys for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve E2EE keys"})
		return
	}

	if publicKey == "" || privateKeyEncrypted == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "E2EE keys not found - please re-register your account"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(E2EEKeysResponse{
		PublicKey:           publicKey,
		PrivateKeyEncrypted: privateKeyEncrypted,
	})
}

func E2EEConfigHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"pepper": ctx.E2EEPepper,
	})
}

func GetUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Email parameter is required"})
		return
	}

	if !validation.ValidateEmail(email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid email format"})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(email)).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "User not found"})
			return
		}
		log.Printf("Failed to get public key for user %s: %v", email, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve public key"})
		return
	}

	if publicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "User does not have E2EE keys configured"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"e2ee_public_key": publicKey,
	})
}

func UpdateUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		E2EEPublicKey string `json:"e2ee_public_key"`
		CSRFToken     string `json:"csrf_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request"})
		return
	}

	if req.E2EEPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Public key is required"})
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err = ctx.DB.ExecContext(ctxDB,
		"UPDATE Users SET e2ee_public_key = $1 WHERE id = $2",
		req.E2EEPublicKey, userID)
	if err != nil {
		log.Printf("Failed to update public key for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to update public key"})
		return
	}

	log.Printf("Updated E2EE public key for user %d", userID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Public key updated successfully",
	})
}

type UserKeysRequest struct {
	UserID int    `json:"user_id"`
	Token  string `json:"token"`
	Keys   struct {
		PublicKey   string `json:"public_key"`
		PrivateKey  string `json:"private_key"`
		Signature   string `json:"signature"`
		PublicKeyID string `json:"public_key_id"`
	} `json:"keys"`
}

type CSRFTokenRequest struct {
	Token string `json:"csrf_token"`
}

func CSRFTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
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

	token, err := ctx.CSRFStore.CreateToken(userEmail, 15*time.Minute)
	if err != nil {
		log.Printf("Failed to create CSRF token for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to generate CSRF token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CSRFTokenResponse{Token: token})
}

func GetE2EEFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey)
	if err != nil || publicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "E2EE not configured"})
		return
	}

	hash := sha256.Sum256([]byte(publicKey))
	fingerprint := hex.EncodeToString(hash[:])

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"fingerprint": fingerprint,
	})
}

func GetUserFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Email parameter is required"})
		return
	}

	if !validation.ValidateEmail(email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid email format"})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(email)).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "User not found"})
			return
		}
		log.Printf("Failed to get public key for fingerprint: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve fingerprint"})
		return
	}

	if publicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "User does not have E2EE configured"})
		return
	}

	hash := sha256.Sum256([]byte(publicKey))
	fingerprint := hex.EncodeToString(hash[:])

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"email":       strings.ToLower(email),
		"fingerprint": fingerprint,
	})
}
