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
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, _, ok := requireAuth(w, r)
	if !ok {
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey, privateKeyEncrypted string
	err := ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, ''), COALESCE(e2ee_private_key_encrypted, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey, &privateKeyEncrypted)
	if err != nil {
		log.Printf("Failed to get E2EE keys for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve E2EE keys")
		return
	}

	if publicKey == "" || privateKeyEncrypted == "" {
		writeError(w, http.StatusNotFound, "E2EE keys not found - please re-register your account")
		return
	}

	writeJSON(w, http.StatusOK, E2EEKeysResponse{
		PublicKey:           publicKey,
		PrivateKeyEncrypted: privateKeyEncrypted,
	})
}

func E2EEConfigHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	_, _, ok := requireAuth(w, r)
	if !ok {
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"pepper": ctx.E2EEPepper,
	})
}

func GetUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	_, _, ok := requireAuth(w, r)
	if !ok {
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		writeError(w, http.StatusBadRequest, "Email parameter is required")
		return
	}

	if !validation.ValidateEmail(email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err := ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(email)).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("Failed to get public key for user %s: %v", email, err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve public key")
		return
	}

	if publicKey == "" {
		writeError(w, http.StatusNotFound, "User does not have E2EE keys configured")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"e2ee_public_key": publicKey,
	})
}

func UpdateUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	userID, userEmail, ok := requireAuth(w, r)
	if !ok {
		return
	}

	var req struct {
		E2EEPublicKey string `json:"e2ee_public_key"`
		CSRFToken     string `json:"csrf_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	if req.E2EEPublicKey == "" {
		writeError(w, http.StatusBadRequest, "Public key is required")
		return
	}

	if !ctx.CSRFStore.ValidateToken(userEmail, req.CSRFToken) {
		writeError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err := ctx.DB.ExecContext(ctxDB,
		"UPDATE Users SET e2ee_public_key = $1 WHERE id = $2",
		req.E2EEPublicKey, userID)
	if err != nil {
		log.Printf("Failed to update public key for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to update public key")
		return
	}

	log.Printf("Updated E2EE public key for user %d", userID)
	writeMessage(w, http.StatusOK, "Public key updated successfully")
}

func CSRFTokenHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, userEmail, ok := requireAuth(w, r)
	if !ok {
		return
	}

	token, err := ctx.CSRFStore.CreateToken(userEmail, 15*time.Minute)
	if err != nil {
		log.Printf("Failed to create CSRF token for user %d: %v", userID, err)
		writeError(w, http.StatusInternalServerError, "Failed to generate CSRF token")
		return
	}

	writeJSON(w, http.StatusOK, CSRFTokenResponse{Token: token})
}

func GetE2EEFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, _, ok := requireAuth(w, r)
	if !ok {
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err := ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey)
	if err != nil || publicKey == "" {
		writeError(w, http.StatusNotFound, "E2EE not configured")
		return
	}

	hash := sha256.Sum256([]byte(publicKey))
	fingerprint := hex.EncodeToString(hash[:])

	writeJSON(w, http.StatusOK, map[string]string{
		"fingerprint": fingerprint,
	})
}

func GetUserFingerprintHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	_, _, ok := requireAuth(w, r)
	if !ok {
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		writeError(w, http.StatusBadRequest, "Email parameter is required")
		return
	}

	if !validation.ValidateEmail(email) {
		writeError(w, http.StatusBadRequest, "Invalid email format")
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err := ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(email)).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		log.Printf("Failed to get public key for fingerprint: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve fingerprint")
		return
	}

	if publicKey == "" {
		writeError(w, http.StatusNotFound, "User does not have E2EE configured")
		return
	}

	hash := sha256.Sum256([]byte(publicKey))
	fingerprint := hex.EncodeToString(hash[:])

	writeJSON(w, http.StatusOK, map[string]string{
		"email":       strings.ToLower(email),
		"fingerprint": fingerprint,
	})
}
