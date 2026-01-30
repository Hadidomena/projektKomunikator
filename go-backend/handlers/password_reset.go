package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/email"
	"github.com/Hadidomena/projektKomunikator/password_reset"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/validation"
)

func PasswordResetRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req PasswordResetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request"})
		return
	}

	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists, a reset link has been sent"})
		return
	}

	emailAddr := strings.ToLower(req.Email)

	var userID int
	err := ctx.DB.QueryRow("SELECT id FROM Users WHERE email = $1", emailAddr).Scan(&userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists, a reset link has been sent"})
		return
	}

	resetToken, err := password_reset.GenerateResetToken(userID)
	if err != nil {
		log.Printf("Error generating reset token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to process request"})
		return
	}

	// Hash token before storing in database (like passwords)
	hashedToken, err := cryptography.HashPassword(resetToken.Token)
	if err != nil {
		log.Printf("Error hashing reset token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to process request"})
		return
	}

	_, err = ctx.DB.Exec(`
		INSERT INTO PasswordResetTokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, resetToken.UserID, hashedToken, resetToken.ExpiresAt)

	if err != nil {
		log.Printf("Error storing reset token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to process request"})
		return
	}

	go email.SendPasswordResetEmail(emailAddr, resetToken.Token)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "If the email exists, a reset link has been sent"})
}

func PasswordResetVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	var req PasswordResetVerify
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request"})
		return
	}

	if req.Token == "" || req.NewPassword == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Token and password required"})
		return
	}

	if passwordutils.IsViablePassword(req.NewPassword) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Password does not meet requirements"})
		return
	}

	// Retrieve all non-expired, unused tokens and verify by comparing hashes
	rows, err := ctx.DB.Query(`
		SELECT user_id, token, expires_at, used, created_at
		FROM PasswordResetTokens
		WHERE used = FALSE AND expires_at > NOW()
	`)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid or expired token"})
		return
	}
	defer rows.Close()

	var storedToken password_reset.ResetToken
	var hashedToken string
	found := false

	// Compare provided token with hashed tokens in database
	for rows.Next() {
		if err := rows.Scan(&storedToken.UserID, &hashedToken, &storedToken.ExpiresAt, &storedToken.Used, &storedToken.CreatedAt); err != nil {
			continue
		}

		// Verify token hash (like password verification)
		match, err := cryptography.VerifyPassword(req.Token, hashedToken)
		if err != nil {
			continue
		}

		if match {
			storedToken.Token = req.Token
			found = true
			break
		}
	}

	if !found {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid or expired token"})
		return
	}

	if err := password_reset.ValidateToken(req.Token, &storedToken); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid or expired token"})
		return
	}

	hashedPassword, err := cryptography.HashPassword(req.NewPassword)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
		return
	}

	_, err = ctx.DB.Exec(`UPDATE Users SET password_hash = $1 WHERE id = $2`, hashedPassword, storedToken.UserID)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
		return
	}

	// Mark token as used by hashing it again with a timestamp (prevents reuse)
	_, err = ctx.DB.Exec(`UPDATE PasswordResetTokens SET used = TRUE, used_at = $1 WHERE user_id = $2 AND token = $3`,
		time.Now(), storedToken.UserID, hashedToken)
	if err != nil {
		log.Printf("Error marking token as used: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successful"})
}
