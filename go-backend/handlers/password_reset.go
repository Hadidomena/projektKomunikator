package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

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

	hashedToken := password_reset.HashToken(resetToken.Token)

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

	if passwordutils.IsViablePassword(req.NewPassword) != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Password does not meet requirements"})
		return
	}

	hashedToken := password_reset.HashToken(req.Token)

	tx, err := ctx.DB.Begin()
	if err != nil {
		log.Printf("Error starting password reset transaction: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
		return
	}
	defer tx.Rollback()

	var userID int
	err = tx.QueryRow(`
		UPDATE PasswordResetTokens
		SET used = TRUE, used_at = NOW()
		WHERE token = $1 AND used = FALSE AND expires_at > NOW()
		RETURNING user_id
	`, hashedToken).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid or expired token"})
			return
		}
		log.Printf("Error consuming reset token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
		return
	}

	_, err = tx.Exec(`
		UPDATE PasswordResetTokens
		SET used = TRUE, used_at = NOW()
		WHERE user_id = $1 AND used = FALSE
	`, userID)
	if err != nil {
		log.Printf("Error invalidating outstanding reset tokens: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
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

	_, err = tx.Exec(
		`UPDATE Users SET password_hash = $1, failed_login_attempts = 0, locked_until = NULL, is_blocked = FALSE WHERE id = $2`,
		hashedPassword, userID)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("Error committing password reset: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to reset password"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successful"})
}
