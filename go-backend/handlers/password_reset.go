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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

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

	_, err = ctx.DB.Exec(`
		INSERT INTO PasswordResetTokens (user_id, token, expires_at)
		VALUES ($1, $2, $3)
	`, resetToken.UserID, resetToken.Token, resetToken.ExpiresAt)

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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

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

	var storedToken password_reset.ResetToken
	err := ctx.DB.QueryRow(`
		SELECT user_id, token, expires_at, used, created_at
		FROM PasswordResetTokens
		WHERE token = $1
	`, req.Token).Scan(&storedToken.UserID, &storedToken.Token, &storedToken.ExpiresAt, &storedToken.Used, &storedToken.CreatedAt)

	if err != nil {
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

	_, err = ctx.DB.Exec(`UPDATE PasswordResetTokens SET used = TRUE, used_at = $1 WHERE token = $2`, time.Now(), req.Token)
	if err != nil {
		log.Printf("Error marking token as used: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Password reset successful"})
}
