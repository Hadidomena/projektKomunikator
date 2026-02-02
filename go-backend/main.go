package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/csrf"
	"github.com/Hadidomena/projektKomunikator/handlers"
	jwt_auth "github.com/Hadidomena/projektKomunikator/jwt_auth"
	"github.com/Hadidomena/projektKomunikator/middleware"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/totp"
	"github.com/Hadidomena/projektKomunikator/validation"
	_ "github.com/lib/pq"
)

type SendMessageRequest struct {
	ReceiverEmail string       `json:"receiver_email"`
	Content       string       `json:"content"`
	Signature     string       `json:"signature,omitempty"`
	CSRFToken     string       `json:"csrf_token"`
	Attachments   []Attachment `json:"attachments,omitempty"`
	DHPublicKey   string       `json:"dh_public_key,omitempty"`
}

type E2EEKeysResponse struct {
	PublicKey           string `json:"public_key"`
	PrivateKeyEncrypted string `json:"private_key_encrypted"`
}

type MessageResponse struct {
	ID                int          `json:"id"`
	SenderEmail       string       `json:"sender_email"`
	ReceiverEmail     string       `json:"receiver_email"`
	Content           string       `json:"content"`
	Signature         string       `json:"signature,omitempty"`
	IsRead            bool         `json:"is_read"`
	CreatedAt         time.Time    `json:"created_at"`
	ReadAt            *time.Time   `json:"read_at,omitempty"`
	Attachments       []Attachment `json:"attachments,omitempty"`
	DHPublicKey       string       `json:"dh_public_key,omitempty"`
	ReceiverPublicKey string       `json:"receiver_public_key,omitempty"`
}

// Attachment represents a file attachment in a message
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        string `json:"data"`
}

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
}

type CSRFTokenResponse struct {
	Token string `json:"csrf_token"`
}

var db *sql.DB
var csrfStore *csrf.TokenStore
var loginTracker *validation.LoginAttemptTracker

func init() {
	appPepper := os.Getenv("PEPPER")
	if appPepper == "" {
		log.Fatal("SECURITY ERROR: PEPPER environment variable not set")
	}
	cryptography.SetPepper(appPepper)
	encryptionSecret := os.Getenv("ENCRYPTION_SECRET")
	if encryptionSecret == "" {
		log.Fatal("SECURITY ERROR: ENCRYPTION_SECRET environment variable not set")
	}
	if err := cryptography.InitializeEncryptionKey(encryptionSecret); err != nil {
		log.Fatalf("Failed to initialize encryption key: %v", err)
	}
}

func main() {
	var err error
	sslMode := os.Getenv("DB_SSLMODE")
	if sslMode == "" {
		sslMode = "require"
	}
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		sslMode)

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	csrfStore = csrf.NewTokenStore()
	loginTracker = validation.NewLoginAttemptTracker()

	handlers.Initialize(db, csrfStore, loginTracker)

	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	if err := passwordutils.LoadCommonPasswords(); err != nil {
		log.Printf("Warning: Could not load common passwords: %v", err)
	}

	if err := jwt_auth.InitJWT(); err != nil {
		log.Fatalf("Failed to initialize JWT: %v", err)
	}
	generalLimiter := middleware.NewRateLimiter(100, time.Minute)
	authLimiter := middleware.NewRateLimiter(10, time.Minute)

	mux := http.NewServeMux()

	mux.HandleFunc("/api/register", handlers.RegisterHandler)
	mux.HandleFunc("/api/login", handlers.LoginHandler)
	mux.HandleFunc("/api/check-password-strength", handlers.CheckPasswordStrengthHandler)
	mux.HandleFunc("/api/csrf-token", authMiddleware(csrfTokenHandler))
	mux.HandleFunc("/api/2fa/status", authMiddleware(totpStatusHandler))
	mux.HandleFunc("/api/2fa/setup", authMiddleware(totpSetupHandler))
	mux.HandleFunc("/api/2fa/verify", authMiddleware(totpVerifyHandler))
	mux.HandleFunc("/api/2fa/disable", authMiddleware(totpDisableHandler))
	mux.HandleFunc("/api/2fa/validate", totpValidateHandler)
	mux.HandleFunc("/api/messages/send", authMiddleware(sendMessageHandler))
	mux.HandleFunc("/api/messages", authMiddleware(getInboxHandler))
	mux.HandleFunc("/api/messages/mark-read", authMiddleware(markMessageAsReadHandler))
	mux.HandleFunc("/api/messages/delete", authMiddleware(deleteMessageHandler))
	mux.HandleFunc("/api/messages/sent", authMiddleware(getSentMessagesHandler))
	mux.HandleFunc("/api/messages/get", authMiddleware(getMessageHandler))
	mux.HandleFunc("/api/e2ee/keys", authMiddleware(getE2EEKeysHandler))
	mux.HandleFunc("/api/user/public-key", authMiddleware(getUserPublicKeyHandler))
	mux.HandleFunc("/api/user/update-public-key", authMiddleware(updateUserPublicKeyHandler))
	mux.HandleFunc("/api/password-reset/request", handlers.PasswordResetRequestHandler)
	mux.HandleFunc("/api/password-reset/verify", handlers.PasswordResetVerifyHandler)
	mux.HandleFunc("/api/login-history", authMiddleware(loginHistoryHandler))
	mux.HandleFunc("/api/admin/honeypot-stats", authMiddleware(honeypotStatsHandler))

	conditionalRateLimiter := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/login") ||
			strings.HasPrefix(r.URL.Path, "/api/register") ||
			strings.HasPrefix(r.URL.Path, "/api/password-reset") {
			authLimiter.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mux.ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		} else {
			generalLimiter.RateLimitMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mux.ServeHTTP(w, r)
			})).ServeHTTP(w, r)
		}
	})

	handler := middleware.SecurityHeadersMiddleware(
		middleware.CORSMiddleware(conditionalRateLimiter),
	)

	fmt.Println("Go backend server starting on port 8080")
	fmt.Println("Security features enabled: CORS, Rate Limiting, Security Headers")
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid authorization header format"})
			return
		}

		tokenString := parts[1]
		claims, err := jwt_auth.ValidateToken(tokenString)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid or expired token"})
			return
		}

		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		ctx = context.WithValue(ctx, "userEmail", claims.Email)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

func loginHistoryHandler(w http.ResponseWriter, r *http.Request) {
	userID, userEmail, err := handlers.GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}
	handlers.GetLoginHistoryHandler(w, r, userID, userEmail)
}

func honeypotStatsHandler(w http.ResponseWriter, r *http.Request) {
	userID, userEmail, err := handlers.GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}
	handlers.GetHoneypotStatsHandler(w, r, userID, userEmail)
}

func getUserFromContext(r *http.Request) (int, string, error) {
	return handlers.GetUserFromContext(r)
}

func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	senderID, senderEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	var req SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !csrfStore.ValidateToken(senderEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	if req.ReceiverEmail == "" || req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !validation.ValidateEmail(req.ReceiverEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Validate message size (allow larger for attachments in base64)
	if len(req.Content) > 25*1024*1024 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Message too long (max 15MB attachments)"})
		return
	}

	// Log attachments info
	if len(req.Attachments) > 0 {
		log.Printf("Sending encrypted message with %d attachments from %s to %s", len(req.Attachments), senderEmail, req.ReceiverEmail)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var receiverID int
	var receiverPublicKey string
	err = db.QueryRowContext(ctx,
		"SELECT id, COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(req.ReceiverEmail)).Scan(&receiverID, &receiverPublicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Receiver not found"})
			return
		}
		log.Printf("Failed to get receiver: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to send message"})
		return
	}

	// Check if receiver has E2EE keys
	if receiverPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Receiver doesn't have E2EE keys - they need to re-register or update their account"})
		return
	}

	// Get sender's public key
	var senderPublicKey string
	err = db.QueryRowContext(ctx,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE id = $1",
		senderID).Scan(&senderPublicKey)
	if err != nil || senderPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "You don't have E2EE keys - please re-register or update your account"})
		return
	}

	contentToStore := req.Content

	encKeyStr := "client-e2ee"

	var messageID int
	err = db.QueryRowContext(ctx,
		"INSERT INTO Messages (sender_id, receiver_id, content, encrypted_key, message_signature, dh_public_key) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		senderID, receiverID, contentToStore, encKeyStr, req.Signature, req.DHPublicKey).Scan(&messageID)
	if err != nil {
		log.Printf("Failed to insert message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to send message"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Message sent successfully",
		"message_id": messageID,
		"encrypted":  true,
	})
}

// getInboxHandler retrieves inbox messages for the authenticated user
func getInboxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT m.id, u.email, m.content, m.message_signature, m.is_read, m.created_at, m.read_at,
		       COALESCE(m.dh_public_key, '')
		FROM Messages m
		JOIN Users u ON m.sender_id = u.id
		WHERE m.receiver_id = $1 AND m.is_deleted_by_receiver = FALSE
		ORDER BY m.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to get messages: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to retrieve messages"})
		return
	}
	defer rows.Close()

	messages := []MessageResponse{}
	for rows.Next() {
		var msg MessageResponse
		var senderEmail string
		var signature sql.NullString
		err := rows.Scan(&msg.ID, &senderEmail, &msg.Content, &signature, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt,
			&msg.DHPublicKey)
		if err != nil {
			log.Printf("Failed to scan message: %v", err)
			continue
		}
		msg.SenderEmail = senderEmail
		msg.ReceiverEmail = userEmail
		if signature.Valid {
			msg.Signature = signature.String
		}
		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(messages)
}

// getSentMessagesHandler retrieves sent messages for the authenticated user
func getSentMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT m.id, u.email, m.content, m.is_read, m.created_at, m.read_at,
		       COALESCE(m.dh_public_key, ''), COALESCE(u.e2ee_public_key, '')
		FROM Messages m
		JOIN Users u ON m.receiver_id = u.id
		WHERE m.sender_id = $1 AND m.is_deleted_by_sender = FALSE
		ORDER BY m.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to get sent messages: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to retrieve messages"})
		return
	}
	defer rows.Close()

	messages := []MessageResponse{}
	for rows.Next() {
		var msg MessageResponse
		var receiverEmail string
		var receiverPublicKey string
		err := rows.Scan(&msg.ID, &receiverEmail, &msg.Content, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt,
			&msg.DHPublicKey, &receiverPublicKey)
		if err != nil {
			log.Printf("Failed to scan message: %v", err)
			continue
		}
		msg.SenderEmail = userEmail
		msg.ReceiverEmail = receiverEmail
		msg.ReceiverPublicKey = receiverPublicKey
		messages = append(messages, msg)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(messages)
}

// markMessageAsReadHandler marks a message as read
func markMessageAsReadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if req.MessageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := db.ExecContext(ctx,
		"UPDATE Messages SET is_read = TRUE, read_at = NOW() WHERE id = $1 AND receiver_id = $2 AND is_read = FALSE",
		req.MessageID, userID)
	if err != nil {
		log.Printf("Failed to mark message as read: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to mark message as read"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Message not found or already read"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Message marked as read",
	})
}

// getMessageHandler retrieves a single message with decrypted content and attachments
func getMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	messageIDStr := r.URL.Query().Get("id")
	if messageIDStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Message ID required"})
		return
	}

	messageID, err := strconv.Atoi(messageIDStr)
	if err != nil || messageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid message ID"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var msg MessageResponse
	var senderEmail, receiverEmail string
	var senderID, receiverID int
	var encryptedKey sql.NullString
	var signature sql.NullString
	var receiverPublicKey string

	err = db.QueryRowContext(ctx, `
		SELECT m.id, m.sender_id, u1.email, m.receiver_id, u2.email, 
		       m.content, m.encrypted_key, m.message_signature,
		       m.is_read, m.created_at, m.read_at, COALESCE(m.dh_public_key, ''),
		       COALESCE(u2.e2ee_public_key, '')
		FROM Messages m
		JOIN Users u1 ON m.sender_id = u1.id
		JOIN Users u2 ON m.receiver_id = u2.id
		WHERE m.id = $1 
		  AND (m.sender_id = $2 OR m.receiver_id = $2)
		  AND ((m.sender_id = $2 AND m.is_deleted_by_sender = FALSE) 
		       OR (m.receiver_id = $2 AND m.is_deleted_by_receiver = FALSE))
	`, messageID, userID).Scan(
		&msg.ID, &senderID, &senderEmail, &receiverID, &receiverEmail,
		&msg.Content, &encryptedKey, &signature,
		&msg.IsRead, &msg.CreatedAt, &msg.ReadAt, &msg.DHPublicKey, &receiverPublicKey,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Message not found"})
			return
		}
		log.Printf("Failed to get message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to retrieve message"})
		return
	}

	msg.SenderEmail = senderEmail
	msg.ReceiverEmail = receiverEmail
	msg.ReceiverPublicKey = receiverPublicKey
	if signature.Valid {
		msg.Signature = signature.String
	}

	if !(encryptedKey.Valid && encryptedKey.String == "client-e2ee") {
		fmt.Printf("Warning: Message %d is not marked as encrypted\n", msg.ID)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(msg)
}

func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if req.MessageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := db.ExecContext(ctx, `
		UPDATE Messages 
		SET is_deleted_by_sender = CASE WHEN sender_id = $2 THEN TRUE ELSE is_deleted_by_sender END,
		    is_deleted_by_receiver = CASE WHEN receiver_id = $2 THEN TRUE ELSE is_deleted_by_receiver END
		WHERE id = $1 AND (sender_id = $2 OR receiver_id = $2)
	`, req.MessageID, userID)
	if err != nil {
		log.Printf("Failed to delete message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to delete message"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Message not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Message deleted successfully",
	})
}

func getE2EEKeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey, privateKeyEncrypted string
	err = db.QueryRowContext(ctx,
		"SELECT COALESCE(e2ee_public_key, ''), COALESCE(e2ee_private_key_encrypted, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey, &privateKeyEncrypted)
	if err != nil {
		log.Printf("Failed to get E2EE keys for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to retrieve E2EE keys"})
		return
	}

	if publicKey == "" || privateKeyEncrypted == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "E2EE keys not found - please re-register your account"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(E2EEKeysResponse{
		PublicKey:           publicKey,
		PrivateKeyEncrypted: privateKeyEncrypted,
	})
}

// getUserPublicKeyHandler returns the public E2EE key for a specified user (by email)
func getUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	email := r.URL.Query().Get("email")
	if email == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Email parameter is required"})
		return
	}

	if !validation.ValidateEmail(email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid email format"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	var publicKey string
	err = db.QueryRowContext(ctx,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(email)).Scan(&publicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "User not found"})
			return
		}
		log.Printf("Failed to get public key for user %s: %v", email, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to retrieve public key"})
		return
	}

	if publicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "User does not have E2EE keys configured"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"e2ee_public_key": publicKey,
	})
}

// updateUserPublicKeyHandler allows a user to update their E2EE public key
func updateUserPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		E2EEPublicKey string `json:"e2ee_public_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid request"})
		return
	}

	if req.E2EEPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Public key is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	_, err = db.ExecContext(ctx,
		"UPDATE Users SET e2ee_public_key = $1 WHERE id = $2",
		req.E2EEPublicKey, userID)
	if err != nil {
		log.Printf("Failed to update public key for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to update public key"})
		return
	}

	log.Printf("Updated E2EE public key for user %d", userID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Public key updated successfully",
	})
}

// csrfTokenHandler generates and returns a new CSRF token
func csrfTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}

	token, err := csrfStore.CreateToken(userEmail, csrf.DefaultExpiration)
	if err != nil {
		log.Printf("Failed to create CSRF token for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to generate CSRF token"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(CSRFTokenResponse{Token: token})
}

// totpStatusHandler returns the 2FA status for a user
func totpStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}

	var totpEnabled bool
	var totpSecret sql.NullString
	err = db.QueryRow(`SELECT totp_enabled, totp_secret FROM Users WHERE id = $1`, userID).Scan(&totpEnabled, &totpSecret)
	if err != nil {
		log.Printf("Failed to get 2FA status for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to get 2FA status"})
		return
	}

	// Check if setup is in progress (secret exists but not enabled)
	setupInProgress := totpSecret.Valid && totpSecret.String != "" && !totpEnabled

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"enabled":           totpEnabled,
		"setup_in_progress": setupInProgress,
	})
}

// totpSetupHandler initiates 2FA setup for a user
func totpSetupHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}

	var req TOTPSetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid request body"})
		return
	}

	if req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Password is required to secure the 2FA secret"})
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		log.Printf("Failed to generate TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to generate 2FA secret"})
		return
	}

	encryptedSecretForDB, err := cryptography.EncryptSensitiveData(secret)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	_, err = db.Exec(`UPDATE Users SET totp_secret = $1 WHERE id = $2`, encryptedSecretForDB, userID)
	if err != nil {
		log.Printf("Failed to store TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	encryptedSecretForUser, err := cryptography.EncryptForUser(secret, req.Password, userID)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for transmission to user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	qrCodeURL := totp.GenerateQRCodeURL(userEmail, "Komunikator", secret)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"secret":           secret,
		"encrypted_secret": encryptedSecretForUser,
		"qr_code":          qrCodeURL, // QR code URL for authenticator app
	})
}

// totpVerifyHandler verifies and enables 2FA for a user
func totpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid request body"})
		return
	}

	if !csrfStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	var encryptedTotpSecret string
	err = db.QueryRow(`SELECT totp_secret FROM Users WHERE id = $1`, userID).Scan(&encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to retrieve TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "2FA not setup"})
		return
	}

	if encryptedTotpSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Please setup 2FA first"})
		return
	}

	// Decrypt TOTP secret
	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to verify 2FA"})
		return
	}

	// Accept either 'code' or 'totp_code' from the request
	verificationCode := req.Code
	if verificationCode == "" {
		verificationCode = req.TOTPCode
	}

	if verificationCode == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Verification code is required"})
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, verificationCode, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Validation failed"})
		return
	}

	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid 2FA code"})
		return
	}

	_, err = db.Exec(`UPDATE Users SET totp_enabled = TRUE, totp_verified_at = NOW() WHERE id = $1`, userID)
	if err != nil {
		log.Printf("Failed to enable 2FA for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to enable 2FA"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA enabled successfully"})
}

// totpDisableHandler disables 2FA for a user
func totpDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Unauthorized"})
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid request body"})
		return
	}

	if !csrfStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	_, err = db.Exec(`UPDATE Users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, userID)
	if err != nil {
		log.Printf("Failed to disable 2FA for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to disable 2FA"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA disabled successfully"})
}

// totpValidateHandler validates a TOTP code during login
func totpValidateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Method not allowed"})
		return
	}

	var req TOTPValidateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid request body"})
		return
	}

	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid email format"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var userID int
	var encryptedTotpSecret string
	var totpEnabled bool
	var passwordHash string
	err := db.QueryRowContext(ctx, `SELECT id, password_hash, totp_secret, totp_enabled FROM Users WHERE email = $1`, strings.ToLower(req.Email)).
		Scan(&userID, &passwordHash, &encryptedTotpSecret, &totpEnabled)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid credentials"})
		return
	}

	// Verify password
	passwordValid, err := cryptography.VerifyPassword(req.Password, passwordHash)
	if err != nil || !passwordValid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid credentials"})
		return
	}

	if !totpEnabled || encryptedTotpSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "2FA not enabled"})
		return
	}

	// Decrypt TOTP secret
	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Validation failed"})
		return
	}

	valid, err := totp.ValidateTOTP(totpSecret, req.Code, totp.DefaultConfig())
	if err != nil {
		log.Printf("Failed to validate TOTP for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Validation failed"})
		return
	}

	if !valid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Invalid 2FA code"})
		return
	}

	// Generate JWT token after successful 2FA verification
	token, err := jwt_auth.GenerateToken(userID, strings.ToLower(req.Email))
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(handlers.ErrorResponse{Message: "Failed to complete login"})
		return
	}

	// Get E2EE keys for the user
	var publicKey, privateKeyEncrypted string
	err = db.QueryRowContext(ctx,
		"SELECT COALESCE(e2ee_public_key, ''), COALESCE(e2ee_private_key_encrypted, '') FROM Users WHERE id = $1",
		userID).Scan(&publicKey, &privateKeyEncrypted)
	if err != nil {
		log.Printf("Failed to get E2EE keys for user %d during 2FA login: %v", userID, err)
	}

	log.Printf("Successful 2FA login for user: %s", req.Email)

	response := map[string]interface{}{
		"message":    "Login successful",
		"token":      token,
		"user_id":    userID,
		"email":      strings.ToLower(req.Email),
		"expires_in": jwt_auth.GetTokenExpiration().Seconds(),
	}

	// Include E2EE keys if they exist
	if publicKey != "" && privateKeyEncrypted != "" {
		response["e2ee_public_key"] = publicKey
		decryptedPrivateKey, err := cryptography.DecryptForUser(privateKeyEncrypted, req.Password, userID)
		if err != nil {
			log.Printf("Warning: Failed to decrypt E2EE private key for user %d during 2FA: %v", userID, err)
			response["e2ee_private_key_encrypted"] = privateKeyEncrypted
		} else {
			response["e2ee_private_key"] = decryptedPrivateKey
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
