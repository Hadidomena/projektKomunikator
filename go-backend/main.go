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

type RegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Website  string `json:"website,omitempty"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SendMessageRequest struct {
	ReceiverEmail string       `json:"receiver_email"`
	Content       string       `json:"content"`               // Encrypted content (client-side E2EE)
	Signature     string       `json:"signature,omitempty"`   // Message signature for authenticity
	CSRFToken     string       `json:"csrf_token"`            // CSRF token
	Attachments   []Attachment `json:"attachments,omitempty"` // Attachments (encrypted by client)
	// Ratcheting fields (managed by client)
	DHPublicKey         string `json:"dh_public_key,omitempty"`         // Sender's current DH public key
	MessageNumber       int    `json:"message_number,omitempty"`        // Message number in the sending chain
	PreviousChainLength int    `json:"previous_chain_length,omitempty"` // Number of messages in previous receiving chain
}

type E2EEKeysResponse struct {
	PublicKey           string `json:"public_key"`
	PrivateKeyEncrypted string `json:"private_key_encrypted"` // Encrypted with user's password
}

type MessageResponse struct {
	ID            int          `json:"id"`
	SenderEmail   string       `json:"sender_email"`
	ReceiverEmail string       `json:"receiver_email"`
	Content       string       `json:"content"` // Encrypted content (client-side E2EE)
	Signature     string       `json:"signature,omitempty"`
	IsRead        bool         `json:"is_read"`
	CreatedAt     time.Time    `json:"created_at"`
	ReadAt        *time.Time   `json:"read_at,omitempty"`
	Attachments   []Attachment `json:"attachments,omitempty"` // Encrypted by client
	// Ratcheting fields (managed by client)
	DHPublicKey         string `json:"dh_public_key,omitempty"`
	MessageNumber       int    `json:"message_number,omitempty"`
	PreviousChainLength int    `json:"previous_chain_length,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

// Attachment represents a file attachment in a message (client-side encrypted)
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        string `json:"data"` // base64 encoded, encrypted by client
}

// MessageWithAttachments represents the complete message structure (client-side encrypted)
type MessageWithAttachments struct {
	Content     string       `json:"content"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

type PasswordResetRequest struct {
	Email string `json:"email"`
}

type PasswordResetVerify struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type TOTPSetupRequest struct {
	CSRFToken string `json:"csrf_token"`
	Password  string `json:"password"` // Required: to encrypt the TOTP secret for the user
}

type TOTPSetupResponse struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code_url"`
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

type RatchetState struct {
	ID                   int    `json:"id,omitempty"`
	UserID               int    `json:"user_id,omitempty"`
	PeerUserID           int    `json:"peer_user_id"`
	RootKey              string `json:"root_key"`
	SendingChainKey      string `json:"sending_chain_key"`
	ReceivingChainKey    string `json:"receiving_chain_key"`
	SendingChainLength   int    `json:"sending_chain_length"`
	ReceivingChainLength int    `json:"receiving_chain_length"`
	PreviousChainLength  int    `json:"previous_chain_length"`
	DHPublicKey          string `json:"dh_public_key"`
	DHPeerPublicKey      string `json:"dh_peer_public_key"`
}

var db *sql.DB
var csrfStore *csrf.TokenStore
var loginTracker *validation.LoginAttemptTracker

var (
	appPepper string
)

func init() {
	appPepper := os.Getenv("PEPPER")
	if appPepper == "" {
		log.Fatal("SECURITY ERROR: PEPPER environment variable not set")
	}
	cryptography.SetPepper(appPepper)

	// Initialize encryption key for sensitive data (TOTP secrets, tokens, etc.)
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
	mux.HandleFunc("/api/ratchet/state", authMiddleware(getRatchetStateHandler))
	mux.HandleFunc("/api/ratchet/update", authMiddleware(updateRatchetStateHandler))
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
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Authorization header required"})
			return
		}

		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid authorization header format"})
			return
		}

		tokenString := parts[1]
		claims, err := jwt_auth.ValidateToken(tokenString)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid or expired token"})
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

// sendMessageHandler handles sending messages between users
func sendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	senderID, senderEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !csrfStore.ValidateToken(senderEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	if req.ReceiverEmail == "" || req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !validation.ValidateEmail(req.ReceiverEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Validate message size (allow larger for attachments in base64)
	if len(req.Content) > 50000 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message too long"})
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
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Receiver not found"})
			return
		}
		log.Printf("Failed to get receiver: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to send message"})
		return
	}

	// Check if receiver has E2EE keys
	if receiverPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Receiver doesn't have E2EE keys - they need to re-register or update their account"})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "You don't have E2EE keys - please re-register or update your account"})
		return
	}

	// NOTE: For simplicity, we're storing encrypted content in the database
	// The content should already be encrypted by the client before sending
	// Backend just stores it as-is for E2EE
	msgWithAttachments := MessageWithAttachments{
		Content:     req.Content,
		Attachments: req.Attachments,
	}

	// Serialize message with attachments as JSON
	msgJSON, err := json.Marshal(msgWithAttachments)
	if err != nil {
		log.Printf("Failed to serialize message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message processing failed"})
		return
	}

	encKeyStr := "client-e2ee-ratchet" // Indicating client-side encryption with Double Ratchet

	var messageID int
	err = db.QueryRowContext(ctx,
		"INSERT INTO Messages (sender_id, receiver_id, content, encrypted_key, message_signature, dh_public_key, message_number, previous_chain_length) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id",
		senderID, receiverID, string(msgJSON), encKeyStr, req.Signature, req.DHPublicKey, req.MessageNumber, req.PreviousChainLength).Scan(&messageID)
	if err != nil {
		log.Printf("Failed to insert message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to send message"})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT m.id, u.email, m.content, m.message_signature, m.is_read, m.created_at, m.read_at,
		       COALESCE(m.dh_public_key, ''), COALESCE(m.message_number, 0), COALESCE(m.previous_chain_length, 0)
		FROM Messages m
		JOIN Users u ON m.sender_id = u.id
		WHERE m.receiver_id = $1 AND m.is_deleted_by_receiver = FALSE
		ORDER BY m.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to get messages: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve messages"})
		return
	}
	defer rows.Close()

	messages := []MessageResponse{}
	for rows.Next() {
		var msg MessageResponse
		var senderEmail string
		var signature sql.NullString
		err := rows.Scan(&msg.ID, &senderEmail, &msg.Content, &signature, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt,
			&msg.DHPublicKey, &msg.MessageNumber, &msg.PreviousChainLength)
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT m.id, u.email, m.content, m.is_read, m.created_at, m.read_at
		FROM Messages m
		JOIN Users u ON m.receiver_id = u.id
		WHERE m.sender_id = $1 AND m.is_deleted_by_sender = FALSE
		ORDER BY m.created_at DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to get sent messages: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve messages"})
		return
	}
	defer rows.Close()

	messages := []MessageResponse{}
	for rows.Next() {
		var msg MessageResponse
		var receiverEmail string
		err := rows.Scan(&msg.ID, &receiverEmail, &msg.Content, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt)
		if err != nil {
			log.Printf("Failed to scan message: %v", err)
			continue
		}
		msg.SenderEmail = userEmail
		msg.ReceiverEmail = receiverEmail
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if req.MessageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to mark message as read"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message not found or already read"})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	// Get message ID from query parameter
	messageIDStr := r.URL.Query().Get("id")
	if messageIDStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message ID required"})
		return
	}

	messageID, err := strconv.Atoi(messageIDStr)
	if err != nil || messageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid message ID"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get message details
	var msg MessageResponse
	var senderEmail, receiverEmail string
	var senderID, receiverID int
	var encryptedKey sql.NullString
	var signature sql.NullString

	err = db.QueryRowContext(ctx, `
		SELECT m.id, m.sender_id, u1.email, m.receiver_id, u2.email, 
		       m.content, m.encrypted_key, m.message_signature,
		       m.is_read, m.created_at, m.read_at
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
		&msg.IsRead, &msg.CreatedAt, &msg.ReadAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Message not found"})
			return
		}
		log.Printf("Failed to get message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve message"})
		return
	}

	msg.SenderEmail = senderEmail
	msg.ReceiverEmail = receiverEmail
	if signature.Valid {
		msg.Signature = signature.String
	}

	// Decrypt message if it's encrypted and user has access
	// Note: E2EE decryption happens on frontend with user's decrypted private key
	if encryptedKey.Valid && encryptedKey.String == "e2ee" {
		// Message is encrypted - frontend will handle decryption
		// Just send the encrypted content as-is
	} else {
		// Try to parse as JSON with attachments (for non-encrypted messages)
		var msgWithAttachments MessageWithAttachments
		if err := json.Unmarshal([]byte(msg.Content), &msgWithAttachments); err == nil {
			// Successfully parsed as JSON with attachments
			if len(msgWithAttachments.Attachments) > 0 {
				msg.Content = msgWithAttachments.Content
				msg.Attachments = msgWithAttachments.Attachments
			}
			// If no attachments, msg.Content already has the right value
		}
		// If parsing fails, msg.Content is just plain text (backwards compatible)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(msg)
}

// deleteMessageHandler soft-deletes a message
func deleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if req.MessageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to delete message"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Message deleted successfully",
	})
}

// registerDeviceHandler handles registering a new device for E2EE
// getE2EEKeysHandler returns E2EE keys for the authenticated user
func getE2EEKeysHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
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

// csrfTokenHandler generates and returns a new CSRF token
func csrfTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	token, err := csrfStore.CreateToken(userEmail, csrf.DefaultExpiration)
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

// getRatchetStateHandler retrieves or initializes ratchet state between two users
func getRatchetStateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	peerEmail := r.URL.Query().Get("peer_email")
	if peerEmail == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "peer_email is required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get peer user ID
	var peerUserID int
	err = db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(peerEmail)).Scan(&peerUserID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Peer user not found"})
		return
	}

	// Try to get existing ratchet state
	var state RatchetState
	err = db.QueryRowContext(ctx, `
		SELECT id, user_id, peer_user_id, root_key, sending_chain_key, receiving_chain_key,
		       sending_chain_length, receiving_chain_length, previous_chain_length,
		       dh_public_key, COALESCE(dh_peer_public_key, '')
		FROM RatchetStates
		WHERE user_id = $1 AND peer_user_id = $2
	`, userID, peerUserID).Scan(
		&state.ID, &state.UserID, &state.PeerUserID, &state.RootKey,
		&state.SendingChainKey, &state.ReceivingChainKey,
		&state.SendingChainLength, &state.ReceivingChainLength, &state.PreviousChainLength,
		&state.DHPublicKey, &state.DHPeerPublicKey,
	)

	if err == sql.ErrNoRows {
		// No state exists yet - client needs to initialize
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "No ratchet state exists - initialize on first message",
			"exists":  false,
		})
		return
	} else if err != nil {
		log.Printf("Failed to get ratchet state: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve ratchet state"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(state)
}

// updateRatchetStateHandler updates ratchet state after sending/receiving messages
func updateRatchetStateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var state RatchetState
	if err := json.NewDecoder(r.Body).Decode(&state); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request body"})
		return
	}

	// Ensure user can only update their own state
	state.UserID = userID

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check if state exists
	var existingID int
	err = db.QueryRowContext(ctx, "SELECT id FROM RatchetStates WHERE user_id = $1 AND peer_user_id = $2",
		state.UserID, state.PeerUserID).Scan(&existingID)

	if err == sql.ErrNoRows {
		// Insert new state
		err = db.QueryRowContext(ctx, `
			INSERT INTO RatchetStates (user_id, peer_user_id, root_key, sending_chain_key, receiving_chain_key,
			                          sending_chain_length, receiving_chain_length, previous_chain_length,
			                          dh_public_key, dh_peer_public_key)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING id
		`, state.UserID, state.PeerUserID, state.RootKey, state.SendingChainKey, state.ReceivingChainKey,
			state.SendingChainLength, state.ReceivingChainLength, state.PreviousChainLength,
			state.DHPublicKey, state.DHPeerPublicKey).Scan(&state.ID)

		if err != nil {
			log.Printf("Failed to insert ratchet state: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to create ratchet state"})
			return
		}
	} else if err != nil {
		log.Printf("Failed to check ratchet state: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to update ratchet state"})
		return
	} else {
		// Update existing state
		_, err = db.ExecContext(ctx, `
			UPDATE RatchetStates
			SET root_key = $1, sending_chain_key = $2, receiving_chain_key = $3,
			    sending_chain_length = $4, receiving_chain_length = $5, previous_chain_length = $6,
			    dh_public_key = $7, dh_peer_public_key = $8, updated_at = CURRENT_TIMESTAMP
			WHERE user_id = $9 AND peer_user_id = $10
		`, state.RootKey, state.SendingChainKey, state.ReceivingChainKey,
			state.SendingChainLength, state.ReceivingChainLength, state.PreviousChainLength,
			state.DHPublicKey, state.DHPeerPublicKey, state.UserID, state.PeerUserID)

		if err != nil {
			log.Printf("Failed to update ratchet state: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to update ratchet state"})
			return
		}
		state.ID = existingID
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Ratchet state updated successfully",
		"id":      state.ID,
	})
}

// totpStatusHandler returns the 2FA status for a user
func totpStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	var totpEnabled bool
	var totpSecret sql.NullString
	err = db.QueryRow(`SELECT totp_enabled, totp_secret FROM Users WHERE id = $1`, userID).Scan(&totpEnabled, &totpSecret)
	if err != nil {
		log.Printf("Failed to get 2FA status for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to get 2FA status"})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
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

	_, err = db.Exec(`UPDATE Users SET totp_secret = $1 WHERE id = $2`, encryptedSecretForDB, userID)
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
		"encrypted_secret": encryptedSecretForUser, // Encrypted with user's password
		"qr_code":          qrCodeURL,              // QR code URL for authenticator app
	})
}

// totpVerifyHandler verifies and enables 2FA for a user
func totpVerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
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

	if !csrfStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	var encryptedTotpSecret string
	err = db.QueryRow(`SELECT totp_secret FROM Users WHERE id = $1`, userID).Scan(&encryptedTotpSecret)
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

	// Decrypt TOTP secret
	totpSecret, err := cryptography.DecryptSensitiveData(encryptedTotpSecret)
	if err != nil {
		log.Printf("Failed to decrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to verify 2FA"})
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

	_, err = db.Exec(`UPDATE Users SET totp_enabled = TRUE, totp_verified_at = NOW() WHERE id = $1`, userID)
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

// totpDisableHandler disables 2FA for a user
func totpDisableHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Method not allowed"})
		return
	}

	userID, userEmail, err := getUserFromContext(r)
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

	if !csrfStore.ValidateToken(userEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	_, err = db.Exec(`UPDATE Users SET totp_enabled = FALSE, totp_secret = NULL WHERE id = $1`, userID)
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

// totpValidateHandler validates a TOTP code during login
func totpValidateHandler(w http.ResponseWriter, r *http.Request) {
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

	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid email format"})
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
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
		return
	}

	// Verify password
	passwordValid, err := cryptography.VerifyPassword(req.Password, passwordHash)
	if err != nil || !passwordValid {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid credentials"})
		return
	}

	if !totpEnabled || encryptedTotpSecret == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "2FA not enabled"})
		return
	}

	// Decrypt TOTP secret
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid 2FA code"})
		return
	}

	// Generate JWT token after successful 2FA verification
	token, err := jwt_auth.GenerateToken(userID, strings.ToLower(req.Email))
	if err != nil {
		log.Printf("Failed to generate JWT token: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to complete login"})
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
		response["e2ee_private_key_encrypted"] = privateKeyEncrypted
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}
