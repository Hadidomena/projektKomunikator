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
	"github.com/Hadidomena/projektKomunikator/e2ee"
	"github.com/Hadidomena/projektKomunikator/handlers"
	jwt_auth "github.com/Hadidomena/projektKomunikator/jwt_auth"
	message_utils "github.com/Hadidomena/projektKomunikator/message_utils"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/totp"
	"github.com/Hadidomena/projektKomunikator/validation"
	"github.com/lib/pq"
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
	ReceiverEmail string                     `json:"receiver_email"`
	Content       string                     `json:"content"`
	DeviceID      int                        `json:"device_id,omitempty"`   // Optional: sender's device ID
	Encrypted     bool                       `json:"encrypted,omitempty"`   // Is the message encrypted?
	Signature     string                     `json:"signature,omitempty"`   // Message signature for authenticity
	CSRFToken     string                     `json:"csrf_token"`            // CSRF token
	Attachments   []message_utils.Attachment `json:"attachments,omitempty"` // Attachments (will be encrypted with message)
}

type RegisterDeviceRequest struct {
	DeviceName string `json:"device_name"`
	PublicKey  string `json:"public_key,omitempty"` // Optional: if client provides key
}

type DeviceResponse struct {
	ID                int       `json:"id"`
	DeviceName        string    `json:"device_name"`
	PublicKey         string    `json:"public_key"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	LastUsed          time.Time `json:"last_used"`
	CreatedAt         time.Time `json:"created_at"`
	IsActive          bool      `json:"is_active"`
}

type MessageResponse struct {
	ID            int                        `json:"id"`
	SenderEmail   string                     `json:"sender_email"`
	ReceiverEmail string                     `json:"receiver_email"`
	Content       string                     `json:"content"`
	Signature     string                     `json:"signature,omitempty"`
	IsRead        bool                       `json:"is_read"`
	CreatedAt     time.Time                  `json:"created_at"`
	ReadAt        *time.Time                 `json:"read_at,omitempty"`
	Attachments   []message_utils.Attachment `json:"attachments,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message"`
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
}

type TOTPSetupResponse struct {
	Secret string `json:"secret"`
	QRCode string `json:"qr_code_url"`
}

type TOTPVerifyRequest struct {
	Code      string `json:"code"`
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

var (
	appPepper string
)

func init() {
	appPepper := os.Getenv("PEPPER")
	if appPepper == "" {
		appPepper = "testPepper"
		// panic("SECURITY ERROR: PEPPER environment variable not set")
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
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"))

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	csrfStore = csrf.NewTokenStore()
	loginTracker = validation.NewLoginAttemptTracker()

	handlers.Initialize(db, csrfStore, loginTracker)

	http.HandleFunc("/api/register", handlers.RegisterHandler)
	http.HandleFunc("/api/login", handlers.LoginHandler)
	http.HandleFunc("/api/check-password-strength", handlers.CheckPasswordStrengthHandler)

	http.HandleFunc("/api/csrf-token", authMiddleware(csrfTokenHandler))

	// 2FA endpoints (protected)
	http.HandleFunc("/api/2fa/setup", authMiddleware(totpSetupHandler))
	http.HandleFunc("/api/2fa/verify", authMiddleware(totpVerifyHandler))
	http.HandleFunc("/api/2fa/disable", authMiddleware(totpDisableHandler))
	http.HandleFunc("/api/2fa/validate", totpValidateHandler)

	http.HandleFunc("/api/messages/send", authMiddleware(sendMessageHandler))
	http.HandleFunc("/api/messages", authMiddleware(getInboxHandler))
	http.HandleFunc("/api/messages/mark-read", authMiddleware(markMessageAsReadHandler))
	http.HandleFunc("/api/messages/delete", authMiddleware(deleteMessageHandler))
	http.HandleFunc("/api/messages/sent", authMiddleware(getSentMessagesHandler))
	http.HandleFunc("/api/messages/get", authMiddleware(getMessageHandler))

	http.HandleFunc("/api/devices/register", authMiddleware(registerDeviceHandler))
	http.HandleFunc("/api/devices", authMiddleware(listDevicesHandler))
	http.HandleFunc("/api/devices/remove", authMiddleware(deactivateDeviceHandler))

	http.HandleFunc("/api/password-reset/request", handlers.PasswordResetRequestHandler)
	http.HandleFunc("/api/password-reset/verify", handlers.PasswordResetVerifyHandler)

	http.HandleFunc("/api/login-history", authMiddleware(loginHistoryHandler))
	http.HandleFunc("/api/admin/honeypot-stats", authMiddleware(honeypotStatsHandler))

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

	fmt.Println("Go backend server starting on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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
		log.Printf("Sending message with %d attachments from %s to %s", len(req.Attachments), senderEmail, req.ReceiverEmail)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var receiverID int
	err = db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(req.ReceiverEmail)).Scan(&receiverID)
	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Receiver not found"})
			return
		}
		log.Printf("Failed to get receiver ID: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to send message"})
		return
	}

	messageContent := req.Content
	var encryptedKey *string

	// If message has attachments, serialize them with content
	if len(req.Attachments) > 0 {
		msgWithAttachments := message_utils.MessageWithAttachments{
			Content:     req.Content,
			Attachments: req.Attachments,
		}
		// Serialize to JSON for storage
		jsonData, err := json.Marshal(msgWithAttachments)
		if err != nil {
			log.Printf("Failed to serialize message with attachments: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to process attachments"})
			return
		}
		messageContent = string(jsonData)
	}

	if req.Encrypted && req.DeviceID > 0 {
		// Get sender's device private key from environment
		var senderDeviceFingerprint string
		err = db.QueryRowContext(ctx,
			"SELECT device_fingerprint FROM UserDevices WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
			req.DeviceID, senderID).Scan(&senderDeviceFingerprint)
		if err != nil {
			log.Printf("Failed to get sender device: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid sender device"})
			return
		}

		senderPrivateKey, err := e2ee.GetPrivateKeyFromEnv(senderDeviceFingerprint)
		if err != nil {
			log.Printf("Failed to get sender private key: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "E2EE key not available"})
			return
		}

		var receiverPublicKey string
		var receiverDeviceID int
		err = db.QueryRowContext(ctx,
			"SELECT id, public_key FROM UserDevices WHERE user_id = $1 AND is_active = TRUE ORDER BY last_used DESC LIMIT 1",
			receiverID).Scan(&receiverDeviceID, &receiverPublicKey)
		if err != nil {
			log.Printf("Failed to get receiver device: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Receiver has no active devices for E2EE"})
			return
		}

		sharedSecret, err := e2ee.ComputeSharedSecret(senderPrivateKey, receiverPublicKey)
		if err != nil {
			log.Printf("Failed to compute shared secret: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "E2EE encryption failed"})
			return
		}

		encryptionKey := sharedSecret[:32]

		// Create message with attachments structure
		msgWithAttachments := message_utils.MessageWithAttachments{
			Content:     req.Content,
			Attachments: req.Attachments,
		}

		encryptedContent, err := message_utils.EncryptMessageWithAttachments(msgWithAttachments, encryptionKey)
		if err != nil {
			log.Printf("Failed to encrypt message: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Message encryption failed"})
			return
		}

		messageContent = encryptedContent
		encKeyStr := "e2ee"
		encryptedKey = &encKeyStr

		req.DeviceID = receiverDeviceID
	}

	var messageID int
	if encryptedKey != nil {
		err = db.QueryRowContext(ctx,
			"INSERT INTO Messages (sender_id, sender_device_id, receiver_id, receiver_device_id, content, encrypted_key, message_signature) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
			senderID, req.DeviceID, receiverID, req.DeviceID, messageContent, encryptedKey, req.Signature).Scan(&messageID)
	} else {
		err = db.QueryRowContext(ctx,
			"INSERT INTO Messages (sender_id, receiver_id, content, message_signature) VALUES ($1, $2, $3, $4) RETURNING id",
			senderID, receiverID, messageContent, req.Signature).Scan(&messageID)
	}
	if err != nil {
		log.Printf("Failed to insert message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to send message"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	response := map[string]interface{}{
		"message":    "Message sent successfully",
		"message_id": messageID,
	}
	if encryptedKey != nil {
		response["encrypted"] = true
	}
	json.NewEncoder(w).Encode(response)
}

// getInboxHandler retrieves inbox messages for the authenticated user
func getInboxHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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
		SELECT m.id, u.email, m.content, m.message_signature, m.is_read, m.created_at, m.read_at
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
		err := rows.Scan(&msg.ID, &senderEmail, &msg.Content, &signature, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt)
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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

	// Optional device ID for decryption
	deviceIDStr := r.URL.Query().Get("device_id")
	var deviceID int
	if deviceIDStr != "" {
		deviceID, _ = strconv.Atoi(deviceIDStr)
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get message details
	var msg MessageResponse
	var senderEmail, receiverEmail string
	var senderID, receiverID int
	var senderDeviceID, receiverDeviceID sql.NullInt64
	var encryptedKey sql.NullString
	var signature sql.NullString

	err = db.QueryRowContext(ctx, `
		SELECT m.id, m.sender_id, u1.email, m.receiver_id, u2.email, 
		       m.content, m.encrypted_key, m.message_signature,
		       m.sender_device_id, m.receiver_device_id,
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
		&senderDeviceID, &receiverDeviceID,
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
	if encryptedKey.Valid && encryptedKey.String == "e2ee" {
		// Determine which device to use for decryption
		var userDeviceID int
		if userID == receiverID {
			// User is receiver, use receiver's device
			if deviceID > 0 {
				userDeviceID = deviceID
			} else if receiverDeviceID.Valid {
				userDeviceID = int(receiverDeviceID.Int64)
			}
		} else if userID == senderID {
			// User is sender, use sender's device
			if deviceID > 0 {
				userDeviceID = deviceID
			} else if senderDeviceID.Valid {
				userDeviceID = int(senderDeviceID.Int64)
			}
		}

		if userDeviceID > 0 {
			// Get user's device fingerprint and private key
			var deviceFingerprint string
			err = db.QueryRowContext(ctx,
				"SELECT device_fingerprint FROM UserDevices WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
				userDeviceID, userID).Scan(&deviceFingerprint)

			if err == nil {
				userPrivateKey, err := e2ee.GetPrivateKeyFromEnv(deviceFingerprint)
				if err == nil {
					// Get the other party's public key
					var otherPartyID int
					var otherDeviceID int
					if userID == receiverID {
						otherPartyID = senderID
						if senderDeviceID.Valid {
							otherDeviceID = int(senderDeviceID.Int64)
						}
					} else {
						otherPartyID = receiverID
						if receiverDeviceID.Valid {
							otherDeviceID = int(receiverDeviceID.Int64)
						}
					}

					if otherDeviceID > 0 {
						var otherPublicKey string
						err = db.QueryRowContext(ctx,
							"SELECT public_key FROM UserDevices WHERE id = $1 AND user_id = $2 AND is_active = TRUE",
							otherDeviceID, otherPartyID).Scan(&otherPublicKey)

						if err == nil {
							// Compute shared secret and decrypt
							sharedSecret, err := e2ee.ComputeSharedSecret(userPrivateKey, otherPublicKey)
							if err == nil {
								encryptionKey := sharedSecret[:32]

								// Decrypt message with attachments
								decryptedMsg, err := message_utils.DecryptMessageWithAttachments(msg.Content, encryptionKey)
								if err == nil {
									msg.Content = decryptedMsg.Content
									msg.Attachments = decryptedMsg.Attachments
								} else {
									log.Printf("Failed to decrypt message: %v", err)
								}
							}
						}
					}
				}
			}
		}
	} else {
		// Try to parse as JSON with attachments (for non-encrypted messages)
		var msgWithAttachments message_utils.MessageWithAttachments
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
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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
func registerDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := getUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req RegisterDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request"})
		return
	}

	if req.DeviceName == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Device name is required"})
		return
	}

	deviceKeys, err := e2ee.GenerateDeviceKeys(userID, req.DeviceName)
	if err != nil {
		log.Printf("Failed to generate device keys: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to generate device keys"})
		return
	}

	publicKey := deviceKeys.PublicKey
	if req.PublicKey != "" {
		publicKey = req.PublicKey
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var deviceID int
	err = db.QueryRowContext(ctx,
		`INSERT INTO UserDevices (user_id, device_name, public_key, device_fingerprint) 
		 VALUES ($1, $2, $3, $4) RETURNING id`,
		userID, req.DeviceName, publicKey, deviceKeys.DeviceFingerprint).Scan(&deviceID)
	if err != nil {
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" { // Unique violation
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Device already registered"})
			return
		}
		log.Printf("Failed to register device: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to register device"})
		return
	}

	if err := e2ee.StorePrivateKeyInEnv(deviceKeys.DeviceFingerprint, deviceKeys.PrivateKey); err != nil {
		log.Printf("Warning: Failed to store private key in environment: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":            "Device registered successfully",
		"device_id":          deviceID,
		"device_fingerprint": deviceKeys.DeviceFingerprint,
		"public_key":         publicKey,
		"private_key":        deviceKeys.PrivateKey, // Return once to client - client must store securely
	})
}

// listDevicesHandler lists all devices for the authenticated user
func listDevicesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := db.QueryContext(ctx, `
		SELECT id, device_name, public_key, device_fingerprint, last_used, created_at, is_active
		FROM UserDevices
		WHERE user_id = $1
		ORDER BY last_used DESC
	`, userID)
	if err != nil {
		log.Printf("Failed to query devices: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve devices"})
		return
	}
	defer rows.Close()

	var devices []DeviceResponse
	for rows.Next() {
		var device DeviceResponse
		if err := rows.Scan(&device.ID, &device.DeviceName, &device.PublicKey, &device.DeviceFingerprint,
			&device.LastUsed, &device.CreatedAt, &device.IsActive); err != nil {
			log.Printf("Failed to scan device: %v", err)
			continue
		}
		devices = append(devices, device)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(devices)
}

// deactivateDeviceHandler deactivates a device
func deactivateDeviceHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
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
		DeviceID int `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid request"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	result, err := db.ExecContext(ctx, `
		UPDATE UserDevices 
		SET is_active = FALSE
		WHERE id = $1 AND user_id = $2
	`, req.DeviceID, userID)
	if err != nil {
		log.Printf("Failed to deactivate device: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to deactivate device"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Device not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Device deactivated successfully",
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

	// No request body needed for setup - JWT auth is sufficient

	secret, err := totp.GenerateSecret()
	if err != nil {
		log.Printf("Failed to generate TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to generate 2FA secret"})
		return
	}

	// Encrypt TOTP secret before storing
	encryptedSecret, err := cryptography.EncryptSensitiveData(secret)
	if err != nil {
		log.Printf("Failed to encrypt TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	_, err = db.Exec(`UPDATE Users SET totp_secret = $1 WHERE id = $2`, encryptedSecret, userID)
	if err != nil {
		log.Printf("Failed to store TOTP secret for user %d: %v", userID, err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to setup 2FA"})
		return
	}

	qrCodeURL := totp.GenerateQRCodeURL(userEmail, "Komunikator", secret)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"secret":  secret,
		"qr_code": qrCodeURL,
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

	log.Printf("Successful 2FA login for user: %s", req.Email)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Login successful",
		"token":      token,
		"user_id":    userID,
		"email":      strings.ToLower(req.Email),
		"expires_in": jwt_auth.GetTokenExpiration().Seconds(),
	})
}
