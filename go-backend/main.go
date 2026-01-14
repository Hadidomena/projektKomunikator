package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/validation"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type TextSubmission struct {
	Content string `json:"content"`
}

type RegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SendMessageRequest struct {
	ReceiverEmail string `json:"receiver_email"`
	Content       string `json:"content"`
}

type MessageResponse struct {
	ID            int        `json:"id"`
	SenderEmail   string     `json:"sender_email"`
	ReceiverEmail string     `json:"receiver_email"`
	Content       string     `json:"content"`
	IsRead        bool       `json:"is_read"`
	CreatedAt     time.Time  `json:"created_at"`
	ReadAt        *time.Time `json:"read_at,omitempty"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

var db *sql.DB
var loginTracker *validation.LoginAttemptTracker

var (
	// appPepper is a global secret used to augment password hashing.
	// It is loaded from an environment variable at startup.
	appPepper string
)

func init() {
	appPepper := os.Getenv("PEPPER")
	if appPepper == "" {
		appPepper = "testPepper"
		// panic("SECURITY ERROR: PEPPER environment variable not set")
	}
	cryptography.SetPepper(appPepper)
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

	// Configure connection pool for better concurrency
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(10 * time.Minute)

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	// Load common passwords into memory on startup
	if err := passwordutils.LoadCommonPasswords(); err != nil {
		log.Printf("Warning: Could not load common passwords: %v", err)
	}

	// Initialize login attempt tracker
	loginTracker = validation.NewLoginAttemptTracker()

	http.HandleFunc("/api/texts", textsHandler)
	http.HandleFunc("/api/register", registerHandler)
	http.HandleFunc("/api/login", loginHandler)
	http.HandleFunc("/api/messages/send", sendMessageHandler)
	http.HandleFunc("/api/messages/inbox", getInboxHandler)
	http.HandleFunc("/api/messages/sent", getSentMessagesHandler)
	http.HandleFunc("/api/messages/mark-read", markMessageAsReadHandler)
	http.HandleFunc("/api/messages/delete", deleteMessageHandler)

	fmt.Println("Go backend server starting on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func textsHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var submission TextSubmission
	err := json.NewDecoder(r.Body).Decode(&submission)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create context with timeout for database operation
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Use context-aware database query
	_, err = db.ExecContext(ctx, "INSERT INTO Texts (content) VALUES ($1)", submission.Content)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			http.Error(w, "Request timeout", http.StatusRequestTimeout)
			log.Printf("Database operation timeout: %v", err)
			return
		}
		http.Error(w, "Failed to insert text into database", http.StatusInternalServerError)
		log.Printf("Failed to insert text: %v", err)
		return
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Text successfully submitted")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers for preflight and actual requests
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

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

	// Validate input fields
	if req.Username == "" || req.Email == "" || req.Password == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Validate email format
	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Check if email already exists
	ctx2, cancel2 := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel2()

	emailExists, err := validation.CheckEmailExists(db, req.Email)
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

	// Password validation is now fast (in-memory check)
	if passwordutils.IsViablePassword(req.Password) == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Create context with timeout for potentially long operations
	ctx2, cancel2 = context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel2()

	// Use a channel to handle the password hashing asynchronously
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

	// Insert the new user into the database with context
	_, err = db.ExecContext(ctx2, "INSERT INTO Users (username, email, password_hash, public_key) VALUES ($1, $2, $3, $4)", req.Username, strings.ToLower(req.Email), hashedPassword, "")
	if err != nil {
		// Check if the error is a unique constraint violation
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
			return
		}

		// Check for context timeout
		if ctx2.Err() == context.DeadlineExceeded {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusRequestTimeout)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
			log.Printf("Database operation timeout: %v", err)
			return
		}

		// For any other database error
		log.Printf("Failed to insert user into database: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("registration_failed")})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Validate email format
	if !validation.ValidateEmail(req.Email) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	// Normalize email to lowercase
	email := strings.ToLower(req.Email)

	// Check account status before attempting login
	isLocked, remainingTime, isBlocked := loginTracker.CheckAccountStatus(email)

	if isBlocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("account_blocked")})
		return
	}

	if isLocked {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(ErrorResponse{
			Message: validation.GetSanitizedError("account_locked"),
		})
		log.Printf("Login attempt for locked account: %s, remaining time: %v", email, remainingTime)
		return
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Query user from database
	var storedHash string
	var userID int
	err := db.QueryRowContext(ctx, "SELECT id, password_hash FROM Users WHERE email = $1", email).Scan(&userID, &storedHash)

	if err != nil {
		if err == sql.ErrNoRows {
			// User not found - record failed attempt and return generic error
			ip := r.RemoteAddr
			loginTracker.RecordFailedAttempt(email, ip)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
			return
		}

		// Database error
		log.Printf("Database error during login: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Verify password
	passwordValid, err := cryptography.VerifyPassword(req.Password, storedHash)
	if err != nil {
		log.Printf("Error verifying password: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	if !passwordValid {
		// Invalid password - record failed attempt
		ip := r.RemoteAddr
		isLocked, lockDuration, isBlocked, _ := loginTracker.RecordFailedAttempt(email, ip)

		log.Printf("Failed login attempt for user: %s from IP: %s", email, ip)

		if isBlocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("account_blocked")})
			return
		}

		if isLocked {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(ErrorResponse{
				Message: validation.GetSanitizedError("account_locked"),
			})
			log.Printf("Account locked: %s, duration: %v", email, lockDuration)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Successful login - reset failed attempts
	loginTracker.ResetAttempts(email)

	log.Printf("Successful login for user: %s", email)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Login successful",
		"user_id": userID,
	})
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

	// TODO: Get sender_id from JWT token/session
	// For now, we'll expect it in the request or use a header
	senderEmail := r.Header.Get("X-User-Email")
	if senderEmail == "" {
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

	// Validate input
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

	// Limit message length
	if len(req.Content) > 10000 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message too long"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get sender ID
	var senderID int
	err := db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(senderEmail)).Scan(&senderID)
	if err != nil {
		log.Printf("Failed to get sender ID: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Get receiver ID
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

	// Insert message
	var messageID int
	err = db.QueryRowContext(ctx,
		"INSERT INTO Messages (sender_id, receiver_id, content) VALUES ($1, $2, $3) RETURNING id",
		senderID, receiverID, req.Content).Scan(&messageID)
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
	})
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

	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get user ID
	var userID int
	err := db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(userEmail)).Scan(&userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Get messages
	rows, err := db.QueryContext(ctx, `
		SELECT m.id, u.email, m.content, m.is_read, m.created_at, m.read_at
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
		err := rows.Scan(&msg.ID, &senderEmail, &msg.Content, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt)
		if err != nil {
			log.Printf("Failed to scan message: %v", err)
			continue
		}
		msg.SenderEmail = senderEmail
		msg.ReceiverEmail = userEmail
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

	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get user ID
	var userID int
	err := db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(userEmail)).Scan(&userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Get sent messages
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

	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
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

	// Get user ID
	var userID int
	err := db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(userEmail)).Scan(&userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Mark message as read (only if user is the receiver)
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

	userEmail := r.Header.Get("X-User-Email")
	if userEmail == "" {
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

	// Get user ID
	var userID int
	err := db.QueryRowContext(ctx, "SELECT id FROM Users WHERE email = $1", strings.ToLower(userEmail)).Scan(&userID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("login_failed")})
		return
	}

	// Soft delete message (mark as deleted for the user)
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
