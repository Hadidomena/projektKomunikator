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
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

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
	ctx2, cancel2 := context.WithTimeout(r.Context(), 10*time.Second)
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
	if !cryptography.CheckPasswordHash(req.Password, storedHash) {
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
