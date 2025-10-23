package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/lib/pq"
	_ "github.com/lib/pq"
)

type TextSubmission struct {
	Content string `json:"content"`
}

type RegistrationRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ErrorResponse struct {
	Message string `json:"message"`
}

var db *sql.DB

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

	if err = db.Ping(); err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/api/texts", textsHandler)
	http.HandleFunc("/api/register", registerHandler)

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

	_, err = db.Exec("INSERT INTO Texts (content) VALUES ($1)", submission.Content)
	if err != nil {
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
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Username == "" || req.Password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Hash the password using the cryptography package
	hashedPassword, err := cryptography.HashPassword(req.Password)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Failed to process registration", http.StatusInternalServerError)
		return
	}

	// Insert the new user into the database
	_, err = db.Exec("INSERT INTO Users (username, password_hash) VALUES ($1, $2)", req.Username, hashedPassword)
	if err != nil {
		// Check if the error is a unique constraint violation (username already exists)
		if pqErr, ok := err.(*pq.Error); ok && pqErr.Code == "23505" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict) // 409 Conflict
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Username already exists"})
			return
		}

		// For any other database error
		log.Printf("Failed to insert user into database: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to register user"})
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}
