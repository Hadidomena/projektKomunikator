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
	"github.com/Hadidomena/projektKomunikator/csrf"
	"github.com/Hadidomena/projektKomunikator/handlers"
	jwt_auth "github.com/Hadidomena/projektKomunikator/jwt_auth"
	"github.com/Hadidomena/projektKomunikator/middleware"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
	"github.com/Hadidomena/projektKomunikator/validation"
	_ "github.com/lib/pq"
)

var db *sql.DB
var csrfStore *csrf.TokenStore
var loginTracker *validation.LoginAttemptTracker
var e2eePepper string

func init() {
	appPepper := os.Getenv("PEPPER")
	if appPepper == "" {
		log.Fatal("SECURITY ERROR: PEPPER environment variable not set")
	}
	cryptography.SetPepper(appPepper)

	e2eePepper = os.Getenv("E2EE_PEPPER")
	if e2eePepper == "" {
		log.Fatal("SECURITY ERROR: E2EE_PEPPER environment variable not set")
	}

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

	handlers.Initialize(db, csrfStore, loginTracker, e2eePepper)

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
	mux.HandleFunc("/api/csrf-token", authMiddleware(handlers.CSRFTokenHandler))
	mux.HandleFunc("/api/2fa/status", authMiddleware(handlers.TOTPStatusHandler))
	mux.HandleFunc("/api/2fa/setup", authMiddleware(handlers.TOTPSetupHandler))
	mux.HandleFunc("/api/2fa/verify", authMiddleware(handlers.TOTPVerifyHandler))
	mux.HandleFunc("/api/2fa/disable", authMiddleware(handlers.TOTPDisableHandler))
	mux.HandleFunc("/api/2fa/validate", handlers.TOTPValidateHandler)
	mux.HandleFunc("/api/messages/send", authMiddleware(handlers.SendMessageHandler))
	mux.HandleFunc("/api/messages", authMiddleware(handlers.GetInboxHandler))
	mux.HandleFunc("/api/messages/mark-read", authMiddleware(handlers.MarkMessageAsReadHandler))
	mux.HandleFunc("/api/messages/delete", authMiddleware(handlers.DeleteMessageHandler))
	mux.HandleFunc("/api/messages/sent", authMiddleware(handlers.GetSentMessagesHandler))
	mux.HandleFunc("/api/messages/get", authMiddleware(handlers.GetMessageHandler))
	mux.HandleFunc("/api/e2ee/keys", authMiddleware(handlers.GetE2EEKeysHandler))
	mux.HandleFunc("/api/e2ee/config", authMiddleware(handlers.E2EEConfigHandler))
	mux.HandleFunc("/api/user/public-key", authMiddleware(handlers.GetUserPublicKeyHandler))
	mux.HandleFunc("/api/user/update-public-key", authMiddleware(handlers.UpdateUserPublicKeyHandler))
	mux.HandleFunc("/api/user/fingerprint", authMiddleware(handlers.GetUserFingerprintHandler))
	mux.HandleFunc("/api/e2ee/fingerprint", authMiddleware(handlers.GetE2EEFingerprintHandler))
	mux.HandleFunc("/api/password-reset/request", handlers.PasswordResetRequestHandler)
	mux.HandleFunc("/api/password-reset/verify", handlers.PasswordResetVerifyHandler)
	mux.HandleFunc("/api/login-history", authMiddleware(handlers.LoginHistoryHandler))
	mux.HandleFunc("/api/admin/honeypot-stats", authMiddleware(handlers.HoneypotStatsHandler))

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

		ctx := context.WithValue(r.Context(), handlers.ContextKeyUserID, claims.UserID)
		ctx = context.WithValue(ctx, handlers.ContextKeyUserEmail, claims.Email)

		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
