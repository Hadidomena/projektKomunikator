package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/handlers"
	jwt_auth "github.com/Hadidomena/projektKomunikator/jwt_auth"
	"github.com/Hadidomena/projektKomunikator/validation"
)

func setupLoginTest(t *testing.T) (sqlmock.Sqlmock, *validation.LoginAttemptTracker) {
	t.Helper()
	cryptography.SetPepper("test-login-pepper")
	os.Setenv("JWT_SECRET", "a-very-long-jwt-secret-key-for-tests-1234567890")
	if err := jwt_auth.InitJWT(); err != nil {
		t.Fatalf("failed to init JWT: %v", err)
	}
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	loginTracker := validation.NewLoginAttemptTracker()
	handlers.Initialize(db, nil, loginTracker, "")
	return mock, loginTracker
}

func postLogin(t *testing.T, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.LoginHandler(w, r)
	return w
}

func TestLoginHandler_WrongMethod(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest(http.MethodGet, "/api/login", nil)
	w := httptest.NewRecorder()
	handlers.LoginHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}

func TestLoginHandler_InvalidJSON(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader([]byte("invalid")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.LoginHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestLoginHandler_InvalidEmail(t *testing.T) {
	_, _ = setupLoginTest(t)

	w := postLogin(t, map[string]string{"email": "not-an-email", "password": "password"})

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestLoginHandler_HoneypotTriggered(t *testing.T) {
	mock, _ := setupLoginTest(t)
	mock.ExpectExec("INSERT INTO HoneypotAttempts").WillReturnResult(sqlmock.NewResult(1, 1))

	w := postLogin(t, map[string]string{
		"email":    "user@test.com",
		"password": "password",
		"website":  "http://spam.example.com",
	})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestLoginHandler_BlockedAccount(t *testing.T) {
	_, loginTracker := setupLoginTest(t)
	for i := 0; i < 5; i++ {
		loginTracker.RecordFailedAttempt("blocked@test.com", "127.0.0.1")
	}

	w := postLogin(t, map[string]string{"email": "blocked@test.com", "password": "password"})

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected 403, got %d", w.Code)
	}
}

func TestLoginHandler_LockedAccount(t *testing.T) {
	_, loginTracker := setupLoginTest(t)
	loginTracker.RecordFailedAttempt("locked@test.com", "127.0.0.1")

	w := postLogin(t, map[string]string{"email": "locked@test.com", "password": "password"})

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", w.Code)
	}
}

func TestLoginHandler_UserNotFound(t *testing.T) {
	mock, _ := setupLoginTest(t)
	mock.ExpectQuery("SELECT id, password_hash, totp_enabled").
		WithArgs("ghost@test.com").
		WillReturnError(sql.ErrNoRows)

	w := postLogin(t, map[string]string{"email": "ghost@test.com", "password": "password"})

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401, got %d", w.Code)
	}
}

func TestLoginHandler_WrongPassword(t *testing.T) {
	mock, _ := setupLoginTest(t)
	hash, err := cryptography.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	rows := sqlmock.NewRows([]string{"id", "password_hash", "totp_enabled", "e2ee_public_key", "e2ee_private_key_encrypted"}).
		AddRow(1, hash, false, "", "")
	mock.ExpectQuery("SELECT id, password_hash, totp_enabled").
		WithArgs("user@test.com").
		WillReturnRows(rows)
	w := postLogin(t, map[string]string{"email": "user@test.com", "password": "wrong-password"})

	if w.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429 (lockout), got %d", w.Code)
	}
}

func TestLoginHandler_Success(t *testing.T) {
	mock, _ := setupLoginTest(t)
	hash, err := cryptography.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	rows := sqlmock.NewRows([]string{"id", "password_hash", "totp_enabled", "e2ee_public_key", "e2ee_private_key_encrypted"}).
		AddRow(1, hash, false, "pubkey", "privkeyenc")
	mock.ExpectQuery("SELECT id, password_hash, totp_enabled").
		WithArgs("user@test.com").
		WillReturnRows(rows)

	deviceRows := sqlmock.NewRows([]string{"count"}).AddRow(0)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM LoginHistory").
		WithArgs(1, sqlmock.AnyArg()).
		WillReturnRows(deviceRows)

	mock.ExpectExec("INSERT INTO LoginHistory").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := postLogin(t, map[string]string{"email": "user@test.com", "password": "correct-password"})

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["token"] == nil || resp["token"] == "" {
		t.Error("Expected a JWT token in response")
	}
	if resp["e2ee_public_key"] != "pubkey" {
		t.Errorf("Expected e2ee_public_key 'pubkey', got '%v'", resp["e2ee_public_key"])
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestLoginHandler_2FARequired(t *testing.T) {
	mock, _ := setupLoginTest(t)
	hash, err := cryptography.HashPassword("correct-password")
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	rows := sqlmock.NewRows([]string{"id", "password_hash", "totp_enabled", "e2ee_public_key", "e2ee_private_key_encrypted"}).
		AddRow(1, hash, true, "", "")
	mock.ExpectQuery("SELECT id, password_hash, totp_enabled").
		WithArgs("user@test.com").
		WillReturnRows(rows)

	deviceRows := sqlmock.NewRows([]string{"count"}).AddRow(0)
	mock.ExpectQuery("SELECT COUNT\\(\\*\\) FROM LoginHistory").
		WithArgs(1, sqlmock.AnyArg()).
		WillReturnRows(deviceRows)

	mock.ExpectExec("INSERT INTO LoginHistory").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := postLogin(t, map[string]string{"email": "user@test.com", "password": "correct-password"})

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["requires_totp"] != true {
		t.Error("Expected requires_totp to be true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}
