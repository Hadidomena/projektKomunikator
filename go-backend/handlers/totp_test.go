package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Hadidomena/projektKomunikator/handlers"
)

func TestTOTPStatusHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/2fa/status", nil)
	w := httptest.NewRecorder()

	handlers.TOTPStatusHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestTOTPStatusHandler_WrongMethod(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("POST", "/api/2fa/status", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.TOTPStatusHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestTOTPStatusHandler_Enabled(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	handlers.Initialize(db, nil, nil, "")

	rows := sqlmock.NewRows([]string{"totp_enabled", "totp_secret"}).
		AddRow(true, "encrypted-secret")
	mock.ExpectQuery("SELECT totp_enabled, totp_secret FROM Users WHERE id = \\$1").
		WithArgs(1).
		WillReturnRows(rows)

	r := httptest.NewRequest("GET", "/api/2fa/status", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.TOTPStatusHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["enabled"] != true {
		t.Error("Expected TOTP to be enabled")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestTOTPStatusHandler_SetupInProgress(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	handlers.Initialize(db, nil, nil, "")

	rows := sqlmock.NewRows([]string{"totp_enabled", "totp_secret"}).
		AddRow(false, "encrypted-secret")
	mock.ExpectQuery("SELECT totp_enabled, totp_secret FROM Users WHERE id = \\$1").
		WithArgs(1).
		WillReturnRows(rows)

	r := httptest.NewRequest("GET", "/api/2fa/status", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.TOTPStatusHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)

	if resp["enabled"] != false {
		t.Error("Expected TOTP to be disabled")
	}
	if resp["setup_in_progress"] != true {
		t.Error("Expected setup_in_progress to be true")
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestTOTPSetupHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{"password": "testpass"})
	r := httptest.NewRequest("POST", "/api/2fa/setup", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.TOTPSetupHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestTOTPSetupHandler_MissingPassword(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{})
	r := httptest.NewRequest("POST", "/api/2fa/setup", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.TOTPSetupHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestTOTPValidateHandler_InvalidEmail(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{
		"email":    "invalid",
		"password": "pass",
		"totp_code": "123456",
	})
	r := httptest.NewRequest("POST", "/api/2fa/validate", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.TOTPValidateHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestTOTPDisableHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{"csrf_token": "token"})
	r := httptest.NewRequest("POST", "/api/2fa/disable", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.TOTPDisableHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestTOTPVerifyHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{
		"code":       "123456",
		"csrf_token": "token",
	})
	r := httptest.NewRequest("POST", "/api/2fa/verify", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.TOTPVerifyHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}
