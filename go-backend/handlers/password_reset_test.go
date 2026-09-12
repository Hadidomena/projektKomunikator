package handlers_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Hadidomena/projektKomunikator/cryptography"
	"github.com/Hadidomena/projektKomunikator/handlers"
	passwordutils "github.com/Hadidomena/projektKomunikator/password_utils"
)

func setupPasswordResetTest(t *testing.T) sqlmock.Sqlmock {
	t.Helper()
	cryptography.SetPepper("test-reset-pepper")
	_ = passwordutils.LoadCommonPasswords()

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	handlers.Initialize(db, nil, nil, "")
	return mock
}

func postPasswordResetRequest(t *testing.T, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/password-reset/request", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.PasswordResetRequestHandler(w, r)
	return w
}

func TestPasswordResetRequestHandler_InvalidJSON(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest(http.MethodPost, "/api/password-reset/request", bytes.NewReader([]byte("invalid")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.PasswordResetRequestHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestPasswordResetRequestHandler_InvalidEmail(t *testing.T) {
	setupPasswordResetTest(t)
	w := postPasswordResetRequest(t, map[string]string{"email": "not-an-email"})

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}

func TestPasswordResetRequestHandler_UserNotFound(t *testing.T) {
	mock := setupPasswordResetTest(t)
	mock.ExpectQuery("SELECT id FROM Users WHERE email = \\$1").
		WithArgs("ghost@test.com").
		WillReturnError(sql.ErrNoRows)
	w := postPasswordResetRequest(t, map[string]string{"email": "ghost@test.com"})

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestPasswordResetRequestHandler_Success(t *testing.T) {
	mock := setupPasswordResetTest(t)
	rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
	mock.ExpectQuery("SELECT id FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)
	mock.ExpectExec("INSERT INTO PasswordResetTokens").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(1, 1))

	w := postPasswordResetRequest(t, map[string]string{"email": "user@test.com"})

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestPasswordResetRequestHandler_DBError(t *testing.T) {
	mock := setupPasswordResetTest(t)
	rows := sqlmock.NewRows([]string{"id"}).AddRow(1)
	mock.ExpectQuery("SELECT id FROM Users WHERE email = \\$1").
		WithArgs("user@test.com").
		WillReturnRows(rows)
	mock.ExpectExec("INSERT INTO PasswordResetTokens").
		WithArgs(1, sqlmock.AnyArg(), sqlmock.AnyArg()).
		WillReturnError(sqlmock.ErrCancelled)

	w := postPasswordResetRequest(t, map[string]string{"email": "user@test.com"})

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected 500, got %d", w.Code)
	}
}

func postPasswordResetVerify(t *testing.T, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(body)
	r := httptest.NewRequest(http.MethodPost, "/api/password-reset/verify", bytes.NewReader(payload))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.PasswordResetVerifyHandler(w, r)
	return w
}

func TestPasswordResetVerifyHandler_InvalidJSON(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest(http.MethodPost, "/api/password-reset/verify", bytes.NewReader([]byte("invalid")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handlers.PasswordResetVerifyHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestPasswordResetVerifyHandler_MissingFields(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	w := postPasswordResetVerify(t, map[string]string{})

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestPasswordResetVerifyHandler_WeakPassword(t *testing.T) {
	setupPasswordResetTest(t)

	w := postPasswordResetVerify(t, map[string]string{
		"token":        "some-token",
		"new_password": "short",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
}

func TestPasswordResetVerifyHandler_InvalidToken(t *testing.T) {
	mock := setupPasswordResetTest(t)
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE PasswordResetTokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)
	mock.ExpectRollback()

	w := postPasswordResetVerify(t, map[string]string{
		"token":        "invalid-token",
		"new_password": "NewStrongP@ssw0rd123",
	})

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected 400, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}

func TestPasswordResetVerifyHandler_Success(t *testing.T) {
	mock := setupPasswordResetTest(t)
	mock.ExpectBegin()
	mock.ExpectQuery("UPDATE PasswordResetTokens").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"user_id"}).AddRow(1))
	mock.ExpectExec("UPDATE PasswordResetTokens").
		WithArgs(1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec("UPDATE Users SET password_hash").
		WithArgs(sqlmock.AnyArg(), 1).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	w := postPasswordResetVerify(t, map[string]string{
		"token":        "valid-token",
		"new_password": "NewStrongP@ssw0rd123",
	})

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}
