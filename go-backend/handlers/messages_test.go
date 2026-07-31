package handlers_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/Hadidomena/projektKomunikator/csrf"
	"github.com/Hadidomena/projektKomunikator/handlers"
)

func TestSendMessageHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{
		"receiver_email": "receiver@test.com",
		"content":        "hello",
		"csrf_token":     "token",
	})
	r := httptest.NewRequest("POST", "/api/messages/send", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.SendMessageHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestSendMessageHandler_MissingReceiver(t *testing.T) {
	csrfStore := csrf.NewTokenStore()
	token, _ := csrfStore.CreateToken("sender@test.com", 3600)
	handlers.Initialize(nil, csrfStore, nil, "")

	body, _ := json.Marshal(map[string]string{
		"content":    "hello",
		"csrf_token": token,
	})
	r := httptest.NewRequest("POST", "/api/messages/send", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "sender@test.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.SendMessageHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestSendMessageHandler_WrongMethod(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/send", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.SendMessageHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestGetInboxHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages", nil)
	w := httptest.NewRecorder()

	handlers.GetInboxHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestGetSentMessagesHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/sent", nil)
	w := httptest.NewRecorder()

	handlers.GetSentMessagesHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestGetMessageHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/get?id=1", nil)
	w := httptest.NewRecorder()

	handlers.GetMessageHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestGetMessageHandler_MissingID(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/get", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.GetMessageHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetMessageHandler_InvalidID(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/get?id=abc", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.GetMessageHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestMarkMessageAsReadHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]int{"message_id": 1})
	r := httptest.NewRequest("PUT", "/api/messages/mark-read", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.MarkMessageAsReadHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestMarkMessageAsReadHandler_WrongMethod(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/mark-read", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.MarkMessageAsReadHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestMarkMessageAsReadHandler_InvalidMessageID(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]int{"message_id": 0})
	r := httptest.NewRequest("PUT", "/api/messages/mark-read", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.MarkMessageAsReadHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDeleteMessageHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]int{"message_id": 1})
	r := httptest.NewRequest("DELETE", "/api/messages/delete", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.DeleteMessageHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestDeleteMessageHandler_WrongMethod(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/messages/delete", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.DeleteMessageHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestDeleteMessageHandler_InvalidMessageID(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]int{"message_id": -1})
	r := httptest.NewRequest("DELETE", "/api/messages/delete", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.DeleteMessageHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestSendMessageHandler_ReceiverNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	csrfStore := csrf.NewTokenStore()
	token, _ := csrfStore.CreateToken("sender@test.com", 3600)
	handlers.Initialize(db, csrfStore, nil, "")

	mock.ExpectQuery("SELECT id, COALESCE\\(e2ee_public_key, ''\\) FROM Users WHERE email = \\$1").
		WithArgs("nonexistent@test.com").
		WillReturnError(sqlmock.ErrCancelled)

	body, _ := json.Marshal(handlers.SendMessageRequest{
		ReceiverEmail: "nonexistent@test.com",
		Content:       "hello",
		CSRFToken:     token,
	})
	r := httptest.NewRequest("POST", "/api/messages/send", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "sender@test.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.SendMessageHandler(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestGetUserPublicKeyHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/user/public-key?email=test@test.com", nil)
	w := httptest.NewRecorder()

	handlers.GetUserPublicKeyHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestGetUserPublicKeyHandler_MissingEmail(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/user/public-key", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.GetUserPublicKeyHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetUserPublicKeyHandler_InvalidEmail(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/user/public-key?email=invalid", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.GetUserPublicKeyHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestUpdateUserPublicKeyHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	body, _ := json.Marshal(map[string]string{"e2ee_public_key": "key"})
	r := httptest.NewRequest("POST", "/api/user/update-public-key", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.UpdateUserPublicKeyHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestUpdateUserPublicKeyHandler_MissingKey(t *testing.T) {
	csrfStore := csrf.NewTokenStore()
	token, _ := csrfStore.CreateToken("test@example.com", 3600)
	handlers.Initialize(nil, csrfStore, nil, "")

	body, _ := json.Marshal(map[string]string{"csrf_token": token})
	r := httptest.NewRequest("POST", "/api/user/update-public-key", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.UpdateUserPublicKeyHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestGetE2EEKeysHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "")

	r := httptest.NewRequest("GET", "/api/e2ee/keys", nil)
	w := httptest.NewRecorder()

	handlers.GetE2EEKeysHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestGetE2EEKeysHandler_NoKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	handlers.Initialize(db, nil, nil, "")

	rows := sqlmock.NewRows([]string{"e2ee_public_key", "e2ee_private_key_encrypted"}).
		AddRow("", "")
	mock.ExpectQuery("SELECT COALESCE\\(e2ee_public_key, ''\\), COALESCE\\(e2ee_private_key_encrypted, ''\\) FROM Users WHERE id = \\$1").
		WithArgs(1).
		WillReturnRows(rows)

	r := httptest.NewRequest("GET", "/api/e2ee/keys", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.GetE2EEKeysHandler(w, r)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unmet mock expectations: %v", err)
	}
}
