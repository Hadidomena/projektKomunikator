package handlers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hadidomena/projektKomunikator/csrf"
	"github.com/Hadidomena/projektKomunikator/handlers"
)

func TestE2EEConfigHandler(t *testing.T) {
	csrfStore := csrf.NewTokenStore()
	handlers.Initialize(nil, csrfStore, nil, "test-e2ee-pepper")

	r := httptest.NewRequest("GET", "/api/e2ee/config", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.E2EEConfigHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp["pepper"] != "test-e2ee-pepper" {
		t.Errorf("Expected pepper 'test-e2ee-pepper', got '%s'", resp["pepper"])
	}
}

func TestE2EEConfigHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "test-pepper")

	r := httptest.NewRequest("GET", "/api/e2ee/config", nil)
	w := httptest.NewRecorder()

	handlers.E2EEConfigHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestE2EEConfigHandler_WrongMethod(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "test-pepper")

	r := httptest.NewRequest("POST", "/api/e2ee/config", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.E2EEConfigHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestCSRFTokenHandler(t *testing.T) {
	csrfStore := csrf.NewTokenStore()
	handlers.Initialize(nil, csrfStore, nil, "test-pepper")

	r := httptest.NewRequest("GET", "/api/csrf-token", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.CSRFTokenHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp struct {
		Token string `json:"csrf_token"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Token == "" {
		t.Error("Expected non-empty CSRF token")
	}
}

func TestCSRFTokenHandler_Unauthenticated(t *testing.T) {
	handlers.Initialize(nil, nil, nil, "test-pepper")

	r := httptest.NewRequest("GET", "/api/csrf-token", nil)
	w := httptest.NewRecorder()

	handlers.CSRFTokenHandler(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestCSRFTokenHandler_WrongMethod(t *testing.T) {
	csrfStore := csrf.NewTokenStore()
	handlers.Initialize(nil, csrfStore, nil, "test-pepper")

	r := httptest.NewRequest("POST", "/api/csrf-token", nil)
	ctx := context.WithValue(r.Context(), "userID", 1)
	ctx = context.WithValue(ctx, "userEmail", "test@example.com")
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()

	handlers.CSRFTokenHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}
