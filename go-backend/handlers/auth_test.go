package handlers_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Hadidomena/projektKomunikator/handlers"
)

func TestCheckPasswordStrengthHandler(t *testing.T) {
	req := map[string]string{
		"password": "StrongP@ssw0rd123",
	}
	body, _ := json.Marshal(req)

	r := httptest.NewRequest("POST", "/api/check-password-strength", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CheckPasswordStrengthHandler(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestCheckPasswordStrengthHandler_InvalidMethod(t *testing.T) {
	r := httptest.NewRequest("GET", "/api/check-password-strength", nil)
	w := httptest.NewRecorder()

	handlers.CheckPasswordStrengthHandler(w, r)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status 405, got %d", w.Code)
	}
}

func TestCheckPasswordStrengthHandler_InvalidJSON(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/check-password-strength", bytes.NewReader([]byte("invalid json")))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CheckPasswordStrengthHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}
