package handlers_test

import (
	"net/http/httptest"
	"testing"

	"github.com/Hadidomena/projektKomunikator/handlers"
)

func TestGetClientIP_XForwardedFor(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.1, 198.51.100.1")

	ip := handlers.GetClientIP(r)

	if ip != "203.0.113.1" {
		t.Errorf("Expected IP 203.0.113.1, got %s", ip)
	}
}

func TestGetClientIP_XRealIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Real-IP", "203.0.113.5")

	ip := handlers.GetClientIP(r)

	if ip != "203.0.113.5" {
		t.Errorf("Expected IP 203.0.113.5, got %s", ip)
	}
}

func TestGetClientIP_RemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.RemoteAddr = "192.168.1.100:12345"

	ip := handlers.GetClientIP(r)

	if ip != "192.168.1.100:12345" {
		t.Errorf("Expected IP 192.168.1.100:12345, got %s", ip)
	}
}

func TestGetClientIP_Priority(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	r.Header.Set("X-Real-IP", "203.0.113.5")
	r.RemoteAddr = "192.168.1.100:12345"

	ip := handlers.GetClientIP(r)

	if ip != "203.0.113.1" {
		t.Errorf("X-Forwarded-For should have priority, got %s", ip)
	}
}

func TestGetClientIP_XForwardedForWithSpaces(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Header.Set("X-Forwarded-For", "  203.0.113.1  , 198.51.100.1")

	ip := handlers.GetClientIP(r)

	if ip != "203.0.113.1" {
		t.Errorf("Expected trimmed IP 203.0.113.1, got %s", ip)
	}
}

func TestGetUserFromContext_NoUserID(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)

	userID, email, err := handlers.GetUserFromContext(r)

	if err == nil {
		t.Error("Expected error when no userID in context")
	}
	if userID != 0 {
		t.Errorf("Expected userID 0, got %d", userID)
	}
	if email != "" {
		t.Errorf("Expected empty email, got %s", email)
	}
}
