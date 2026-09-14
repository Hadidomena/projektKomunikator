package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

func TestCORSMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	os.Setenv("ALLOWED_ORIGINS", "http://localhost:3000")
	defer os.Unsetenv("ALLOWED_ORIGINS")

	middleware := CORSMiddleware(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:3000" {
		t.Error("Allowed origin not set correctly")
	}

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.Header.Set("Origin", "http://evil.com")
	rec2 := httptest.NewRecorder()
	middleware.ServeHTTP(rec2, req2)

	if rec2.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("Disallowed origin should not be set")
	}

	req3 := httptest.NewRequest("OPTIONS", "/test", nil)
	req3.Header.Set("Origin", "http://localhost:3000")
	rec3 := httptest.NewRecorder()
	middleware.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Errorf("OPTIONS should return 200, got %d", rec3.Code)
	}
}

func TestRateLimiter(t *testing.T) {
	rl := NewRateLimiter(3, time.Second)

	if rl == nil {
		t.Fatal("NewRateLimiter returned nil")
	}

	ip := "192.168.1.1"

	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	if rl.Allow(ip) {
		t.Error("4th request should be denied")
	}

	if !rl.Allow("192.168.1.2") {
		t.Error("Different IP should be allowed")
	}

	window := 100 * time.Millisecond
	rl2 := NewRateLimiter(1, window)
	rl2.Allow(ip)
	if rl2.Allow(ip) {
		t.Error("Should be denied before window reset")
	}
	time.Sleep(window + 10*time.Millisecond)
	if !rl2.Allow(ip) {
		t.Error("Should be allowed after window reset")
	}

	rl3 := NewRateLimiter(100, time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rl3.Allow(ip)
		}()
	}
	wg.Wait()

	rl3.mu.RLock()
	v, exists := rl3.visitors[ip]
	rl3.mu.RUnlock()

	if !exists {
		t.Fatal("Visitor should exist")
	}
	if v.count != 50 {
		t.Errorf("Expected count 50, got %d", v.count)
	}
}

func TestRateLimitMiddleware(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	rl := NewRateLimiter(2, time.Second)
	middleware := rl.RateLimitMiddleware(handler)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		middleware.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Request %d: expected 200, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest("GET", "/test", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	middleware.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("Expected 429, got %d", rec.Code)
	}

	req2 := httptest.NewRequest("GET", "/test", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	req2.Header.Set("X-Forwarded-For", "192.168.1.100")
	rec2 := httptest.NewRecorder()
	middleware.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Error("X-Forwarded-For IP should have separate limit")
	}
}
