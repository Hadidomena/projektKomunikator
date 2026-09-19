package middleware

import (
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func CORSMiddleware(next http.Handler) http.Handler {
	allowedOrigins := strings.Split(os.Getenv("ALLOWED_ORIGINS"), ",")
	if len(allowedOrigins) == 0 || allowedOrigins[0] == "" {
		allowedOrigins = []string{"http://localhost:3000", "http://localhost:4321"}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		allowed := false
		for _, allowedOrigin := range allowedOrigins {
			if strings.TrimSpace(allowedOrigin) == origin {
				allowed = true
				break
			}
		}

		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type RateLimiter struct {
	visitors map[string]*visitor
	mu       sync.RWMutex
	rate     int
	window   time.Duration
}

type visitor struct {
	lastSeen time.Time
	count    int
}

func NewRateLimiter(rate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
	}

	go func() {
		for {
			time.Sleep(time.Minute)
			rl.cleanup()
		}
	}()

	return rl
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	for ip, v := range rl.visitors {
		if time.Since(v.lastSeen) > rl.window {
			delete(rl.visitors, ip)
		}
	}
}

func (rl *RateLimiter) getVisitor(ip string) *visitor {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		rl.visitors[ip] = &visitor{lastSeen: time.Now(), count: 0}
		return rl.visitors[ip]
	}

	if time.Since(v.lastSeen) > rl.window {
		v.count = 0
		v.lastSeen = time.Now()
	}

	return v
}

func (rl *RateLimiter) Allow(ip string) bool {
	v := rl.getVisitor(ip)

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if v.count >= rl.rate {
		return false
	}

	v.count++
	v.lastSeen = time.Now()
	return true
}

func (rl *RateLimiter) RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if idx := strings.LastIndex(ip, ":"); idx != -1 {
			ip = ip[:idx]
		}

		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			ip = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}

		if !rl.Allow(ip) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			if _, err := w.Write([]byte(`{"message":"Too many requests. Please try again later."}`)); err != nil {
				log.Printf("Failed to write rate limit response: %v", err)
			}
			return
		}

		next.ServeHTTP(w, r)
	})
}
