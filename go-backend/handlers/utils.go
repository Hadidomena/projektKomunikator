package handlers

import (
	"net/http"
	"strings"
)

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return false
	}
	return true
}

func requireAuth(w http.ResponseWriter, r *http.Request) (int, string, bool) {
	userID, email, err := GetUserFromContext(r)
	if err != nil {
		writeUnauthorized(w)
		return 0, "", false
	}
	return userID, email, true
}

func requireAuthOnly(w http.ResponseWriter, r *http.Request) bool {
	_, _, ok := requireAuth(w, r)
	return ok
}

func GetClientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	realIP := r.Header.Get("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	return r.RemoteAddr
}
