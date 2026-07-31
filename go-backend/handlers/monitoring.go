package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/Hadidomena/projektKomunikator/honeypot"
	"github.com/Hadidomena/projektKomunikator/login_monitoring"
)

func IsAdmin(userID int) (bool, error) {
	var isAdmin bool
	err := ctx.DB.QueryRow("SELECT is_admin FROM Users WHERE id = $1", userID).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin, nil
}

type contextKey string

const (
	ContextKeyUserID    contextKey = "userID"
	ContextKeyUserEmail contextKey = "userEmail"
)

func GetLoginHistoryHandler(w http.ResponseWriter, r *http.Request, userID int, userEmail string) {
	history, err := login_monitoring.GetLoginHistory(ctx.DB, userID, 20)
	if err != nil {
		log.Printf("Error fetching login history: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to fetch login history"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(history)
}

func GetHoneypotStatsHandler(w http.ResponseWriter, r *http.Request, userID int, userEmail string) {
	stats, err := honeypot.GetHoneypotStats(ctx.DB, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		log.Printf("Error fetching honeypot stats: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to fetch statistics"})
		return
	}

	topIPs, err := honeypot.GetTopAttackingIPs(ctx.DB, 10)
	if err != nil {
		log.Printf("Error fetching top IPs: %v", err)
	} else {
		stats["top_ips"] = topIPs
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

func LoginHistoryHandler(w http.ResponseWriter, r *http.Request) {
	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}
	GetLoginHistoryHandler(w, r, userID, userEmail)
}

func HoneypotStatsHandler(w http.ResponseWriter, r *http.Request) {
	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Unauthorized"})
		return
	}

	admin, err := IsAdmin(userID)
	if err != nil || !admin {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Admin access required"})
		return
	}

	GetHoneypotStatsHandler(w, r, userID, userEmail)
}

func GetUserFromContext(r *http.Request) (int, string, error) {
	userID, ok := r.Context().Value(ContextKeyUserID).(int)
	if !ok {
		return 0, "", fmt.Errorf("user ID not found in context")
	}

	userEmail, ok := r.Context().Value(ContextKeyUserEmail).(string)
	if !ok {
		return 0, "", fmt.Errorf("user email not found in context")
	}

	return userID, userEmail, nil
}
