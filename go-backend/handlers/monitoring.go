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
	var isAdmin bool
	err := ctx.DB.QueryRow("SELECT COALESCE((SELECT TRUE FROM Users WHERE id = $1 AND email LIKE '%@admin.%'), FALSE)", userID).Scan(&isAdmin)
	if err != nil || !isAdmin {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Forbidden"})
		return
	}

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

func GetUserFromContext(r *http.Request) (int, string, error) {
	userID, ok := r.Context().Value("userID").(int)
	if !ok {
		return 0, "", fmt.Errorf("user ID not found in context")
	}

	userEmail, ok := r.Context().Value("userEmail").(string)
	if !ok {
		return 0, "", fmt.Errorf("user email not found in context")
	}

	return userID, userEmail, nil
}
