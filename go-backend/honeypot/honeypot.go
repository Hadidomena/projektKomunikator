package honeypot

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

type HoneypotAttempt struct {
	IPAddress     string
	UserAgent     string
	HoneypotField string
	HoneypotValue string
	SubmittedData map[string]interface{}
	AttemptTime   time.Time
	Blocked       bool
}

const (
	HoneypotFieldName = "website"
)

func CheckHoneypot(fieldValue string) bool {
	return fieldValue != ""
}

func RecordHoneypotAttempt(db *sql.DB, attempt *HoneypotAttempt) error {
	dataJSON, err := json.Marshal(attempt.SubmittedData)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	query := `
		INSERT INTO HoneypotAttempts (ip_address, user_agent, honeypot_field, honeypot_value, submitted_data, blocked)
		VALUES ($1, $2, $3, $4, $5, $6)
	`

	_, err = db.Exec(query,
		attempt.IPAddress,
		attempt.UserAgent,
		attempt.HoneypotField,
		attempt.HoneypotValue,
		dataJSON,
		attempt.Blocked,
	)

	return err
}

func GetHoneypotStats(db *sql.DB, since time.Time) (map[string]interface{}, error) {
	query := `
		SELECT 
			COUNT(*) as total_attempts,
			COUNT(DISTINCT ip_address) as unique_ips,
			COUNT(*) FILTER (WHERE blocked = TRUE) as blocked_attempts
		FROM HoneypotAttempts
		WHERE attempt_time > $1
	`

	var totalAttempts, uniqueIPs, blockedAttempts int
	err := db.QueryRow(query, since).Scan(&totalAttempts, &uniqueIPs, &blockedAttempts)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"total_attempts":   totalAttempts,
		"unique_ips":       uniqueIPs,
		"blocked_attempts": blockedAttempts,
		"since":            since,
	}, nil
}

func GetTopAttackingIPs(db *sql.DB, limit int) ([]map[string]interface{}, error) {
	query := `
		SELECT ip_address, COUNT(*) as attempts
		FROM HoneypotAttempts
		WHERE blocked = TRUE
		GROUP BY ip_address
		ORDER BY attempts DESC
		LIMIT $1
	`

	rows, err := db.Query(query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var ip string
		var attempts int
		if err := rows.Scan(&ip, &attempts); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"ip":       ip,
			"attempts": attempts,
		})
	}

	return results, nil
}

func IsIPBlocked(db *sql.DB, ipAddress string, threshold int, window time.Duration) (bool, error) {
	query := `
		SELECT COUNT(*) FROM HoneypotAttempts
		WHERE ip_address = $1 AND attempt_time > $2 AND blocked = TRUE
	`

	since := time.Now().Add(-window)
	var count int
	err := db.QueryRow(query, ipAddress, since).Scan(&count)
	if err != nil {
		return false, err
	}

	return count >= threshold, nil
}
