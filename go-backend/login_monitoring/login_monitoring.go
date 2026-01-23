package login_monitoring

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

type LoginAttempt struct {
	UserID            int       `json:"user_id"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	Success           bool      `json:"success"`
	NewDevice         bool      `json:"new_device"`
	LoginTime         time.Time `json:"login_time"`
	Country           string    `json:"country"`
	City              string    `json:"city"`
}

func GenerateDeviceFingerprint(ipAddress, userAgent string) string {
	data := fmt.Sprintf("%s|%s", ipAddress, normalizeUserAgent(userAgent))
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func normalizeUserAgent(ua string) string {
	ua = strings.ToLower(ua)
	parts := strings.Fields(ua)
	if len(parts) > 0 {
		return parts[0]
	}
	return ua
}

func RecordLoginAttempt(db *sql.DB, attempt *LoginAttempt) error {
	query := `
		INSERT INTO LoginHistory (user_id, ip_address, user_agent, device_fingerprint, success, new_device, country, city)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`

	_, err := db.Exec(query,
		attempt.UserID,
		attempt.IPAddress,
		attempt.UserAgent,
		attempt.DeviceFingerprint,
		attempt.Success,
		attempt.NewDevice,
		attempt.Country,
		attempt.City,
	)

	return err
}

func IsNewDevice(db *sql.DB, userID int, deviceFingerprint string) (bool, error) {
	query := `
		SELECT COUNT(*) FROM LoginHistory 
		WHERE user_id = $1 AND device_fingerprint = $2 AND success = TRUE
	`

	var count int
	err := db.QueryRow(query, userID, deviceFingerprint).Scan(&count)
	if err != nil {
		return false, err
	}

	return count == 0, nil
}

func GetLoginHistory(db *sql.DB, userID int, limit int) ([]LoginAttempt, error) {
	query := `
		SELECT user_id, ip_address, user_agent, device_fingerprint, success, new_device, login_time, 
		       COALESCE(country, ''), COALESCE(city, '')
		FROM LoginHistory
		WHERE user_id = $1
		ORDER BY login_time DESC
		LIMIT $2
	`

	rows, err := db.Query(query, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var history []LoginAttempt
	for rows.Next() {
		var attempt LoginAttempt
		err := rows.Scan(
			&attempt.UserID,
			&attempt.IPAddress,
			&attempt.UserAgent,
			&attempt.DeviceFingerprint,
			&attempt.Success,
			&attempt.NewDevice,
			&attempt.LoginTime,
			&attempt.Country,
			&attempt.City,
		)
		if err != nil {
			return nil, err
		}
		history = append(history, attempt)
	}

	return history, nil
}

func GetRecentLoginCount(db *sql.DB, userID int, since time.Time) (int, error) {
	query := `
		SELECT COUNT(*) FROM LoginHistory 
		WHERE user_id = $1 AND login_time > $2
	`

	var count int
	err := db.QueryRow(query, userID, since).Scan(&count)
	return count, err
}
