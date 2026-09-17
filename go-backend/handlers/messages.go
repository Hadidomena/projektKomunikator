package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Hadidomena/projektKomunikator/validation"
)

const (
	maxMessageContentSize = 25 * 1024 * 1024
)

type PaginationMeta struct {
	Page       int `json:"page"`
	Limit      int `json:"limit"`
	Total      int `json:"total"`
	TotalPages int `json:"total_pages"`
}

func parsePagination(r *http.Request) (int, int) {
	page := 1
	limit := 20
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 && v <= 100 {
			limit = v
		}
	}
	return page, limit
}

func clampPage(page, totalPages int) int {
	if page > totalPages {
		if totalPages > 0 {
			return totalPages
		}
		return 1
	}
	return page
}

type SendMessageRequest struct {
	ReceiverEmail string `json:"receiver_email"`
	Content       string `json:"content"`
	Signature     string `json:"signature,omitempty"`
	CSRFToken     string `json:"csrf_token"`
	DHPublicKey   string `json:"dh_public_key,omitempty"`
}

type MessageResponse struct {
	ID                int        `json:"id"`
	SenderEmail       string     `json:"sender_email"`
	ReceiverEmail     string     `json:"receiver_email"`
	Content           string     `json:"content"`
	Signature         string     `json:"signature,omitempty"`
	IsRead            bool       `json:"is_read"`
	CreatedAt         time.Time  `json:"created_at"`
	ReadAt            *time.Time `json:"read_at,omitempty"`
	DHPublicKey       string     `json:"dh_public_key,omitempty"`
	ReceiverPublicKey string     `json:"receiver_public_key,omitempty"`
}

func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}

	senderID, senderEmail, err := GetUserFromContext(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	var req SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	if !ctx.CSRFStore.ValidateToken(senderEmail, req.CSRFToken) {
		writeError(w, http.StatusForbidden, "Invalid CSRF token")
		return
	}

	if req.ReceiverEmail == "" || req.Content == "" {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	if !validation.ValidateEmail(req.ReceiverEmail) {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return
	}

	if len(req.Content) > maxMessageContentSize {
		writeError(w, http.StatusBadRequest, "Message payload too large (max 25MB)")
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var receiverID int
	var receiverPublicKey string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT id, COALESCE(e2ee_public_key, '') FROM Users WHERE email = $1",
		strings.ToLower(req.ReceiverEmail)).Scan(&receiverID, &receiverPublicKey)
	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "Receiver not found")
			return
		}
		log.Printf("Failed to get receiver: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to send message")
		return
	}

	if receiverPublicKey == "" {
		writeError(w, http.StatusBadRequest, "Receiver doesn't have E2EE keys - they need to re-register or update their account")
		return
	}

	var senderPublicKey string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE id = $1",
		senderID).Scan(&senderPublicKey)
	if err != nil || senderPublicKey == "" {
		writeError(w, http.StatusBadRequest, "You don't have E2EE keys - please re-register or update your account")
		return
	}

	contentToStore := req.Content
	encKeyStr := "client-e2ee"

	var messageID int
	err = ctx.DB.QueryRowContext(ctxDB,
		"INSERT INTO Messages (sender_id, receiver_id, content, encrypted_key, message_signature, dh_public_key) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
		senderID, receiverID, contentToStore, encKeyStr, req.Signature, req.DHPublicKey).Scan(&messageID)
	if err != nil {
		log.Printf("Failed to insert message: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to send message")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"message":    "Message sent successfully",
		"message_id": messageID,
		"encrypted":  true,
	})
}

func GetInboxHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	page, limit := parsePagination(r)

	ctxDB, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var total int
	err = ctx.DB.QueryRowContext(ctxDB, `
		SELECT COUNT(*) FROM Messages m
		WHERE m.receiver_id = $1 AND m.is_deleted_by_receiver = FALSE
	`, userID).Scan(&total)
	if err != nil {
		log.Printf("Failed to count inbox messages: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve messages")
		return
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}
	page = clampPage(page, totalPages)
	offset := (page - 1) * limit

	rows, err := ctx.DB.QueryContext(ctxDB, `
		SELECT m.id, u.email, m.content, m.message_signature, m.is_read, m.created_at, m.read_at,
		       COALESCE(m.dh_public_key, '')
		FROM Messages m
		JOIN Users u ON m.sender_id = u.id
		WHERE m.receiver_id = $1 AND m.is_deleted_by_receiver = FALSE
		ORDER BY m.created_at DESC, m.id DESC
		LIMIT $2 OFFSET $3
	`, userID, limit, offset)
	if err != nil {
		log.Printf("Failed to get messages: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve messages")
		return
	}
	defer rows.Close()

	messages := []MessageResponse{}
	for rows.Next() {
		var msg MessageResponse
		var senderEmail string
		var signature sql.NullString
		err := rows.Scan(&msg.ID, &senderEmail, &msg.Content, &signature, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt,
			&msg.DHPublicKey)
		if err != nil {
			log.Printf("Failed to scan message: %v", err)
			continue
		}
		msg.SenderEmail = senderEmail
		msg.ReceiverEmail = userEmail
		if signature.Valid {
			msg.Signature = signature.String
		}
		messages = append(messages, msg)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"messages":   messages,
		"pagination": PaginationMeta{Page: page, Limit: limit, Total: total, TotalPages: totalPages},
	})
}

func GetSentMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	page, limit := parsePagination(r)

	ctxDB, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var total int
	err = ctx.DB.QueryRowContext(ctxDB, `
		SELECT COUNT(*) FROM Messages m
		WHERE m.sender_id = $1 AND m.is_deleted_by_sender = FALSE
	`, userID).Scan(&total)
	if err != nil {
		log.Printf("Failed to count sent messages: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve messages")
		return
	}

	totalPages := int(math.Ceil(float64(total) / float64(limit)))
	if totalPages < 1 {
		totalPages = 1
	}
	page = clampPage(page, totalPages)
	offset := (page - 1) * limit

	rows, err := ctx.DB.QueryContext(ctxDB, `
		SELECT m.id, u.email, m.content, m.is_read, m.created_at, m.read_at,
		       COALESCE(m.dh_public_key, ''), COALESCE(u.e2ee_public_key, '')
		FROM Messages m
		JOIN Users u ON m.receiver_id = u.id
		WHERE m.sender_id = $1 AND m.is_deleted_by_sender = FALSE
		ORDER BY m.created_at DESC, m.id DESC
		LIMIT $2 OFFSET $3
	`, userID, limit, offset)
	if err != nil {
		log.Printf("Failed to get sent messages: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve messages")
		return
	}
	defer rows.Close()

	messages := []MessageResponse{}
	for rows.Next() {
		var msg MessageResponse
		var receiverEmail string
		var receiverPublicKey string
		err := rows.Scan(&msg.ID, &receiverEmail, &msg.Content, &msg.IsRead, &msg.CreatedAt, &msg.ReadAt,
			&msg.DHPublicKey, &receiverPublicKey)
		if err != nil {
			log.Printf("Failed to scan message: %v", err)
			continue
		}
		msg.SenderEmail = userEmail
		msg.ReceiverEmail = receiverEmail
		msg.ReceiverPublicKey = receiverPublicKey
		messages = append(messages, msg)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"messages":   messages,
		"pagination": PaginationMeta{Page: page, Limit: limit, Total: total, TotalPages: totalPages},
	})
}

func decodeMessageID(w http.ResponseWriter, r *http.Request) (int, bool) {
	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.MessageID <= 0 {
		writeError(w, http.StatusBadRequest, validation.GetSanitizedError("validation_failed"))
		return 0, false
	}
	return req.MessageID, true
}

func MarkMessageAsReadHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	messageID, ok := decodeMessageID(w, r)
	if !ok {
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := ctx.DB.ExecContext(ctxDB,
		"UPDATE Messages SET is_read = TRUE, read_at = NOW() WHERE id = $1 AND receiver_id = $2 AND is_read = FALSE",
		messageID, userID)
	if err != nil {
		log.Printf("Failed to mark message as read: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to mark message as read")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeError(w, http.StatusNotFound, "Message not found or already read")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Message marked as read",
	})
}

func GetMessageHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	messageIDStr := r.URL.Query().Get("id")
	if messageIDStr == "" {
		writeError(w, http.StatusBadRequest, "Message ID required")
		return
	}

	messageID, err := strconv.Atoi(messageIDStr)
	if err != nil || messageID <= 0 {
		writeError(w, http.StatusBadRequest, "Invalid message ID")
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var msg MessageResponse
	var senderEmail, receiverEmail string
	var encryptedKey sql.NullString
	var signature sql.NullString
	var receiverPublicKey string

	err = ctx.DB.QueryRowContext(ctxDB, `
		SELECT m.id, u1.email, u2.email,
		       m.content, m.encrypted_key, m.message_signature,
		       m.is_read, m.created_at, m.read_at, COALESCE(m.dh_public_key, ''),
		       COALESCE(u2.e2ee_public_key, '')
		FROM Messages m
		JOIN Users u1 ON m.sender_id = u1.id
		JOIN Users u2 ON m.receiver_id = u2.id
		WHERE m.id = $1
		  AND (m.sender_id = $2 OR m.receiver_id = $2)
		  AND ((m.sender_id = $2 AND m.is_deleted_by_sender = FALSE)
		       OR (m.receiver_id = $2 AND m.is_deleted_by_receiver = FALSE))
	`, messageID, userID).Scan(
		&msg.ID, &senderEmail, &receiverEmail,
		&msg.Content, &encryptedKey, &signature,
		&msg.IsRead, &msg.CreatedAt, &msg.ReadAt, &msg.DHPublicKey, &receiverPublicKey,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			writeError(w, http.StatusNotFound, "Message not found")
			return
		}
		log.Printf("Failed to get message: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to retrieve message")
		return
	}

	msg.SenderEmail = senderEmail
	msg.ReceiverEmail = receiverEmail
	msg.ReceiverPublicKey = receiverPublicKey
	if signature.Valid {
		msg.Signature = signature.String
	}

	if !(encryptedKey.Valid && encryptedKey.String == "client-e2ee") {
		log.Printf("Warning: Message %d is not marked as encrypted\n", msg.ID)
	}

	writeJSON(w, http.StatusOK, msg)
}

func DeleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodDelete) {
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Authentication required")
		return
	}

	messageID, ok := decodeMessageID(w, r)
	if !ok {
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := ctx.DB.ExecContext(ctxDB, `
		UPDATE Messages
		SET is_deleted_by_sender = CASE WHEN sender_id = $2 THEN TRUE ELSE is_deleted_by_sender END,
		    is_deleted_by_receiver = CASE WHEN receiver_id = $2 THEN TRUE ELSE is_deleted_by_receiver END
		WHERE id = $1 AND (sender_id = $2 OR receiver_id = $2)
	`, messageID, userID)
	if err != nil {
		log.Printf("Failed to delete message: %v", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete message")
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		writeError(w, http.StatusNotFound, "Message not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"message": "Message deleted successfully",
	})
}
