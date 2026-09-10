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
	maxAttachmentSize     = 15 * 1024 * 1024
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
	ReceiverEmail string       `json:"receiver_email"`
	Content       string       `json:"content"`
	Signature     string       `json:"signature,omitempty"`
	CSRFToken     string       `json:"csrf_token"`
	Attachments   []Attachment `json:"attachments,omitempty"`
	DHPublicKey   string       `json:"dh_public_key,omitempty"`
}

type MessageResponse struct {
	ID                int          `json:"id"`
	SenderEmail       string       `json:"sender_email"`
	ReceiverEmail     string       `json:"receiver_email"`
	Content           string       `json:"content"`
	Signature         string       `json:"signature,omitempty"`
	IsRead            bool         `json:"is_read"`
	CreatedAt         time.Time    `json:"created_at"`
	ReadAt            *time.Time   `json:"read_at,omitempty"`
	Attachments       []Attachment `json:"attachments,omitempty"`
	DHPublicKey       string       `json:"dh_public_key,omitempty"`
	ReceiverPublicKey string       `json:"receiver_public_key,omitempty"`
}

type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Size        int64  `json:"size"`
	Data        string `json:"data"`
}

func SendMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	senderID, senderEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req SendMessageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !ctx.CSRFStore.ValidateToken(senderEmail, req.CSRFToken) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid CSRF token"})
		return
	}

	if req.ReceiverEmail == "" || req.Content == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if !validation.ValidateEmail(req.ReceiverEmail) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	for _, att := range req.Attachments {
		if att.Size > maxAttachmentSize {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Attachment too large (max 15MB)"})
			return
		}
	}

	if len(req.Content) > maxMessageContentSize {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message payload too large (max 25MB)"})
		return
	}

	if len(req.Attachments) > 0 {
		log.Printf("Sending encrypted message with %d attachments from %s to %s", len(req.Attachments), senderEmail, req.ReceiverEmail)
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Receiver not found"})
			return
		}
		log.Printf("Failed to get receiver: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to send message"})
		return
	}

	if receiverPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Receiver doesn't have E2EE keys - they need to re-register or update their account"})
		return
	}

	var senderPublicKey string
	err = ctx.DB.QueryRowContext(ctxDB,
		"SELECT COALESCE(e2ee_public_key, '') FROM Users WHERE id = $1",
		senderID).Scan(&senderPublicKey)
	if err != nil || senderPublicKey == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "You don't have E2EE keys - please re-register or update your account"})
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to send message"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":    "Message sent successfully",
		"message_id": messageID,
		"encrypted":  true,
	})
}

func GetInboxHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve messages"})
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve messages"})
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages":   messages,
		"pagination": PaginationMeta{Page: page, Limit: limit, Total: total, TotalPages: totalPages},
	})
}

func GetSentMessagesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, userEmail, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve messages"})
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve messages"})
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"messages":   messages,
		"pagination": PaginationMeta{Page: page, Limit: limit, Total: total, TotalPages: totalPages},
	})
}

func MarkMessageAsReadHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Only PUT method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if req.MessageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := ctx.DB.ExecContext(ctxDB,
		"UPDATE Messages SET is_read = TRUE, read_at = NOW() WHERE id = $1 AND receiver_id = $2 AND is_read = FALSE",
		req.MessageID, userID)
	if err != nil {
		log.Printf("Failed to mark message as read: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to mark message as read"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message not found or already read"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Message marked as read",
	})
}

func GetMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Only GET method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	messageIDStr := r.URL.Query().Get("id")
	if messageIDStr == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message ID required"})
		return
	}

	messageID, err := strconv.Atoi(messageIDStr)
	if err != nil || messageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Invalid message ID"})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var msg MessageResponse
	var senderEmail, receiverEmail string
	var senderID, receiverID int
	var encryptedKey sql.NullString
	var signature sql.NullString
	var receiverPublicKey string

	err = ctx.DB.QueryRowContext(ctxDB, `
		SELECT m.id, m.sender_id, u1.email, m.receiver_id, u2.email, 
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
		&msg.ID, &senderID, &senderEmail, &receiverID, &receiverEmail,
		&msg.Content, &encryptedKey, &signature,
		&msg.IsRead, &msg.CreatedAt, &msg.ReadAt, &msg.DHPublicKey, &receiverPublicKey,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(ErrorResponse{Message: "Message not found"})
			return
		}
		log.Printf("Failed to get message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to retrieve message"})
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

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(msg)
}

func DeleteMessageHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Only DELETE method is allowed", http.StatusMethodNotAllowed)
		return
	}

	userID, _, err := GetUserFromContext(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Authentication required"})
		return
	}

	var req struct {
		MessageID int `json:"message_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	if req.MessageID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(ErrorResponse{Message: validation.GetSanitizedError("validation_failed")})
		return
	}

	ctxDB, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	result, err := ctx.DB.ExecContext(ctxDB, `
		UPDATE Messages 
		SET is_deleted_by_sender = CASE WHEN sender_id = $2 THEN TRUE ELSE is_deleted_by_sender END,
		    is_deleted_by_receiver = CASE WHEN receiver_id = $2 THEN TRUE ELSE is_deleted_by_receiver END
		WHERE id = $1 AND (sender_id = $2 OR receiver_id = $2)
	`, req.MessageID, userID)
	if err != nil {
		log.Printf("Failed to delete message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Failed to delete message"})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(ErrorResponse{Message: "Message not found"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Message deleted successfully",
	})
}
