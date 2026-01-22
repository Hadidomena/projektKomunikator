package handlers_test

import (
	"encoding/json"
	"testing"

	"github.com/Hadidomena/projektKomunikator/handlers"
)

func TestRegistrationRequest(t *testing.T) {
	req := handlers.RegistrationRequest{
		Username: "testuser",
		Email:    "test@example.com",
		Password: "securePassword123",
		Website:  "",
	}

	if req.Username != "testuser" {
		t.Errorf("Username = %s, expected testuser", req.Username)
	}
	if req.Email != "test@example.com" {
		t.Errorf("Email = %s, expected test@example.com", req.Email)
	}
	if req.Password != "securePassword123" {
		t.Errorf("Password = %s, expected securePassword123", req.Password)
	}
}

func TestLoginRequest(t *testing.T) {
	req := handlers.LoginRequest{
		Email:    "user@example.com",
		Password: "myPassword",
	}

	if req.Email != "user@example.com" {
		t.Errorf("Email = %s, expected user@example.com", req.Email)
	}
	if req.Password != "myPassword" {
		t.Errorf("Password = %s, expected myPassword", req.Password)
	}
}

func TestErrorResponse(t *testing.T) {
	resp := handlers.ErrorResponse{
		Message: "Invalid credentials",
	}

	if resp.Message != "Invalid credentials" {
		t.Errorf("Message = %s, expected 'Invalid credentials'", resp.Message)
	}
}

func TestPasswordResetRequest(t *testing.T) {
	req := handlers.PasswordResetRequest{
		Email: "reset@example.com",
	}

	if req.Email != "reset@example.com" {
		t.Errorf("Email = %s, expected reset@example.com", req.Email)
	}
}

func TestPasswordResetVerify(t *testing.T) {
	req := handlers.PasswordResetVerify{
		Token:       "abc123token",
		NewPassword: "newSecurePassword456",
	}

	if req.Token != "abc123token" {
		t.Errorf("Token = %s, expected abc123token", req.Token)
	}
	if req.NewPassword != "newSecurePassword456" {
		t.Errorf("NewPassword = %s, expected newSecurePassword456", req.NewPassword)
	}
}

func TestRegistrationRequestJSON(t *testing.T) {
	jsonData := `{"username":"john","email":"john@example.com","password":"pass123","website":""}`

	var req handlers.RegistrationRequest
	err := json.Unmarshal([]byte(jsonData), &req)

	if err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if req.Username != "john" {
		t.Errorf("Username = %s, expected john", req.Username)
	}
	if req.Email != "john@example.com" {
		t.Errorf("Email = %s, expected john@example.com", req.Email)
	}
}

func TestErrorResponseJSON(t *testing.T) {
	resp := handlers.ErrorResponse{Message: "Test error"}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	expected := `{"message":"Test error"}`
	if string(data) != expected {
		t.Errorf("JSON = %s, expected %s", string(data), expected)
	}
}
