package handlers

type RegistrationRequest struct {
	Username                string `json:"username"`
	Email                   string `json:"email"`
	Password                string `json:"password"`
	Website                 string `json:"website"`
	E2EEPublicKey           string `json:"e2ee_public_key,omitempty"`
	E2EEPrivateKeyEncrypted string `json:"e2ee_private_key_encrypted,omitempty"`
}

type LoginRequest struct {
	Email      string `json:"email"`
	Password   string `json:"password"`
	Website    string `json:"website,omitempty"`     // Honeypot field 1
	Phone      string `json:"phone,omitempty"`       // Honeypot field 2
	MiddleName string `json:"middle_name,omitempty"` // Honeypot field 3
}

type ErrorResponse struct {
	Message string `json:"message"`
}

type PasswordResetRequest struct {
	Email string `json:"email"`
}

type PasswordResetVerify struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}
