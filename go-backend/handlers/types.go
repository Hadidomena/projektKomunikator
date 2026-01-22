package handlers

type RegistrationRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Website  string `json:"website"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
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
