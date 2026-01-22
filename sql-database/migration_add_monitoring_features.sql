-- Migration for password reset, login monitoring, and honeypot features

-- Password reset tokens table
CREATE TABLE IF NOT EXISTS PasswordResetTokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP
);

CREATE INDEX idx_password_reset_token ON PasswordResetTokens(token);
CREATE INDEX idx_password_reset_expires ON PasswordResetTokens(expires_at);

-- Login history for monitoring
CREATE TABLE IF NOT EXISTS LoginHistory (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES Users(id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    success BOOLEAN NOT NULL,
    new_device BOOLEAN DEFAULT FALSE,
    login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    country VARCHAR(100),
    city VARCHAR(100)
);

CREATE INDEX idx_login_history_user ON LoginHistory(user_id);
CREATE INDEX idx_login_history_time ON LoginHistory(login_time);
CREATE INDEX idx_login_history_ip ON LoginHistory(ip_address);

-- Honeypot attempts tracking
CREATE TABLE IF NOT EXISTS HoneypotAttempts (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    honeypot_field VARCHAR(100) NOT NULL,
    honeypot_value TEXT,
    submitted_data JSONB,
    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    blocked BOOLEAN DEFAULT TRUE
);

CREATE INDEX idx_honeypot_ip ON HoneypotAttempts(ip_address);
CREATE INDEX idx_honeypot_time ON HoneypotAttempts(attempt_time);
