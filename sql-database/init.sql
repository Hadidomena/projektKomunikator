-- Create the Users table
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    e2ee_public_key TEXT,
    e2ee_private_key_encrypted TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    totp_secret TEXT,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_verified_at TIMESTAMP WITH TIME ZONE
);

-- Create the Messages table with sender and receiver
-- Each message contains all data needed for E2EE decryption (dh_public_key for ECDH)
-- No server-side ratchet state needed - client handles key derivation
CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    encrypted_key TEXT,
    message_signature TEXT,
    dh_public_key TEXT,
    is_read BOOLEAN DEFAULT FALSE,
    is_deleted_by_sender BOOLEAN DEFAULT FALSE,
    is_deleted_by_receiver BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    read_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_sender
        FOREIGN KEY(sender_id)
        REFERENCES Users(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_receiver
        FOREIGN KEY(receiver_id)
        REFERENCES Users(id)
        ON DELETE CASCADE
);

-- Create index for faster message queries
CREATE INDEX idx_messages_receiver ON Messages(receiver_id) WHERE is_deleted_by_receiver = FALSE;
CREATE INDEX idx_messages_sender ON Messages(sender_id) WHERE is_deleted_by_sender = FALSE;
CREATE INDEX idx_messages_unread ON Messages(receiver_id, is_read) WHERE is_deleted_by_receiver = FALSE;

-- Password reset tokens table
CREATE TABLE PasswordResetTokens (
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
CREATE TABLE LoginHistory (
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
CREATE TABLE HoneypotAttempts (
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

-- Create indexes for better security feature performance
CREATE INDEX idx_users_totp_enabled ON Users(totp_enabled) WHERE totp_enabled = TRUE;
CREATE INDEX idx_messages_signature ON Messages(message_signature) WHERE message_signature IS NOT NULL;
