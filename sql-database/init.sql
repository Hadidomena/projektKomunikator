-- Create the Users table
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    totp_secret TEXT,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_verified_at TIMESTAMP WITH TIME ZONE
);

-- Create the UserDevices table for E2EE multi-device support
CREATE TABLE UserDevices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    device_name VARCHAR(100) NOT NULL,
    public_key TEXT NOT NULL,
    device_fingerprint VARCHAR(255) UNIQUE NOT NULL,
    last_used TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    CONSTRAINT fk_user_device
        FOREIGN KEY(user_id)
        REFERENCES Users(id)
        ON DELETE CASCADE,
    CONSTRAINT unique_user_device UNIQUE(user_id, device_fingerprint)
);

-- Create index for faster device lookups
CREATE INDEX idx_user_devices_user ON UserDevices(user_id) WHERE is_active = TRUE;
CREATE INDEX idx_user_devices_fingerprint ON UserDevices(device_fingerprint);

-- Create the Messages table with sender and receiver
CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    sender_device_id INTEGER,
    receiver_id INTEGER NOT NULL,
    receiver_device_id INTEGER,
    content TEXT NOT NULL,
    encrypted_key TEXT,
    message_signature TEXT,
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
        ON DELETE CASCADE,
    CONSTRAINT fk_sender_device
        FOREIGN KEY(sender_device_id)
        REFERENCES UserDevices(id)
        ON DELETE SET NULL,
    CONSTRAINT fk_receiver_device
        FOREIGN KEY(receiver_device_id)
        REFERENCES UserDevices(id)
        ON DELETE SET NULL
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
