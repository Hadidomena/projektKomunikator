-- Create the Users table
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    e2ee_public_key TEXT,
    e2ee_private_key_encrypted TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    totp_secret TEXT,
    totp_enabled BOOLEAN DEFAULT FALSE,
    totp_verified_at TIMESTAMP WITH TIME ZONE
);

-- RatchetStates table for Double Ratchet protocol state management
CREATE TABLE RatchetStates (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    peer_user_id INTEGER NOT NULL,
    root_key TEXT NOT NULL,
    sending_chain_key TEXT NOT NULL,
    receiving_chain_key TEXT NOT NULL,
    sending_chain_length INTEGER DEFAULT 0,
    receiving_chain_length INTEGER DEFAULT 0,
    previous_chain_length INTEGER DEFAULT 0,
    dh_public_key TEXT NOT NULL,
    dh_peer_public_key TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_ratchet_user
        FOREIGN KEY(user_id)
        REFERENCES Users(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_ratchet_peer
        FOREIGN KEY(peer_user_id)
        REFERENCES Users(id)
        ON DELETE CASCADE,
    CONSTRAINT unique_ratchet_pair UNIQUE(user_id, peer_user_id)
);

-- SkippedMessageKeys table for out-of-order message handling
CREATE TABLE SkippedMessageKeys (
    id SERIAL PRIMARY KEY,
    ratchet_state_id INTEGER NOT NULL,
    message_number INTEGER NOT NULL,
    message_key TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_skipped_ratchet
        FOREIGN KEY(ratchet_state_id)
        REFERENCES RatchetStates(id)
        ON DELETE CASCADE,
    CONSTRAINT unique_skipped_message UNIQUE(ratchet_state_id, message_number)
);

-- Create indexes for ratchet state lookups
CREATE INDEX idx_ratchet_user ON RatchetStates(user_id);
CREATE INDEX idx_ratchet_peer ON RatchetStates(peer_user_id);
CREATE INDEX idx_skipped_keys_ratchet ON SkippedMessageKeys(ratchet_state_id);

-- Create the Messages table with sender and receiver
CREATE TABLE Messages (
    id SERIAL PRIMARY KEY,
    sender_id INTEGER NOT NULL,
    receiver_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    encrypted_key TEXT,
    message_signature TEXT,
    dh_public_key TEXT,
    message_number INTEGER,
    previous_chain_length INTEGER,
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
