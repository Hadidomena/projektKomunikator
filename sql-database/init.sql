-- Create the Users table
CREATE TABLE Users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_blocked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE
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

-- Keep the Texts table for backward compatibility (can be removed later)
CREATE TABLE Texts (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_user
        FOREIGN KEY(user_id)
        REFERENCES Users(id)
        ON DELETE CASCADE
);