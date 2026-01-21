-- Migration script for adding new security features
-- Run this if you have an existing database

-- Add 2FA columns to Users table
ALTER TABLE Users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS totp_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE Users ADD COLUMN IF NOT EXISTS totp_verified_at TIMESTAMP WITH TIME ZONE;

-- Add message signature column to Messages table
ALTER TABLE Messages ADD COLUMN IF NOT EXISTS message_signature TEXT;

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_users_totp_enabled ON Users(totp_enabled) WHERE totp_enabled = TRUE;
CREATE INDEX IF NOT EXISTS idx_messages_signature ON Messages(message_signature) WHERE message_signature IS NOT NULL;
