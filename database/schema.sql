-- ============================================================
-- database/schema.sql
-- TOTP 2FA Demo — Database Schema
-- Principle: Separation of Secrets
-- ============================================================

-- Users table: core authentication credentials
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,          -- Argon2id hash (never plaintext)
    is_2fa_enabled BOOLEAN DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    locked_until TIMESTAMP NULL,          -- Account lockout expiry
    failed_attempts INTEGER DEFAULT 0     -- Consecutive failed TOTP attempts
);

-- TOTP secrets: always encrypted at rest, never in plaintext
CREATE TABLE IF NOT EXISTS totp_secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    encrypted_secret BLOB NOT NULL,       -- AES-256-GCM ciphertext
    encryption_iv BLOB NOT NULL,          -- 96-bit IV (NEVER reused)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Used tokens: replay prevention — store hashes of consumed OTPs
CREATE TABLE IF NOT EXISTS used_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,             -- SHA-256(otp_code) — never plaintext
    time_step INTEGER NOT NULL,           -- floor(unix_time / 30)
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);
-- Composite unique index enforces replay prevention at DB level
CREATE UNIQUE INDEX IF NOT EXISTS idx_used_tokens
    ON used_tokens(user_id, token_hash, time_step);

-- Cleanup index: find and purge expired tokens efficiently
CREATE INDEX IF NOT EXISTS idx_used_tokens_time
    ON used_tokens(time_step);

-- Login attempts: full audit trail for rate limiting + forensics
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,                       -- NULL if username doesn't exist
    ip_address TEXT NOT NULL,
    attempt_type TEXT NOT NULL,            -- 'password' | 'totp' | 'enroll'
    success BOOLEAN NOT NULL,
    user_agent TEXT,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Index for fast rate-limit queries
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_time
    ON login_attempts(user_id, attempt_type, attempted_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_time
    ON login_attempts(ip_address, attempted_at);
