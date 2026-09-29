BEGIN;

-- =========================================================
-- DENexpharm FINAL PostgreSQL SCHEMA
-- Compatible with the final production server.js
--
-- IMPORTANT:
-- This schema uses TEXT IDs because server.js generates IDs
-- with crypto.randomUUID().
--
-- Example:
-- user-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
-- score-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
-- payment-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
-- audit-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
--
-- If this is a NEW Render PostgreSQL database, run this file
-- as-is.
--
-- If an OLD DENexpharm database already contains SERIAL/
-- INTEGER IDs, do not mix the old schema with this schema.
-- Back up important data first, then migrate/recreate the
-- database so all related IDs use TEXT consistently.
-- =========================================================


-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,

    email TEXT NOT NULL UNIQUE,

    password_hash TEXT NOT NULL,

    name TEXT NOT NULL,

    university TEXT NOT NULL DEFAULT '',

    country TEXT NOT NULL DEFAULT '',

    level TEXT NOT NULL DEFAULT '200',

    xp INTEGER NOT NULL DEFAULT 0,

    premium BOOLEAN NOT NULL DEFAULT FALSE,

    is_admin BOOLEAN NOT NULL DEFAULT FALSE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- QUESTIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS questions (
    id TEXT PRIMARY KEY,

    country TEXT NOT NULL DEFAULT 'Nigeria',

    level TEXT NOT NULL DEFAULT '200',

    subject TEXT NOT NULL,

    topic TEXT NOT NULL DEFAULT '',

    question TEXT NOT NULL,

    options JSONB NOT NULL,

    answer_index INTEGER NOT NULL,

    explanation TEXT NOT NULL DEFAULT '',

    active BOOLEAN NOT NULL DEFAULT TRUE,

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- SCORES
-- =========================================================

CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    subject TEXT NOT NULL,

    score INTEGER NOT NULL,

    total INTEGER NOT NULL,

    xp INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- PAYMENTS
-- =========================================================

CREATE TABLE IF NOT EXISTS payments (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    reference TEXT NOT NULL UNIQUE,

    amount NUMERIC(12,2) NOT NULL,

    currency TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending',

    provider_status TEXT DEFAULT '',

    paid_at TIMESTAMPTZ,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- AUDIT LOGS
-- =========================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,

    user_id TEXT
        REFERENCES users(id)
        ON DELETE SET NULL,

    action TEXT NOT NULL,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    ip_address TEXT,

    user_agent TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- USERS INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);

CREATE INDEX IF NOT EXISTS idx_users_country_level
ON users(country, level);

CREATE INDEX IF NOT EXISTS idx_users_xp
ON users(xp DESC);


-- =========================================================
-- QUESTIONS INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_questions_filters
ON questions(country, level, subject, topic);

CREATE INDEX IF NOT EXISTS idx_questions_subject
ON questions(subject);

CREATE INDEX IF NOT EXISTS idx_questions_country_level
ON questions(country, level);

CREATE INDEX IF NOT EXISTS idx_questions_active
ON questions(active);


-- =========================================================
-- SCORES INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_scores_user
ON scores(user_id);

CREATE INDEX IF NOT EXISTS idx_scores_xp
ON scores(xp DESC);

CREATE INDEX IF NOT EXISTS idx_scores_created
ON scores(created_at DESC);


-- =========================================================
-- PAYMENTS INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_payments_user
ON payments(user_id);

CREATE INDEX IF NOT EXISTS idx_payments_reference
ON payments(reference);

CREATE INDEX IF NOT EXISTS idx_payments_status
ON payments(status);

CREATE INDEX IF NOT EXISTS idx_payments_created
ON payments(created_at DESC);


-- =========================================================
-- AUDIT INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS idx_audit_user
ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS idx_audit_action
ON audit_logs(action);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_logs(created_at DESC);


-- =========================================================
-- BASIC DATA INTEGRITY
-- =========================================================

ALTER TABLE users
    ADD CONSTRAINT users_xp_nonnegative
    CHECK (xp >= 0);


ALTER TABLE questions
    ADD CONSTRAINT questions_answer_index_nonnegative
    CHECK (answer_index >= 0);


ALTER TABLE scores
    ADD CONSTRAINT scores_score_nonnegative
    CHECK (score >= 0);


ALTER TABLE scores
    ADD CONSTRAINT scores_total_positive
    CHECK (total > 0);


ALTER TABLE scores
    ADD CONSTRAINT scores_score_not_above_total
    CHECK (score <= total);


ALTER TABLE scores
    ADD CONSTRAINT scores_xp_nonnegative
    CHECK (xp >= 0);


ALTER TABLE payments
    ADD CONSTRAINT payments_amount_nonnegative
    CHECK (amount >= 0);


COMMIT;
