BEGIN;

-- =========================================================
-- DENexpharm v6.0.0
-- FINAL PostgreSQL SCHEMA
--
-- MATCHED TO THE PRODUCTION server.js
--
-- ID TYPE:
-- All application-generated IDs are TEXT because server.js
-- generates IDs with crypto.randomUUID().
--
-- XP:
-- users.xp          = user's accumulated/lifetime XP
-- scores.xp_awarded = XP awarded for that particular attempt
--
-- IMPORTANT:
-- This schema is intended for a NEW / EMPTY PostgreSQL database.
-- If an OLD DENexpharm schema already exists, do not mix the
-- old tables with this schema.
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

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT users_xp_nonnegative
        CHECK (xp >= 0)
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

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT questions_answer_index_nonnegative
        CHECK (answer_index >= 0)
);


-- =========================================================
-- SCORES
-- =========================================================
--
-- users.xp = accumulated XP
--
-- scores.xp_awarded = XP awarded for this individual attempt
-- =========================================================

CREATE TABLE IF NOT EXISTS scores (
    id TEXT PRIMARY KEY,

    user_id TEXT NOT NULL
        REFERENCES users(id)
        ON DELETE CASCADE,

    subject TEXT NOT NULL,

    score INTEGER NOT NULL,

    total INTEGER NOT NULL,

    xp_awarded INTEGER NOT NULL DEFAULT 0,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT scores_score_nonnegative
        CHECK (score >= 0),

    CONSTRAINT scores_total_positive
        CHECK (total > 0),

    CONSTRAINT scores_score_not_above_total
        CHECK (score <= total),

    CONSTRAINT scores_xp_awarded_nonnegative
        CHECK (xp_awarded >= 0)
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

    amount NUMERIC(14,2) NOT NULL,

    currency TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'pending',

    provider_status TEXT NOT NULL DEFAULT '',

    paid_at TIMESTAMPTZ,

    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT payments_amount_nonnegative
        CHECK (amount >= 0)
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

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- =========================================================
-- USERS INDEXES
-- =========================================================

-- email is already indexed automatically by UNIQUE(email)

CREATE INDEX IF NOT EXISTS users_country_level_idx
    ON users(country, level);

CREATE INDEX IF NOT EXISTS users_xp_idx
    ON users(xp DESC);


-- =========================================================
-- QUESTIONS INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS questions_country_level_subject_idx
    ON questions(country, level, subject);

CREATE INDEX IF NOT EXISTS questions_country_level_topic_idx
    ON questions(country, level, topic);

CREATE INDEX IF NOT EXISTS questions_subject_idx
    ON questions(subject);

CREATE INDEX IF NOT EXISTS questions_active_idx
    ON questions(active);


-- =========================================================
-- SCORES INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS scores_user_idx
    ON scores(user_id);

CREATE INDEX IF NOT EXISTS scores_score_idx
    ON scores(score DESC);

CREATE INDEX IF NOT EXISTS scores_created_idx
    ON scores(created_at DESC);


-- =========================================================
-- PAYMENTS INDEXES
-- =========================================================

-- reference is already indexed automatically by UNIQUE(reference)

CREATE INDEX IF NOT EXISTS payments_user_idx
    ON payments(user_id);

CREATE INDEX IF NOT EXISTS payments_status_idx
    ON payments(status);

CREATE INDEX IF NOT EXISTS payments_created_idx
    ON payments(created_at DESC);


-- =========================================================
-- AUDIT LOG INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS audit_logs_user_idx
    ON audit_logs(user_id);

CREATE INDEX IF NOT EXISTS audit_logs_created_idx
    ON audit_logs(created_at DESC);


-- =========================================================
-- END
-- =========================================================

COMMIT;
