BEGIN;

-- =========================================================
-- DENexpharm PostgreSQL schema + safe migrations
-- Compatible with the current server.js
-- =========================================================


-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  university TEXT DEFAULT '',
  country TEXT DEFAULT '',
  level TEXT DEFAULT '200',
  xp INTEGER DEFAULT 0,
  premium BOOLEAN DEFAULT FALSE,
  admin BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Safely upgrade older users tables.
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS email TEXT;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS password_hash TEXT;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS name TEXT;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS university TEXT DEFAULT '';

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS country TEXT DEFAULT '';

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS level TEXT DEFAULT '200';

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS xp INTEGER DEFAULT 0;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS premium BOOLEAN DEFAULT FALSE;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS admin BOOLEAN DEFAULT FALSE;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();


-- Repair NULL values in existing records.
UPDATE users
SET university = ''
WHERE university IS NULL;

UPDATE users
SET country = ''
WHERE country IS NULL;

UPDATE users
SET level = '200'
WHERE level IS NULL OR BTRIM(level) = '';

UPDATE users
SET xp = 0
WHERE xp IS NULL;

UPDATE users
SET premium = FALSE
WHERE premium IS NULL;

UPDATE users
SET admin = FALSE
WHERE admin IS NULL;

UPDATE users
SET created_at = NOW()
WHERE created_at IS NULL;


-- Set defaults.
ALTER TABLE users
  ALTER COLUMN university SET DEFAULT '';

ALTER TABLE users
  ALTER COLUMN country SET DEFAULT '';

ALTER TABLE users
  ALTER COLUMN level SET DEFAULT '200';

ALTER TABLE users
  ALTER COLUMN xp SET DEFAULT 0;

ALTER TABLE users
  ALTER COLUMN premium SET DEFAULT FALSE;

ALTER TABLE users
  ALTER COLUMN admin SET DEFAULT FALSE;

ALTER TABLE users
  ALTER COLUMN created_at SET DEFAULT NOW();


-- =========================================================
-- QUESTIONS
-- =========================================================

CREATE TABLE IF NOT EXISTS questions (
  id SERIAL PRIMARY KEY,
  country TEXT NOT NULL DEFAULT 'Nigeria',
  level TEXT NOT NULL DEFAULT '200',
  subject TEXT NOT NULL,
  topic TEXT NOT NULL DEFAULT '',
  question TEXT NOT NULL,
  options JSONB NOT NULL,
  answer_index INTEGER NOT NULL,
  explanation TEXT DEFAULT '',
  active BOOLEAN DEFAULT TRUE,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Safely upgrade older questions tables.
ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS country TEXT;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS level TEXT;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS subject TEXT;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS topic TEXT;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS question TEXT;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS options JSONB;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS answer_index INTEGER;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS explanation TEXT DEFAULT '';

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS active BOOLEAN DEFAULT TRUE;

ALTER TABLE questions
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();


-- Repair existing question records.
UPDATE questions
SET country = 'Nigeria'
WHERE country IS NULL OR BTRIM(country) = '';

UPDATE questions
SET level = '200'
WHERE level IS NULL OR BTRIM(level) = '';

UPDATE questions
SET topic = ''
WHERE topic IS NULL;

UPDATE questions
SET explanation = ''
WHERE explanation IS NULL;

UPDATE questions
SET active = TRUE
WHERE active IS NULL;

UPDATE questions
SET updated_at = NOW()
WHERE updated_at IS NULL;


-- Defaults.
ALTER TABLE questions
  ALTER COLUMN country SET DEFAULT 'Nigeria';

ALTER TABLE questions
  ALTER COLUMN level SET DEFAULT '200';

ALTER TABLE questions
  ALTER COLUMN topic SET DEFAULT '';

ALTER TABLE questions
  ALTER COLUMN explanation SET DEFAULT '';

ALTER TABLE questions
  ALTER COLUMN active SET DEFAULT TRUE;

ALTER TABLE questions
  ALTER COLUMN updated_at SET DEFAULT NOW();


-- Enforce required fields where safe.
ALTER TABLE questions
  ALTER COLUMN country SET NOT NULL;

ALTER TABLE questions
  ALTER COLUMN level SET NOT NULL;

ALTER TABLE questions
  ALTER COLUMN topic SET NOT NULL;

ALTER TABLE questions
  ALTER COLUMN subject SET NOT NULL;

ALTER TABLE questions
  ALTER COLUMN question SET NOT NULL;

ALTER TABLE questions
  ALTER COLUMN options SET NOT NULL;

ALTER TABLE questions
  ALTER COLUMN answer_index SET NOT NULL;


-- =========================================================
-- SCORES
-- =========================================================

CREATE TABLE IF NOT EXISTS scores (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  subject TEXT NOT NULL,
  score INTEGER NOT NULL,
  total INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Safely upgrade older scores tables.
ALTER TABLE scores
  ADD COLUMN IF NOT EXISTS user_id INTEGER;

ALTER TABLE scores
  ADD COLUMN IF NOT EXISTS subject TEXT;

ALTER TABLE scores
  ADD COLUMN IF NOT EXISTS score INTEGER;

ALTER TABLE scores
  ADD COLUMN IF NOT EXISTS total INTEGER;

ALTER TABLE scores
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

UPDATE scores
SET created_at = NOW()
WHERE created_at IS NULL;

ALTER TABLE scores
  ALTER COLUMN created_at SET DEFAULT NOW();


-- =========================================================
-- PAYMENTS
-- =========================================================

CREATE TABLE IF NOT EXISTS payments (
  id SERIAL PRIMARY KEY,
  reference TEXT UNIQUE NOT NULL,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  amount NUMERIC NOT NULL,
  currency TEXT NOT NULL,
  status TEXT NOT NULL,
  provider_reference TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Safely upgrade older payments tables.
ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS reference TEXT;

ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS user_id INTEGER;

ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS amount NUMERIC;

ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS currency TEXT;

ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS status TEXT;

ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS provider_reference TEXT;

ALTER TABLE payments
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();


-- Repair timestamps.
UPDATE payments
SET created_at = NOW()
WHERE created_at IS NULL;

ALTER TABLE payments
  ALTER COLUMN created_at SET DEFAULT NOW();


-- =========================================================
-- INDEXES
-- =========================================================

CREATE INDEX IF NOT EXISTS users_email_idx
ON users(email);

CREATE INDEX IF NOT EXISTS users_country_level_idx
ON users(country, level);

CREATE INDEX IF NOT EXISTS users_xp_idx
ON users(xp DESC);

CREATE INDEX IF NOT EXISTS scores_user_idx
ON scores(user_id);

CREATE INDEX IF NOT EXISTS scores_score_idx
ON scores(score);

CREATE INDEX IF NOT EXISTS questions_country_level_subject_idx
ON questions(country, level, subject);

CREATE INDEX IF NOT EXISTS questions_country_level_topic_idx
ON questions(country, level, topic);

CREATE INDEX IF NOT EXISTS questions_subject_idx
ON questions(subject);

CREATE INDEX IF NOT EXISTS questions_active_idx
ON questions(active);

CREATE INDEX IF NOT EXISTS payments_user_idx
ON payments(user_id);

CREATE INDEX IF NOT EXISTS payments_status_idx
ON payments(status);

CREATE INDEX IF NOT EXISTS payments_created_idx
ON payments(created_at DESC);


-- =========================================================
-- PAYMENT REFERENCE INDEX
-- =========================================================

CREATE UNIQUE INDEX IF NOT EXISTS payments_reference_unique_idx
ON payments(reference);


COMMIT;
