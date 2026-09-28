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

-- Upgrade an existing DENexpharm database without deleting its questions.
ALTER TABLE questions ADD COLUMN IF NOT EXISTS country TEXT;
ALTER TABLE questions ADD COLUMN IF NOT EXISTS level TEXT;
ALTER TABLE questions ADD COLUMN IF NOT EXISTS topic TEXT;
ALTER TABLE questions ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW();

UPDATE questions SET country = 'Nigeria' WHERE country IS NULL OR BTRIM(country) = '';
UPDATE questions SET level = '200' WHERE level IS NULL OR BTRIM(level) = '';
UPDATE questions SET topic = '' WHERE topic IS NULL;
UPDATE questions SET updated_at = NOW() WHERE updated_at IS NULL;

ALTER TABLE questions ALTER COLUMN country SET DEFAULT 'Nigeria';
ALTER TABLE questions ALTER COLUMN level SET DEFAULT '200';
ALTER TABLE questions ALTER COLUMN topic SET DEFAULT '';
ALTER TABLE questions ALTER COLUMN country SET NOT NULL;
ALTER TABLE questions ALTER COLUMN level SET NOT NULL;
ALTER TABLE questions ALTER COLUMN topic SET NOT NULL;

CREATE TABLE IF NOT EXISTS scores (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  subject TEXT NOT NULL,
  score INTEGER NOT NULL,
  total INTEGER NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

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

CREATE INDEX IF NOT EXISTS scores_user_idx ON scores(user_id);
CREATE INDEX IF NOT EXISTS scores_score_idx ON scores(score);
CREATE INDEX IF NOT EXISTS questions_country_level_subject_idx ON questions(country, level, subject);
CREATE INDEX IF NOT EXISTS questions_country_level_topic_idx ON questions(country, level, topic);
CREATE INDEX IF NOT EXISTS questions_subject_idx ON questions(subject);
CREATE INDEX IF NOT EXISTS questions_active_idx ON questions(active);
