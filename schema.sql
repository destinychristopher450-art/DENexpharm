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
  subject TEXT NOT NULL,
  question TEXT NOT NULL,
  options JSONB NOT NULL,
  answer_index INTEGER NOT NULL,
  explanation TEXT DEFAULT '',
  active BOOLEAN DEFAULT TRUE,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

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

CREATE INDEX IF NOT EXISTS scores_user_idx
ON scores(user_id);

CREATE INDEX IF NOT EXISTS scores_score_idx
ON scores(score);
