'use strict';

/*
 * DENexpharm Production Server
 * --------------------------------
 * Express 5 + PostgreSQL + JWT + Paystack
 *
 * Required production environment variables:
 *
 * NODE_ENV=production
 * JWT_SECRET=at-least-32-character-secret
 * DATABASE_URL=postgresql://...
 * PAYSTACK_SECRET_KEY=sk_live_...
 *
 * Optional:
 * PORT=10000
 * PREMIUM_PRICE=5000
 * PREMIUM_CURRENCY=NGN
 * PAYSTACK_CALLBACK_URL=https://your-domain/api/payments/callback
 * FRONTEND_ORIGIN=https://your-domain
 * PUBLIC_BASE_URL=https://your-domain
 * ADMIN_EMAIL=admin@example.com
 *
 * Paystack webhook:
 * https://your-domain/api/payments/webhook
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 10000);
const NODE_ENV = String(process.env.NODE_ENV || 'development').toLowerCase();
const IS_PRODUCTION = NODE_ENV === 'production';

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const QUESTION_FILE = path.join(ROOT, 'question.json');
const DATA_DIR = path.join(ROOT, 'data');
const LOCAL_DB_FILE = path.join(DATA_DIR, 'db.json');

const JWT_SECRET = String(process.env.JWT_SECRET || '');
const DATABASE_URL = String(process.env.DATABASE_URL || '');

const PAYSTACK_SECRET_KEY = String(
  process.env.PAYSTACK_SECRET_KEY || ''
).trim();

const PREMIUM_PRICE = Number(process.env.PREMIUM_PRICE || 5000);
const PREMIUM_CURRENCY = String(
  process.env.PREMIUM_CURRENCY || 'NGN'
).trim().toUpperCase();

const FRONTEND_ORIGIN = String(
  process.env.FRONTEND_ORIGIN || ''
).trim();

const PUBLIC_BASE_URL = String(
  process.env.PUBLIC_BASE_URL || ''
).trim().replace(/\/+$/, '');

const PAYSTACK_CALLBACK_URL = String(
  process.env.PAYSTACK_CALLBACK_URL || ''
).trim();

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || ''
).trim().toLowerCase();

const FREE_QUESTIONS_PER_SUBJECT = Number(
  process.env.FREE_QUESTIONS_PER_SUBJECT || 10
);

const VERSION = '7.0.0';

/* ---------------------------------------------------------
 * Basic validation
 * --------------------------------------------------------- */

if (IS_PRODUCTION) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
      'JWT_SECRET must be configured and at least 32 characters long in production.'
    );
  }

  if (!DATABASE_URL) {
    throw new Error(
      'DATABASE_URL must be configured in production.'
    );
  }

  if (!PAYSTACK_SECRET_KEY) {
    console.warn(
      'WARNING: PAYSTACK_SECRET_KEY is not configured. Payments will be disabled.'
    );
  }

  if (
    PAYSTACK_SECRET_KEY &&
    !/^sk_(live|test)_/.test(PAYSTACK_SECRET_KEY)
  ) {
    console.warn(
      'WARNING: PAYSTACK_SECRET_KEY does not appear to be a valid Paystack secret key.'
    );
  }
} else if (!JWT_SECRET) {
  console.warn(
    'WARNING: JWT_SECRET is not configured. A temporary development secret will be used.'
  );
}

const EFFECTIVE_JWT_SECRET =
  JWT_SECRET || crypto.randomBytes(48).toString('hex');

if (!Number.isFinite(PREMIUM_PRICE) || PREMIUM_PRICE <= 0) {
  throw new Error('PREMIUM_PRICE must be a positive number.');
}

if (!/^[A-Z]{3}$/.test(PREMIUM_CURRENCY)) {
  throw new Error('PREMIUM_CURRENCY must be a valid 3-letter currency code.');
}

/* ---------------------------------------------------------
 * Directories / local database fallback
 * --------------------------------------------------------- */

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DEFAULT_DB = {
  users: [],
  questions: [],
  scores: [],
  payments: [],
  audit_logs: []
};

function loadLocalDB() {
  try {
    if (!fs.existsSync(LOCAL_DB_FILE)) {
      fs.writeFileSync(
        LOCAL_DB_FILE,
        JSON.stringify(DEFAULT_DB, null, 2),
        'utf8'
      );
      return JSON.parse(JSON.stringify(DEFAULT_DB));
    }

    const raw = fs.readFileSync(LOCAL_DB_FILE, 'utf8');
    const parsed = JSON.parse(raw);

    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      questions: Array.isArray(parsed.questions) ? parsed.questions : [],
      scores: Array.isArray(parsed.scores) ? parsed.scores : [],
      payments: Array.isArray(parsed.payments) ? parsed.payments : [],
      audit_logs: Array.isArray(parsed.audit_logs)
        ? parsed.audit_logs
        : []
    };
  } catch (error) {
    console.error('Could not load local database:', error.message);
    return JSON.parse(JSON.stringify(DEFAULT_DB));
  }
}

let localDB = loadLocalDB();

function saveLocalDB() {
  const tempFile = LOCAL_DB_FILE + '.tmp';

  fs.writeFileSync(
    tempFile,
    JSON.stringify(localDB, null, 2),
    'utf8'
  );

  fs.renameSync(tempFile, LOCAL_DB_FILE);
}

/* ---------------------------------------------------------
 * PostgreSQL
 * --------------------------------------------------------- */

let pool = null;
let databaseReady = false;

if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: IS_PRODUCTION
      ? { rejectUnauthorized: false }
      : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
  });

  pool.on('error', (error) => {
    console.error('Unexpected PostgreSQL pool error:', error.message);
  });
}

/* ---------------------------------------------------------
 * Database initialization
 * --------------------------------------------------------- */

async function initializeDatabase() {
  if (!pool) {
    databaseReady = false;
    return;
  }

  const client = await pool.connect();

  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        university TEXT DEFAULT '',
        country TEXT DEFAULT 'Nigeria',
        level TEXT DEFAULT '200',
        xp INTEGER DEFAULT 0,
        premium BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS questions (
        id TEXT PRIMARY KEY,
        question TEXT NOT NULL,
        options JSONB NOT NULL DEFAULT '[]'::jsonb,
        answer_index INTEGER NOT NULL DEFAULT 0,
        explanation TEXT DEFAULT '',
        subject TEXT DEFAULT 'General',
        topic TEXT DEFAULT 'General',
        country TEXT DEFAULT 'Nigeria',
        level TEXT DEFAULT '200',
        year TEXT DEFAULT '',
        difficulty TEXT DEFAULT 'medium',
        premium BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS scores (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT DEFAULT 'General',
        score INTEGER NOT NULL DEFAULT 0,
        total INTEGER NOT NULL DEFAULT 0,
        xp INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reference TEXT UNIQUE NOT NULL,
        provider TEXT DEFAULT 'paystack',
        amount INTEGER NOT NULL,
        currency TEXT NOT NULL,
        status TEXT DEFAULT 'initialized',
        provider_status TEXT DEFAULT '',
        paid_at TIMESTAMPTZ,
        metadata JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        action TEXT NOT NULL,
        details JSONB DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_questions_filters
        ON questions(country, level, subject, topic);

      CREATE INDEX IF NOT EXISTS idx_questions_subject
        ON questions(subject);

      CREATE INDEX IF NOT EXISTS idx_questions_country_level
        ON questions(country, level);

      CREATE INDEX IF NOT EXISTS idx_scores_user
        ON scores(user_id);

      CREATE INDEX IF NOT EXISTS idx_scores_xp
        ON scores(xp DESC);

      CREATE INDEX IF NOT EXISTS idx_payments_user
        ON payments(user_id);

      CREATE INDEX IF NOT EXISTS idx_payments_reference
        ON payments(reference);
    `);

    databaseReady = true;

    await importQuestionsFromFile(client);

    console.log('PostgreSQL database ready.');
  } finally {
    client.release();
  }
}

/* ---------------------------------------------------------
 * Question normalization
 * --------------------------------------------------------- */

function cleanText(value, fallback = '') {
  if (value === null || value === undefined) {
    return fallback;
  }

  return String(value).trim();
}

function normalizeLevel(value) {
  const text = cleanText(value, '200');

  if (/^\d+$/.test(text)) {
    return text;
  }

  return text;
}

function normalizeCountry(value) {
  return cleanText(value, 'Nigeria') || 'Nigeria';
}

function normalizeOptions(value) {
  if (Array.isArray(value)) {
    return value.map((item) => cleanText(item));
  }

  if (typeof value === 'object' && value !== null) {
    return Object.values(value).map((item) => cleanText(item));
  }

  return [];
}

function normalizeAnswerIndex(question) {
  if (
    question.answer_index !== undefined &&
    question.answer_index !== null
  ) {
    const number = Number(question.answer_index);

    if (Number.isInteger(number) && number >= 0) {
      return number;
    }
  }

  if (
    question.correct_index !== undefined &&
    question.correct_index !== null
  ) {
    const number = Number(question.correct_index);

    if (Number.isInteger(number) && number >= 0) {
      return number;
    }
  }

  if (typeof question.answer === 'number') {
    return question.answer;
  }

  if (typeof question.answer === 'string') {
    const answer = question.answer.trim();

    const letter = answer.toUpperCase();

    if (/^[A-F]$/.test(letter)) {
      return letter.charCodeAt(0) - 65;
    }

    const number = Number(answer);

    if (Number.isInteger(number)) {
      if (number >= 1 && number <= 6) {
        return number - 1;
      }

      if (number >= 0) {
        return number;
      }
    }

    const options = normalizeOptions(question.options);
    const index = options.findIndex(
      (option) => option.toLowerCase() === answer.toLowerCase()
    );

    if (index >= 0) {
      return index;
    }
  }

  return 0;
}

function normalizeQuestion(question, index) {
  const options = normalizeOptions(
    question.options ||
    question.choices ||
    question.answers
  );

  const id =
    cleanText(question.id) ||
    cleanText(question.question_id) ||
    `q-${index + 1}`;

  const answerIndex = normalizeAnswerIndex({
    ...question,
    options
  });

  return {
    id,
    question: cleanText(
      question.question ||
      question.text ||
      question.question_text,
      ''
    ),
    options,
    answer_index: answerIndex,
    explanation: cleanText(
      question.explanation ||
      question.explain ||
      question.rationale,
      ''
    ),
    subject: cleanText(
      question.subject ||
      question.course ||
      'General',
      'General'
    ),
    topic: cleanText(
      question.topic ||
      question.subtopic ||
      'General',
      'General'
    ),
    country: normalizeCountry(
      question.country ||
      question.region ||
      'Nigeria'
    ),
    level: normalizeLevel(
      question.level ||
      question.year_level ||
      question.class_level ||
      '200'
    ),
    year: cleanText(question.year || question.exam_year),
    difficulty: cleanText(
      question.difficulty || 'medium',
      'medium'
    ),
    premium: Boolean(
      question.premium === true ||
      question.is_premium === true
    )
  };
}

function loadQuestionsFromFile() {
  if (!fs.existsSync(QUESTION_FILE)) {
    console.warn(
      `Question file not found: ${QUESTION_FILE}`
    );

    return [];
  }

  try {
    const raw = fs.readFileSync(QUESTION_FILE, 'utf8');
    const parsed = JSON.parse(raw);

    let source = [];

    if (Array.isArray(parsed)) {
      source = parsed;
    } else if (Array.isArray(parsed.questions)) {
      source = parsed.questions;
    } else if (Array.isArray(parsed.data)) {
      source = parsed.data;
    }

    return source
      .map((question, index) =>
        normalizeQuestion(question, index)
      )
      .filter(
        (question) =>
          question.question &&
          question.options.length >= 2
      );
  } catch (error) {
    console.error(
      'Could not read question.json:',
      error.message
    );

    return [];
  }
}

async function importQuestionsFromFile(client) {
  const questions = loadQuestionsFromFile();

  if (!questions.length) {
    console.warn('No valid questions found to import.');
    return;
  }

  let imported = 0;

  for (const question of questions) {
    await client.query(
      `
        INSERT INTO questions (
          id,
          question,
          options,
          answer_index,
          explanation,
          subject,
          topic,
          country,
          level,
          year,
          difficulty,
          premium
        )
        VALUES (
          $1,$2,$3::jsonb,$4,$5,$6,$7,$8,$9,$10,$11,$12
        )
        ON CONFLICT (id)
        DO UPDATE SET
          question = EXCLUDED.question,
          options = EXCLUDED.options,
          answer_index = EXCLUDED.answer_index,
          explanation = EXCLUDED.explanation,
          subject = EXCLUDED.subject,
          topic = EXCLUDED.topic,
          country = EXCLUDED.country,
          level = EXCLUDED.level,
          year = EXCLUDED.year,
          difficulty = EXCLUDED.difficulty,
          premium = EXCLUDED.premium,
          updated_at = NOW()
      `,
      [
        question.id,
        question.question,
        JSON.stringify(question.options),
        question.answer_index,
        question.explanation,
        question.subject,
        question.topic,
        question.country,
        question.level,
        question.year,
        question.difficulty,
        question.premium
      ]
    );

    imported++;
  }

  console.log(`Questions synchronized: ${imported}`);
}

/* ---------------------------------------------------------
 * Generic database helpers
 * --------------------------------------------------------- */

async function dbQuery(text, params = []) {
  if (pool && databaseReady) {
    return pool.query(text, params);
  }

  return null;
}

function generateId(prefix = '') {
  return (
    prefix +
    crypto.randomUUID()
  );
}

function localUserToPublic(user) {
  if (!user) return null;

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    university: user.university || '',
    country: user.country || 'Nigeria',
    level: user.level || '200',
    xp: Number(user.xp || 0),
    premium: Boolean(user.premium),
    created_at: user.created_at
  };
}

function pgUserToPublic(user) {
  return {
    id: user.id,
    name: user.name,
    email: user.email,
    university: user.university || '',
    country: user.country || 'Nigeria',
    level: user.level || '200',
    xp: Number(user.xp || 0),
    premium: Boolean(user.premium),
    created_at: user.created_at
  };
}

/* ---------------------------------------------------------
 * User helpers
 * --------------------------------------------------------- */

async function findUserByEmail(email) {
  const normalized = cleanText(email).toLowerCase();

  if (pool && databaseReady) {
    const result = await pool.query(
      `SELECT * FROM users WHERE LOWER(email) = $1 LIMIT 1`,
      [normalized]
    );

    return result.rows[0] || null;
  }

  return (
    localDB.users.find(
      (user) =>
        String(user.email).toLowerCase() === normalized
    ) || null
  );
}

async function findUserById(id) {
  if (pool && databaseReady) {
    const result = await pool.query(
      `SELECT * FROM users WHERE id = $1 LIMIT 1`,
      [id]
    );

    return result.rows[0] || null;
  }

  return (
    localDB.users.find(
      (user) => String(user.id) === String(id)
    ) || null
  );
}

async function createUser(data) {
  const id = generateId('user-');

  if (pool && databaseReady) {
    const result = await pool.query(
      `
        INSERT INTO users (
          id,
          name,
          email,
          password_hash,
          university,
          country,
          level
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        RETURNING *
      `,
      [
        id,
        data.name,
        data.email,
        data.password_hash,
        data.university || '',
        data.country || 'Nigeria',
        data.level || '200'
      ]
    );

    return result.rows[0];
  }

  const user = {
    id,
    name: data.name,
    email: data.email,
    password_hash: data.password_hash,
    university: data.university || '',
    country: data.country || 'Nigeria',
    level: data.level || '200',
    xp: 0,
    premium: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  };

  localDB.users.push(user);
  saveLocalDB();

  return user;
}

async function updateUserPremium(userId) {
  if (pool && databaseReady) {
    const result = await pool.query(
      `
        UPDATE users
        SET premium = TRUE,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `,
      [userId]
    );

    return result.rows[0] || null;
  }

  const user = localDB.users.find(
    (item) => item.id === userId
  );

  if (!user) return null;

  user.premium = true;
  user.updated_at = new Date().toISOString();

  saveLocalDB();

  return user;
}

async function addUserXP(userId, xp) {
  const safeXP = Math.max(
    0,
    Math.floor(Number(xp) || 0)
  );

  if (pool && databaseReady) {
    const result = await pool.query(
      `
        UPDATE users
        SET xp = COALESCE(xp, 0) + $2,
            updated_at = NOW()
        WHERE id = $1
        RETURNING *
      `,
      [userId, safeXP]
    );

    return result.rows[0] || null;
  }

  const user = localDB.users.find(
    (item) => item.id === userId
  );

  if (!user) return null;

  user.xp = Number(user.xp || 0) + safeXP;
  user.updated_at = new Date().toISOString();

  saveLocalDB();

  return user;
}

/* ---------------------------------------------------------
 * Audit logging
 * --------------------------------------------------------- */

async function audit(userId, action, details = {}) {
  try {
    const id = generateId('audit-');

    if (pool && databaseReady) {
      await pool.query(
        `
          INSERT INTO audit_logs (
            id,
            user_id,
            action,
            details
          )
          VALUES ($1,$2,$3,$4::jsonb)
        `,
        [
          id,
          userId || null,
          action,
          JSON.stringify(details)
        ]
      );

      return;
    }

    localDB.audit_logs.push({
      id,
      user_id: userId || null,
      action,
      details,
      created_at: new Date().toISOString()
    });

    if (localDB.audit_logs.length > 5000) {
      localDB.audit_logs =
        localDB.audit_logs.slice(-5000);
    }

    saveLocalDB();
  } catch (error) {
    console.error(
      'Audit logging error:',
      error.message
    );
  }
}

/* ---------------------------------------------------------
 * JWT authentication
 * --------------------------------------------------------- */

function createToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email
    },
    EFFECTIVE_JWT_SECRET,
    {
      expiresIn: '30d',
      issuer: 'denexpharm'
    }
  );
}

function authenticateToken(req, res, next) {
  const header = String(
    req.headers.authorization || ''
  );

  if (!header.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Authentication required.'
    });
  }

  const token = header.slice(7).trim();

  if (!token) {
    return res.status(401).json({
      error: 'Authentication required.'
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      EFFECTIVE_JWT_SECRET,
      {
        issuer: 'denexpharm'
      }
    );

    req.auth = decoded;
    next();
  } catch {
    return res.status(401).json({
      error: 'Your session has expired. Please log in again.'
    });
  }
}

async function getAuthenticatedUser(req) {
  if (!req.auth?.sub) {
    return null;
  }

  return findUserById(req.auth.sub);
}

/* ---------------------------------------------------------
 * Admin
 * --------------------------------------------------------- */

async function isAdminUser(user) {
  if (!user) return false;

  if (
    ADMIN_EMAIL &&
    String(user.email).toLowerCase() === ADMIN_EMAIL
  ) {
    return true;
  }

  return Boolean(user.is_admin);
}

async function requireAdmin(req, res, next) {
  try {
    const user = await getAuthenticatedUser(req);

    if (!user || !(await isAdminUser(user))) {
      return res.status(403).json({
        error: 'Administrator access required.'
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Admin check failed:', error.message);

    return res.status(500).json({
      error: 'Could not verify administrator access.'
    });
  }
}

/* ---------------------------------------------------------
 * Paystack helpers
 * --------------------------------------------------------- */

function paystackConfigured() {
  return Boolean(
    PAYSTACK_SECRET_KEY &&
    /^sk_(live|test)_/.test(PAYSTACK_SECRET_KEY)
  );
}

function paystackIsLive() {
  return PAYSTACK_SECRET_KEY.startsWith('sk_live_');
}

function paymentAmountInMinorUnits(amount) {
  const number = Number(amount);

  if (!Number.isFinite(number) || number <= 0) {
    throw new Error('Invalid payment amount.');
  }

  return Math.round(number * 100);
}

function makePaystackReference() {
  return (
    'DENEX-' +
    Date.now() +
    '-' +
    crypto.randomBytes(8).toString('hex')
  );
}

function getPaymentCallbackUrl() {
  if (PAYSTACK_CALLBACK_URL) {
    return PAYSTACK_CALLBACK_URL;
  }

  if (PUBLIC_BASE_URL) {
    return `${PUBLIC_BASE_URL}/api/payments/callback`;
  }

  if (FRONTEND_ORIGIN) {
    return `${FRONTEND_ORIGIN.replace(/\/+$/, '')}/api/payments/callback`;
  }

  return null;
}

async function initializePaystackTransaction(
  user,
  reference
) {
  if (!paystackConfigured()) {
    throw new Error(
      'Paystack is not configured on the server.'
    );
  }

  const amount = paymentAmountInMinorUnits(
    PREMIUM_PRICE
  );

  const callbackUrl = getPaymentCallbackUrl();

  const metadata = JSON.stringify({
    user_id: String(user.id),
    product: 'DENexpharm Premium',
    reference
  });

  const body = {
    email: user.email,
    amount: String(amount),
    currency: PREMIUM_CURRENCY,
    reference,
    metadata
  };

  if (callbackUrl) {
    body.callback_url = callbackUrl;
  }

  const response = await fetch(
    'https://api.paystack.co/transaction/initialize',
    {
      method: 'POST',
      headers: {
        Authorization:
          `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(body)
    }
  );

  const data = await response.json().catch(
    () => ({})
  );

  if (!response.ok || !data.status) {
    console.error(
      'Paystack initialization failed:',
      {
        httpStatus: response.status,
        paystackMessage: data.message || null
      }
    );

    throw new Error(
      data.message ||
      `Paystack returned HTTP ${response.status}.`
    );
  }

  if (!data.data?.authorization_url) {
    throw new Error(
      'Paystack did not return an authorization URL.'
    );
  }

  return data.data;
}

async function verifyPaystack(reference) {
  if (!paystackConfigured()) {
    throw new Error(
      'Paystack is not configured on the server.'
    );
  }

  const safeReference = encodeURIComponent(
    String(reference)
  );

  const response = await fetch(
    `https://api.paystack.co/transaction/verify/${safeReference}`,
    {
      method: 'GET',
      headers: {
        Authorization:
          `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json'
      }
    }
  );

  const data = await response.json().catch(
    () => ({})
  );

  if (!response.ok || !data.status) {
    console.error(
      'Paystack verification failed:',
      {
        httpStatus: response.status,
        paystackMessage: data.message || null,
        reference
      }
    );

    throw new Error(
      data.message ||
      `Paystack verification returned HTTP ${response.status}.`
    );
  }

  return data.data || null;
}

/* ---------------------------------------------------------
 * Payment database helpers
 * --------------------------------------------------------- */

async function findPaymentByReference(reference) {
  if (pool && databaseReady) {
    const result = await pool.query(
      `
        SELECT *
        FROM payments
        WHERE reference = $1
        LIMIT 1
      `,
      [reference]
    );

    return result.rows[0] || null;
  }

  return (
    localDB.payments.find(
      (payment) =>
        payment.reference === reference
    ) || null
  );
}

async function findPendingPaymentForUser(userId) {
  if (pool && databaseReady) {
    const result = await pool.query(
      `
        SELECT *
        FROM payments
        WHERE user_id = $1
          AND status IN ('initialized','pending')
        ORDER BY created_at DESC
        LIMIT 1
      `,
      [userId]
    );

    return result.rows[0] || null;
  }

  return (
    localDB.payments
      .filter(
        (payment) =>
          payment.user_id === userId &&
          ['initialized', 'pending'].includes(
            payment.status
          )
      )
      .sort(
        (a, b) =>
          new Date(b.created_at) -
          new Date(a.created_at)
      )[0] || null
  );
}

async function createPayment(payment) {
  if (pool && databaseReady) {
    const result = await pool.query(
      `
        INSERT INTO payments (
          id,
          user_id,
          reference,
          provider,
          amount,
          currency,
          status,
          provider_status,
          metadata
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb
        )
        RETURNING *
      `,
      [
        payment.id,
        payment.user_id,
        payment.reference,
        payment.provider,
        payment.amount,
        payment.currency,
        payment.status,
        payment.provider_status || '',
        JSON.stringify(payment.metadata || {})
      ]
    );

    return result.rows[0];
  }

  localDB.payments.push({
    ...payment,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString()
  });

  saveLocalDB();

  return payment;
}

async function updatePayment(
  reference,
  fields
) {
  if (pool && databaseReady) {
    const allowed = {
      status: fields.status,
      provider_status: fields.provider_status,
      paid_at: fields.paid_at,
      metadata: fields.metadata
    };

    const result = await pool.query(
      `
        UPDATE payments
        SET
          status = COALESCE($2, status),
          provider_status = COALESCE($3, provider_status),
          paid_at = COALESCE($4, paid_at),
          metadata = COALESCE($5::jsonb, metadata),
          updated_at = NOW()
        WHERE reference = $1
        RETURNING *
      `,
      [
        reference,
        allowed.status ?? null,
        allowed.provider_status ?? null,
        allowed.paid_at ?? null,
        allowed.metadata !== undefined
          ? JSON.stringify(allowed.metadata)
          : null
      ]
    );

    return result.rows[0] || null;
  }

  const payment =
    localDB.payments.find(
      (item) =>
        item.reference === reference
    );

  if (!payment) return null;

  Object.assign(payment, fields);
  payment.updated_at =
    new Date().toISOString();

  saveLocalDB();

  return payment;
}

/*
 * This function is deliberately strict.
 *
 * Premium is granted only when:
 * 1. Paystack says the transaction succeeded.
 * 2. The transaction exists in our database.
 * 3. The reference matches.
 * 4. The customer/user matches.
 * 5. The amount matches our configured Premium price.
 * 6. The currency matches our configured Premium currency.
 */
async function markPremium(
  reference,
  paymentData
) {
  if (!paymentData) {
    throw new Error(
      'No Paystack transaction data supplied.'
    );
  }

  if (paymentData.status !== 'success') {
    throw new Error(
      'Paystack transaction was not successful.'
    );
  }

  const payment =
    await findPaymentByReference(reference);

  if (!payment) {
    throw new Error(
      'Payment reference is not registered with DENexpharm.'
    );
  }

  const metadata =
    paymentData.metadata || {};

  let parsedMetadata = metadata;

  if (typeof metadata === 'string') {
    try {
      parsedMetadata = JSON.parse(metadata);
    } catch {
      parsedMetadata = {};
    }
  }

  const expectedUserId =
    String(payment.user_id);

  const metadataUserId =
    parsedMetadata?.user_id !== undefined
      ? String(parsedMetadata.user_id)
      : '';

  if (
    metadataUserId &&
    metadataUserId !== expectedUserId
  ) {
    throw new Error(
      'Payment customer verification failed.'
    );
  }

  if (
    String(paymentData.reference || '') !==
    String(payment.reference)
  ) {
    throw new Error(
      'Payment reference verification failed.'
    );
  }

  const expectedAmount =
    paymentAmountInMinorUnits(PREMIUM_PRICE);

  const paidAmount =
    Number(paymentData.amount);

  if (paidAmount !== expectedAmount) {
    throw new Error(
      'Payment amount verification failed.'
    );
  }

  const paidCurrency =
    String(
      paymentData.currency ||
      ''
    ).toUpperCase();

  if (
    paidCurrency !== PREMIUM_CURRENCY
  ) {
    throw new Error(
      'Payment currency verification failed.'
    );
  }

  if (
    Number(payment.amount) !==
    expectedAmount
  ) {
    throw new Error(
      'Internal payment amount verification failed.'
    );
  }

  if (
    String(payment.currency).toUpperCase() !==
    PREMIUM_CURRENCY
  ) {
    throw new Error(
      'Internal payment currency verification failed.'
    );
  }

  const user =
    await findUserById(payment.user_id);

  if (!user) {
    throw new Error(
      'Payment user account no longer exists.'
    );
  }

  const updatedUser =
    await updateUserPremium(user.id);

  if (!updatedUser) {
    throw new Error(
      'Could not activate Premium.'
    );
  }

  await updatePayment(
    reference,
    {
      status: 'success',
      provider_status:
        paymentData.status,
      paid_at:
        paymentData.paid_at ||
        paymentData.paidAt ||
        new Date().toISOString(),
      metadata: parsedMetadata
    }
  );

  await audit(
    user.id,
    'premium_activated',
    {
      reference,
      amount: paidAmount,
      currency: paidCurrency,
      provider: 'paystack'
    }
  );

  return updatedUser;
}

/* ---------------------------------------------------------
 * Express configuration
 * --------------------------------------------------------- */

app.disable('x-powered-by');

app.set(
  'trust proxy',
  IS_PRODUCTION ? 1 : 0
);

app.use(
  helmet({
    crossOriginResourcePolicy: {
      policy: 'cross-origin'
    }
  })
);

/*
 * Capture raw request body because Paystack webhook
 * signatures are generated from the raw payload.
 */
app.use(
  express.json({
    limit: '1mb',
    verify: (req, res, buffer) => {
      if (
        req.originalUrl ===
        '/api/payments/webhook'
      ) {
        req.rawBody = Buffer.from(buffer);
      }
    }
  })
);

app.use(
  express.urlencoded({
    extended: false,
    limit: '100kb'
  })
);

/* ---------------------------------------------------------
 * CORS
 * --------------------------------------------------------- */

const corsOptions = {
  origin: function (origin, callback) {
    /*
     * Same-origin browser requests normally do not
     * contain an Origin header.
     */
    if (!origin) {
      return callback(null, true);
    }

    if (!IS_PRODUCTION) {
      return callback(null, true);
    }

    if (!FRONTEND_ORIGIN) {
      /*
       * When the frontend is served by this same Express
       * application, CORS is not needed.
       */
      return callback(null, true);
    }

    const allowed = FRONTEND_ORIGIN
      .split(',')
      .map((item) =>
        item.trim().replace(/\/+$/, '')
      )
      .filter(Boolean);

    const normalizedOrigin =
      origin.replace(/\/+$/, '');

    if (
      allowed.includes(normalizedOrigin)
    ) {
      return callback(null, true);
    }

    return callback(
      new Error('CORS origin not allowed.')
    );
  },
  credentials: false,
  methods: [
    'GET',
    'POST',
    'PUT',
    'PATCH',
    'DELETE',
    'OPTIONS'
  ],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Requested-With'
  ]
};

app.use(cors(corsOptions));

/* ---------------------------------------------------------
 * Rate limiting
 * --------------------------------------------------------- */

const generalLimiter =
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
      error:
        'Too many requests. Please try again later.'
    }
  });

const authLimiter =
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
      error:
        'Too many authentication attempts. Please try again later.'
    }
  });

const paymentLimiter =
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false,
    message: {
      error:
        'Too many payment requests. Please wait and try again.'
    }
  });

app.use(
  '/api',
  generalLimiter
);

/* ---------------------------------------------------------
 * Health
 * --------------------------------------------------------- */

app.get(
  '/api/health',
  async (req, res) => {
    let dbStatus =
      pool && databaseReady
        ? 'postgresql'
        : 'local';

    let questionCount = 0;

    try {
      if (pool && databaseReady) {
        const result =
          await pool.query(
            `SELECT COUNT(*)::int AS count FROM questions`
          );

        questionCount =
          Number(result.rows[0]?.count || 0);
      } else {
        questionCount =
          localDB.questions.length ||
          loadQuestionsFromFile().length;
      }
    } catch {
      dbStatus = 'unavailable';
    }

    return res.json({
      ok: true,
      version: VERSION,
      environment: NODE_ENV,
      database: dbStatus,
      payments: paystackConfigured(),
      paystackMode:
        paystackIsLive()
          ? 'live'
          : paystackConfigured()
            ? 'test'
            : 'disabled',
      questions: questionCount,
      freeQuestionsPerSubject:
        FREE_QUESTIONS_PER_SUBJECT,
      premiumPrice: PREMIUM_PRICE,
      premiumCurrency: PREMIUM_CURRENCY
    });
  }
);

/* ---------------------------------------------------------
 * Authentication
 * --------------------------------------------------------- */

app.post(
  '/api/auth/register',
  authLimiter,
  async (req, res) => {
    try {
      const name =
        cleanText(req.body?.name);

      const email =
        cleanText(req.body?.email)
          .toLowerCase();

      const password =
        String(
          req.body?.password || ''
        );

      const university =
        cleanText(
          req.body?.university
        );

      const country =
        cleanText(
          req.body?.country,
          'Nigeria'
        ) || 'Nigeria';

      const level =
        cleanText(
          req.body?.level,
          '200'
        ) || '200';

      if (name.length < 2) {
        return res.status(400).json({
          error:
            'Please enter your full name.'
        });
      }

      if (
        !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
          email
        )
      ) {
        return res.status(400).json({
          error:
            'Please enter a valid email address.'
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error:
            'Password must be at least 6 characters.'
        });
      }

      const existing =
        await findUserByEmail(email);

      if (existing) {
        return res.status(409).json({
          error:
            'An account with this email already exists.'
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user =
        await createUser({
          name,
          email,
          password_hash: passwordHash,
          university,
          country,
          level
        });

      const token =
        createToken(user);

      await audit(
        user.id,
        'account_created',
        {
          country,
          level
        }
      );

      return res.status(201).json({
        token,
        user:
          pool && databaseReady
            ? pgUserToPublic(user)
            : localUserToPublic(user)
      });
    } catch (error) {
      console.error(
        'Registration error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not create your account.'
      });
    }
  }
);

app.post(
  '/api/auth/login',
  authLimiter,
  async (req, res) => {
    try {
      const email =
        cleanText(req.body?.email)
          .toLowerCase();

      const password =
        String(
          req.body?.password || ''
        );

      if (!email || !password) {
        return res.status(400).json({
          error:
            'Email and password are required.'
        });
      }

      const user =
        await findUserByEmail(email);

      if (!user) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      const passwordValid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!passwordValid) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      const token =
        createToken(user);

      await audit(
        user.id,
        'login'
      );

      return res.json({
        token,
        user:
          pool && databaseReady
            ? pgUserToPublic(user)
            : localUserToPublic(user)
      });
    } catch (error) {
      console.error(
        'Login error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not complete login.'
      });
    }
  }
);

app.get(
  '/api/me',
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(404).json({
          error:
            'User account not found.'
        });
      }

      return res.json({
        user:
          pool && databaseReady
            ? pgUserToPublic(user)
            : localUserToPublic(user)
      });
    } catch (error) {
      console.error(
        'Current-user error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not load your account.'
      });
    }
  }
);

app.put(
  '/api/users/profile',
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(404).json({
          error:
            'User account not found.'
        });
      }

      const name =
        req.body?.name !== undefined
          ? cleanText(req.body.name)
          : user.name;

      const university =
        req.body?.university !== undefined
          ? cleanText(
              req.body.university
            )
          : user.university || '';

      const country =
        req.body?.country !== undefined
          ? cleanText(
              req.body.country
            )
          : user.country || 'Nigeria';

      const level =
        req.body?.level !== undefined
          ? cleanText(
              req.body.level
            )
          : user.level || '200';

      if (name.length < 2) {
        return res.status(400).json({
          error:
            'Name is too short.'
        });
      }

      let updated;

      if (pool && databaseReady) {
        const result =
          await pool.query(
            `
              UPDATE users
              SET
                name = $2,
                university = $3,
                country = $4,
                level = $5,
                updated_at = NOW()
              WHERE id = $1
              RETURNING *
            `,
            [
              user.id,
              name,
              university,
              country,
              level
            ]
          );

        updated =
          result.rows[0] || null;
      } else {
        user.name = name;
        user.university = university;
        user.country = country;
        user.level = level;
        user.updated_at =
          new Date().toISOString();

        saveLocalDB();

        updated = user;
      }

      return res.json({
        user:
          pool && databaseReady
            ? pgUserToPublic(updated)
            : localUserToPublic(updated)
      });
    } catch (error) {
      console.error(
        'Profile update error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not update your profile.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Question filters
 * --------------------------------------------------------- */

app.get(
  '/api/subjects',
  async (req, res) => {
    try {
      let subjects = [];

      if (pool && databaseReady) {
        const result =
          await pool.query(
            `
              SELECT DISTINCT subject
              FROM questions
              WHERE subject IS NOT NULL
                AND subject <> ''
              ORDER BY subject
            `
          );

        subjects =
          result.rows.map(
            (row) => row.subject
          );
      } else {
        subjects = [
          ...new Set(
            loadQuestionsFromFile()
              .map(
                (question) =>
                  question.subject
              )
              .filter(Boolean)
          )
        ].sort();
      }

      return res.json({
        subjects
      });
    } catch (error) {
      console.error(
        'Subjects error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not load subjects.'
      });
    }
  }
);

app.get(
  '/api/question-filters',
  async (req, res) => {
    try {
      if (pool && databaseReady) {
        const [
          countriesResult,
          subjectsResult,
          topicsResult
        ] = await Promise.all([
          pool.query(`
            SELECT DISTINCT country
            FROM questions
            WHERE country IS NOT NULL
              AND country <> ''
            ORDER BY country
          `),

          pool.query(`
            SELECT DISTINCT subject
            FROM questions
            WHERE subject IS NOT NULL
              AND subject <> ''
            ORDER BY subject
          `),

          pool.query(`
            SELECT DISTINCT
              country,
              level,
              subject,
              topic
            FROM questions
            WHERE topic IS NOT NULL
              AND topic <> ''
            ORDER BY country, level, subject, topic
          `)
        ]);

        return res.json({
          countries:
            countriesResult.rows.map(
              (row) => row.country
            ),

          levels: [
            '100',
            '200',
            '300',
            '400',
            '500',
            '600'
          ],

          subjects:
            subjectsResult.rows.map(
              (row) => row.subject
            ),

          topics:
            topicsResult.rows.map(
              (row) => ({
                country: row.country,
                level: String(row.level),
                subject: row.subject,
                topic: row.topic
              })
            )
        });
      }

      const questions =
        loadQuestionsFromFile();

      const countries = [
        ...new Set(
          questions
            .map(
              (question) =>
                question.country
            )
            .filter(Boolean)
        )
      ].sort();

      const subjects = [
        ...new Set(
          questions
            .map(
              (question) =>
                question.subject
            )
            .filter(Boolean)
        )
      ].sort();

      const topics = [
        ...new Map(
          questions.map(
            (question) => [
              [
                question.country,
                question.level,
                question.subject,
                question.topic
              ].join('|'),

              {
                country:
                  question.country,
                level:
                  question.level,
                subject:
                  question.subject,
                topic:
                  question.topic
              }
            ]
          )
        ).values()
      ];

      return res.json({
        countries,
        levels: [
          '100',
          '200',
          '300',
          '400',
          '500',
          '600'
        ],
        subjects,
        topics
      });
    } catch (error) {
      console.error(
        'Question filters error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not load question filters.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Questions
 * --------------------------------------------------------- */

function publicQuestion(question) {
  return {
    id: question.id,
    question: question.question,
    options: question.options,
    answer_index:
      Number(question.answer_index),
    explanation:
      question.explanation || '',
    subject:
      question.subject || 'General',
    topic:
      question.topic || 'General',
    country:
      question.country || 'Nigeria',
    level:
      String(question.level || '200'),
    year:
      question.year || '',
    difficulty:
      question.difficulty || 'medium'
  };
}

app.get(
  '/api/questions/access',
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          error:
            'Authentication required.'
        });
      }

      return res.json({
        premium:
          Boolean(user.premium),

        free_limit:
          FREE_QUESTIONS_PER_SUBJECT,

        premium_required:
          !Boolean(user.premium)
      });
    } catch (error) {
      console.error(
        'Question access error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not determine question access.'
      });
    }
  }
);

app.get(
  '/api/questions',
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          error:
            'Authentication required.'
        });
      }

      const country =
        cleanText(req.query.country);

      const level =
        cleanText(req.query.level);

      const subject =
        cleanText(req.query.subject);

      const topic =
        cleanText(req.query.topic);

      const random =
        String(
          req.query.random || ''
        ).toLowerCase() === 'true';

      if (!country || !level) {
        return res.status(400).json({
          error:
            'Country and level are required.'
        });
      }

      let questions = [];

      if (pool && databaseReady) {
        const conditions = [
          'LOWER(country) = LOWER($1)',
          'level = $2'
        ];

        const params = [
          country,
          level
        ];

        if (subject) {
          params.push(subject);
          conditions.push(
            `LOWER(subject) = LOWER($${params.length})`
          );
        }

        if (topic) {
          params.push(topic);
          conditions.push(
            `LOWER(topic) = LOWER($${params.length})`
          );
        }

        let order;

        if (random) {
          order = 'RANDOM()';
        } else {
          order = 'created_at ASC';
        }

        const result =
          await pool.query(
            `
              SELECT *
              FROM questions
              WHERE ${conditions.join(
                ' AND '
              )}
              ORDER BY ${order}
            `,
            params
          );

        questions =
          result.rows;
      } else {
        questions =
          loadQuestionsFromFile()
            .filter(
              (question) =>
                question.country.toLowerCase() ===
                  country.toLowerCase() &&
                String(question.level) ===
                  String(level) &&
                (!subject ||
                  question.subject.toLowerCase() ===
                    subject.toLowerCase()) &&
                (!topic ||
                  question.topic.toLowerCase() ===
                    topic.toLowerCase())
            );

        if (random) {
          questions.sort(
            () => Math.random() - 0.5
          );
        }
      }

      const premium =
        Boolean(user.premium);

      /*
       * Free access is limited to the first
       * FREE_QUESTIONS_PER_SUBJECT questions
       * for the requested selection.
       *
       * Premium users receive the expanded set.
       */
      let limited =
        questions;

      let premiumRequired = false;

      if (!premium) {
        const freeLimit =
          FREE_QUESTIONS_PER_SUBJECT;

        limited =
          questions.slice(
            0,
            freeLimit
          );

        premiumRequired =
          questions.length > freeLimit;
      }

      return res.json({
        questions:
          limited.map(publicQuestion),

        total_available:
          questions.length,

        returned:
          limited.length,

        premium,

        premium_required:
          premiumRequired,

        free_limit:
          FREE_QUESTIONS_PER_SUBJECT
      });
    } catch (error) {
      console.error(
        'Question loading error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not load questions.'
      });
    }
  }
);

app.get(
  '/api/questions/:id',
  authenticateToken,
  async (req, res) => {
    try {
      const id =
        cleanText(req.params.id);

      let question = null;

      if (pool && databaseReady) {
        const result =
          await pool.query(
            `
              SELECT *
              FROM questions
              WHERE id = $1
              LIMIT 1
            `,
            [id]
          );

        question =
          result.rows[0] || null;
      } else {
        question =
          loadQuestionsFromFile()
            .find(
              (item) =>
                item.id === id
            ) || null;
      }

      if (!question) {
        return res.status(404).json({
          error:
            'Question not found.'
        });
      }

      const user =
        await getAuthenticatedUser(req);

      if (
        question.premium &&
        !user?.premium
      ) {
        return res.status(403).json({
          error:
            'This question requires Premium access.',
          premium_required: true
        });
      }

      return res.json({
        question:
          publicQuestion(question)
      });
    } catch (error) {
      console.error(
        'Question detail error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not load the question.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Scores
 * --------------------------------------------------------- */

app.post(
  '/api/scores',
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          error:
            'Authentication required.'
        });
      }

      const score =
        Math.max(
          0,
          Math.floor(
            Number(req.body?.score) || 0
          )
        );

      const total =
        Math.max(
          0,
          Math.floor(
            Number(req.body?.total) || 0
          )
        );

      const subject =
        cleanText(
          req.body?.subject,
          'General'
        ) || 'General';

      if (
        total <= 0 ||
        score > total
      ) {
        return res.status(400).json({
          error:
            'Invalid quiz score.'
        });
      }

      /*
       * XP formula:
       * base = correct answers
       * completion bonus = 5
       * capped at a reasonable amount
       */
      const xp =
        Math.min(
          250,
          score + 5
        );

      const id =
        generateId('score-');

      if (pool && databaseReady) {
        await pool.query(
          `
            INSERT INTO scores (
              id,
              user_id,
              subject,
              score,
              total,
              xp
            )
            VALUES ($1,$2,$3,$4,$5,$6)
          `,
          [
            id,
            user.id,
            subject,
            score,
            total,
            xp
          ]
        );
      } else {
        localDB.scores.push({
          id,
          user_id: user.id,
          subject,
          score,
          total,
          xp,
          created_at:
            new Date().toISOString()
        });

        saveLocalDB();
      }

      const updatedUser =
        await addUserXP(
          user.id,
          xp
        );

      await audit(
        user.id,
        'quiz_completed',
        {
          subject,
          score,
          total,
          xp
        }
      );

      return res.json({
        success: true,
        xp,
        user:
          updatedUser
            ? (
                pool &&
                databaseReady
                  ? pgUserToPublic(
                      updatedUser
                    )
                  : localUserToPublic(
                      updatedUser
                    )
              )
            : null
      });
    } catch (error) {
      console.error(
        'Score saving error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not save your score.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Leaderboard
 * --------------------------------------------------------- */

app.get(
  '/api/leaderboard',
  async (req, res) => {
    try {
      let leaderboard = [];

      if (pool && databaseReady) {
        const result =
          await pool.query(
            `
              SELECT
                u.id,
                u.name,
                u.university,
                u.country,
                u.xp
              FROM users u
              WHERE COALESCE(u.xp, 0) > 0
              ORDER BY u.xp DESC, u.created_at ASC
              LIMIT 100
            `
          );

        leaderboard =
          result.rows.map(
            (row) => ({
              id: row.id,
              name: row.name,
              university:
                row.university || '',
              country:
                row.country || '',
              xp:
                Number(row.xp || 0)
            })
          );
      } else {
        leaderboard =
          [...localDB.users]
            .filter(
              (user) =>
                Number(user.xp || 0) > 0
            )
            .sort(
              (a, b) =>
                Number(b.xp || 0) -
                Number(a.xp || 0)
            )
            .slice(0, 100)
            .map(
              (user) => ({
                id: user.id,
                name: user.name,
                university:
                  user.university || '',
                country:
                  user.country || '',
                xp:
                  Number(user.xp || 0)
              })
            );
      }

      return res.json({
        leaderboard
      });
    } catch (error) {
      console.error(
        'Leaderboard error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not load leaderboard.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Paystack: Initialize
 * --------------------------------------------------------- */

app.post(
  '/api/payments/initialize',
  authenticateToken,
  paymentLimiter,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          error:
            'Authentication required.'
        });
      }

      if (user.premium) {
        return res.status(400).json({
          error:
            'This account already has Premium access.'
        });
      }

      if (!paystackConfigured()) {
        console.error(
          'Payment initialization rejected: PAYSTACK_SECRET_KEY is missing or invalid.'
        );

        return res.status(503).json({
          error:
            'Paystack payment service is not configured. Please contact DENexpharm support.'
        });
      }

      /*
       * Production DENexpharm requires a LIVE key.
       * This prevents accidentally charging real users
       * through a test integration.
       */
      if (
        IS_PRODUCTION &&
        !paystackIsLive()
      ) {
        console.error(
          'Production payment attempted with a non-live Paystack key.'
        );

        return res.status(503).json({
          error:
            'Production Paystack is not configured with a live secret key.'
        });
      }

      /*
       * Prevent repeated clicks from creating
       * many simultaneous payment transactions.
       */
      const existing =
        await findPendingPaymentForUser(
          user.id
        );

      if (existing) {
        return res.json({
          authorization_url:
            existing.authorization_url ||
            null,
          reference:
            existing.reference,
          existing: true
        });
      }

      const reference =
        makePaystackReference();

      const amount =
        paymentAmountInMinorUnits(
          PREMIUM_PRICE
        );

      const payment = {
        id:
          generateId('payment-'),
        user_id:
          user.id,
        reference,
        provider:
          'paystack',
        amount,
        currency:
          PREMIUM_CURRENCY,
        status:
          'initialized',
        provider_status:
          '',
        metadata: {
          user_id:
            String(user.id),
          product:
            'DENexpharm Premium'
        }
      };

      /*
       * Store our own transaction BEFORE calling
       * Paystack. This lets us verify the transaction
       * later and prevents granting Premium to an
       * unknown reference.
       */
      await createPayment(payment);

      let paystackData;

      try {
        paystackData =
          await initializePaystackTransaction(
            user,
            reference
          );
      } catch (error) {
        await updatePayment(
          reference,
          {
            status: 'failed',
            provider_status:
              'initialization_failed'
          }
        );

        console.error(
          'Paystack transaction initialization error:',
          error.message
        );

        return res.status(502).json({
          error:
            'Paystack could not initialize the payment. Please try again.'
        });
      }

      await updatePayment(
        reference,
        {
          status: 'pending',
          provider_status:
            'initialized',
          metadata: {
            user_id:
              String(user.id),
            product:
              'DENexpharm Premium',
            access_code:
              paystackData.access_code ||
              null,
            authorization_url:
              paystackData.authorization_url
          }
        }
      );

      await audit(
        user.id,
        'payment_initialized',
        {
          reference,
          amount,
          currency:
            PREMIUM_CURRENCY
        }
      );

      return res.json({
        authorization_url:
          paystackData.authorization_url,
        access_code:
          paystackData.access_code ||
          null,
        reference:
          paystackData.reference ||
          reference
      });
    } catch (error) {
      console.error(
        'Payment initialize route error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not initialize the payment.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Paystack: Verify endpoint
 *
 * Useful if frontend or support needs to check a payment.
 * Premium is still granted only after our strict
 * verification succeeds.
 * --------------------------------------------------------- */

app.get(
  '/api/payments/verify/:reference',
  authenticateToken,
  async (req, res) => {
    try {
      const user =
        await getAuthenticatedUser(req);

      if (!user) {
        return res.status(401).json({
          error:
            'Authentication required.'
        });
      }

      const reference =
        cleanText(
          req.params.reference
        );

      if (!reference) {
        return res.status(400).json({
          error:
            'Payment reference is required.'
        });
      }

      const payment =
        await findPaymentByReference(
          reference
        );

      if (!payment) {
        return res.status(404).json({
          error:
            'Payment reference not found.'
        });
      }

      if (
        String(payment.user_id) !==
        String(user.id)
      ) {
        return res.status(403).json({
          error:
            'You are not authorized to view this payment.'
        });
      }

      const paymentData =
        await verifyPaystack(
          reference
        );

      let updatedUser = user;

      if (
        paymentData?.status ===
        'success'
      ) {
        updatedUser =
          await markPremium(
            reference,
            paymentData
          );
      }

      return res.json({
        success:
          paymentData?.status ===
          'success',
        status:
          paymentData?.status ||
          'unknown',
        premium:
          Boolean(
            updatedUser?.premium
          )
      });
    } catch (error) {
      console.error(
        'Payment verification route error:',
        error
      );

      return res.status(400).json({
        error:
          'Payment could not be verified.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Paystack callback
 * --------------------------------------------------------- */

app.get(
  '/api/payments/callback',
  async (req, res) => {
    const reference =
      cleanText(
        req.query.reference ||
        req.query.trxref
      );

    if (!reference) {
      return res.redirect(
        '/?payment=missing'
      );
    }

    try {
      const payment =
        await findPaymentByReference(
          reference
        );

      if (!payment) {
        console.error(
          'Callback for unknown payment:',
          reference
        );

        return res.redirect(
          '/?payment=failed'
        );
      }

      const paymentData =
        await verifyPaystack(
          reference
        );

      if (
        paymentData?.status !==
        'success'
      ) {
        await updatePayment(
          reference,
          {
            status: 'failed',
            provider_status:
              paymentData?.status ||
              'not_successful'
          }
        );

        return res.redirect(
          '/?payment=failed'
        );
      }

      await markPremium(
        reference,
        paymentData
      );

      return res.redirect(
        '/?payment=success'
      );
    } catch (error) {
      console.error(
        'Paystack callback error:',
        error
      );

      return res.redirect(
        '/?payment=failed'
      );
    }
  }
);

/* ---------------------------------------------------------
 * Paystack webhook
 *
 * IMPORTANT:
 * - Verify HMAC SHA512 against raw body.
 * - Return HTTP 200 promptly.
 * - Process charge.success asynchronously.
 *
 * Paystack may retry webhook deliveries, so all
 * processing is idempotent.
 * --------------------------------------------------------- */

function verifyPaystackSignature(
  req
) {
  if (
    !PAYSTACK_SECRET_KEY ||
    !req.rawBody
  ) {
    return false;
  }

  const signature =
    String(
      req.headers[
        'x-paystack-signature'
      ] || ''
    ).trim();

  if (!signature) {
    return false;
  }

  const expected =
    crypto
      .createHmac(
        'sha512',
        PAYSTACK_SECRET_KEY
      )
      .update(req.rawBody)
      .digest('hex');

  const suppliedBuffer =
    Buffer.from(
      signature,
      'utf8'
    );

  const expectedBuffer =
    Buffer.from(
      expected,
      'utf8'
    );

  if (
    suppliedBuffer.length !==
    expectedBuffer.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    suppliedBuffer,
    expectedBuffer
  );
}

app.post(
  '/api/payments/webhook',
  async (req, res) => {
    if (!verifyPaystackSignature(req)) {
      console.warn(
        'Rejected invalid Paystack webhook signature.'
      );

      return res.status(401).json({
        error:
          'Invalid webhook signature.'
      });
    }

    /*
     * Acknowledge immediately.
     * Paystack recommends returning a successful
     * response promptly and processing longer work
     * after acknowledgement.
     */
    res.status(200).json({
      received: true
    });

    /*
     * Continue processing after response.
     */
    setImmediate(
      async () => {
        try {
          const event =
            req.body || {};

          if (
            event.event !==
            'charge.success'
          ) {
            return;
          }

          const data =
            event.data || {};

          const reference =
            cleanText(
              data.reference
            );

          if (!reference) {
            console.warn(
              'Paystack charge.success webhook has no reference.'
            );

            return;
          }

          const payment =
            await findPaymentByReference(
              reference
            );

          /*
           * Unknown references are never granted
           * Premium automatically.
           */
          if (!payment) {
            console.warn(
              'Ignoring webhook for unknown payment:',
              reference
            );

            return;
          }

          /*
           * If already successful, do nothing.
           * This makes repeated webhook delivery safe.
           */
          if (
            payment.status ===
            'success'
          ) {
            return;
          }

          /*
           * Re-query Paystack rather than trusting
           * the webhook payload alone.
           */
          const verified =
            await verifyPaystack(
              reference
            );

          if (
            verified?.status !==
            'success'
          ) {
            await updatePayment(
              reference,
              {
                status: 'failed',
                provider_status:
                  verified?.status ||
                  'not_successful'
              }
            );

            return;
          }

          await markPremium(
            reference,
            verified
          );

          console.log(
            `Premium activated for payment ${reference}`
          );
        } catch (error) {
          console.error(
            'Paystack webhook processing error:',
            error
          );
        }
      }
    );
  }
);

/* ---------------------------------------------------------
 * Backwards compatibility
 * --------------------------------------------------------- */

app.post(
  '/api/upgrade',
  authenticateToken,
  async (req, res) => {
    return res.status(410).json({
      error:
        'The old upgrade endpoint has been retired. Use /api/payments/initialize.'
    });
  }
);

/* ---------------------------------------------------------
 * Admin question management
 * --------------------------------------------------------- */

app.post(
  '/api/admin/questions',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const question =
        normalizeQuestion(
          req.body || {},
          Date.now()
        );

      if (
        !question.question ||
        question.options.length < 2
      ) {
        return res.status(400).json({
          error:
            'A valid question with at least two options is required.'
        });
      }

      if (pool && databaseReady) {
        await pool.query(
          `
            INSERT INTO questions (
              id,
              question,
              options,
              answer_index,
              explanation,
              subject,
              topic,
              country,
              level,
              year,
              difficulty,
              premium
            )
            VALUES (
              $1,$2,$3::jsonb,$4,$5,$6,$7,$8,$9,$10,$11,$12
            )
            ON CONFLICT (id)
            DO UPDATE SET
              question = EXCLUDED.question,
              options = EXCLUDED.options,
              answer_index = EXCLUDED.answer_index,
              explanation = EXCLUDED.explanation,
              subject = EXCLUDED.subject,
              topic = EXCLUDED.topic,
              country = EXCLUDED.country,
              level = EXCLUDED.level,
              year = EXCLUDED.year,
              difficulty = EXCLUDED.difficulty,
              premium = EXCLUDED.premium,
              updated_at = NOW()
          `,
          [
            question.id,
            question.question,
            JSON.stringify(
              question.options
            ),
            question.answer_index,
            question.explanation,
            question.subject,
            question.topic,
            question.country,
            question.level,
            question.year,
            question.difficulty,
            question.premium
          ]
        );
      } else {
        const index =
          localDB.questions.findIndex(
            (item) =>
              item.id === question.id
          );

        if (index >= 0) {
          localDB.questions[index] =
            question;
        } else {
          localDB.questions.push(
            question
          );
        }

        saveLocalDB();
      }

      await audit(
        req.user.id,
        'admin_question_upsert',
        {
          question_id:
            question.id
        }
      );

      return res.status(201).json({
        question:
          publicQuestion(question)
      });
    } catch (error) {
      console.error(
        'Admin question error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not save question.'
      });
    }
  }
);

app.delete(
  '/api/admin/questions/:id',
  authenticateToken,
  requireAdmin,
  async (req, res) => {
    try {
      const id =
        cleanText(req.params.id);

      if (pool && databaseReady) {
        const result =
          await pool.query(
            `
              DELETE FROM questions
              WHERE id = $1
              RETURNING id
            `,
            [id]
          );

        if (!result.rows.length) {
          return res.status(404).json({
            error:
              'Question not found.'
          });
        }
      } else {
        const before =
          localDB.questions.length;

        localDB.questions =
          localDB.questions.filter(
            (item) =>
              item.id !== id
          );

        if (
          localDB.questions.length ===
          before
        ) {
          return res.status(404).json({
            error:
              'Question not found.'
          });
        }

        saveLocalDB();
      }

      await audit(
        req.user.id,
        'admin_question_delete',
        {
          question_id: id
        }
      );

      return res.json({
        success: true
      });
    } catch (error) {
      console.error(
        'Admin question delete error:',
        error
      );

      return res.status(500).json({
        error:
          'Could not delete question.'
      });
    }
  }
);

/* ---------------------------------------------------------
 * Static frontend
 * --------------------------------------------------------- */

if (fs.existsSync(PUBLIC_DIR)) {
  app.use(
    express.static(
      PUBLIC_DIR,
      {
        index: 'index.html',
        maxAge:
          IS_PRODUCTION
            ? '1h'
            : 0
      }
    )
  );
}

/*
 * Express 5-compatible SPA fallback.
 *
 * API routes have already been defined above, so only
 * non-API GET requests reach this fallback.
 */
app.get(
  /^\/(?!api(?:\/|$)).*/,
  (req, res) => {
    const indexFile =
      path.join(
        PUBLIC_DIR,
        'index.html'
      );

    if (
      fs.existsSync(indexFile)
    ) {
      return res.sendFile(
        indexFile
      );
    }

    return res.status(404).send(
      'DENexpharm frontend not found.'
    );
  }
);

/* ---------------------------------------------------------
 * 404 API handler
 * --------------------------------------------------------- */

app.use(
  '/api',
  (req, res) => {
    return res.status(404).json({
      error:
        'API endpoint not found.'
    });
  }
);

/* ---------------------------------------------------------
 * Global error handler
 * --------------------------------------------------------- */

app.use(
  (error, req, res, next) => {
    console.error(
      'Unhandled server error:',
      error
    );

    if (res.headersSent) {
      return next(error);
    }

    if (
      error.message ===
      'CORS origin not allowed.'
    ) {
      return res.status(403).json({
        error:
          'Request origin is not allowed.'
      });
    }

    return res.status(500).json({
      error:
        'Server error. Please try again.'
    });
  }
);

/* ---------------------------------------------------------
 * Startup
 * --------------------------------------------------------- */

async function startServer() {
  try {
    console.log(
      `Starting DENexpharm ${VERSION}...`
    );

    console.log(
      `Environment: ${NODE_ENV}`
    );

    console.log(
      `Premium: ${PREMIUM_PRICE} ${PREMIUM_CURRENCY}`
    );

    console.log(
      `Paystack configured: ${paystackConfigured()}`
    );

    if (paystackConfigured()) {
      console.log(
        `Paystack mode: ${
          paystackIsLive()
            ? 'LIVE'
            : 'TEST'
        }`
      );
    }

    if (pool) {
      await initializeDatabase();
    } else {
      console.warn(
        'DATABASE_URL not configured. Using local JSON database.'
      );

      localDB.questions =
        loadQuestionsFromFile();

      saveLocalDB();
    }

    /*
     * Production should always have PostgreSQL.
     */
    if (
      IS_PRODUCTION &&
      (!pool || !databaseReady)
    ) {
      throw new Error(
        'Production database is not available.'
      );
    }

    /*
     * Production Paystack should use a live key.
     */
    if (
      IS_PRODUCTION &&
      PAYSTACK_SECRET_KEY &&
      !paystackIsLive()
    ) {
      console.warn(
        'WARNING: PAYSTACK_SECRET_KEY is not a live key. Payment initialization will be rejected in production.'
      );
    }

    app.listen(
      PORT,
      '0.0.0.0',
      () => {
        console.log(
          `DENexpharm server listening on port ${PORT}`
        );

        console.log(
          `Health endpoint: /api/health`
        );

        console.log(
          `Paystack initialize endpoint: /api/payments/initialize`
        );

        console.log(
          `Paystack callback endpoint: /api/payments/callback`
        );

        console.log(
          `Paystack webhook endpoint: /api/payments/webhook`
        );
      }
    );
  } catch (error) {
    console.error(
      'DENexpharm startup failed:',
      error
    );

    process.exit(1);
  }
}

process.on(
  'SIGTERM',
  async () => {
    console.log(
      'SIGTERM received. Shutting down...'
    );

    if (pool) {
      await pool.end().catch(
        () => {}
      );
    }

    process.exit(0);
  }
);

process.on(
  'SIGINT',
  async () => {
    console.log(
      'SIGINT received. Shutting down...'
    );

    if (pool) {
      await pool.end().catch(
        () => {}
      );
    }

    process.exit(0);
  }
);

startServer();
