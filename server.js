'use strict';

/*
 * DENexpharm Production Server
 * Version 6.0.0
 *
 * Designed to work with:
 *   - public/index.html
 *   - PostgreSQL
 *   - JWT authentication
 *   - bcryptjs passwords
 *   - Paystack payments
 *   - question.json
 *
 * IMPORTANT:
 * This server expects the canonical PostgreSQL schema to use TEXT IDs.
 * Do NOT mix this with an old SERIAL/INTEGER users.id schema.
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

const ROOT = __dirname;
const PUBLIC_DIR = path.join(ROOT, 'public');
const QUESTION_FILE = path.join(ROOT, 'data', 'question.json');

/* =========================================================
   ENVIRONMENT
========================================================= */

const NODE_ENV = String(process.env.NODE_ENV || 'development').toLowerCase();
const IS_PRODUCTION = NODE_ENV === 'production';

const PORT = Number(process.env.PORT || 10000);

const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();

const JWT_SECRET = String(process.env.JWT_SECRET || '').trim();

const PAYSTACK_SECRET_KEY = String(
  process.env.PAYSTACK_SECRET_KEY ||
  process.env.PAYSTACK_SECRET ||
  ''
).trim();

const PAYSTACK_PUBLIC_KEY = String(
  process.env.PAYSTACK_PUBLIC_KEY || ''
).trim();

const PREMIUM_PRICE = Number(
  process.env.PREMIUM_PRICE || 5000
);

const PREMIUM_CURRENCY = String(
  process.env.PREMIUM_CURRENCY || 'NGN'
).trim().toUpperCase();

const PREMIUM_FREE_LIMIT = Math.max(
  1,
  Number(process.env.PREMIUM_FREE_LIMIT || 10)
);

const ADMIN_EMAIL = String(
  process.env.ADMIN_EMAIL || ''
).trim().toLowerCase();

const FRONTEND_ORIGIN = String(
  process.env.FRONTEND_ORIGIN || ''
).trim();

const PUBLIC_APP_URL = String(
  process.env.PUBLIC_APP_URL ||
  process.env.APP_URL ||
  ''
).trim().replace(/\/+$/, '');

const TRUST_PROXY = String(
  process.env.TRUST_PROXY || '1'
).trim();

const MAX_QUESTION_LIMIT = Math.min(
  100,
  Math.max(1, Number(process.env.MAX_QUESTION_LIMIT || 100))
);

/* =========================================================
   PRODUCTION VALIDATION
========================================================= */

if (IS_PRODUCTION) {
  if (!DATABASE_URL) {
    throw new Error(
      'DATABASE_URL must be configured in production.'
    );
  }

  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
      'JWT_SECRET must be configured and at least 32 characters long.'
    );
  }

  if (!PAYSTACK_SECRET_KEY) {
    throw new Error(
      'PAYSTACK_SECRET_KEY must be configured in production.'
    );
  }

  if (!PUBLIC_APP_URL) {
    throw new Error(
      'PUBLIC_APP_URL must be configured in production.'
    );
  }
}

if (!Number.isFinite(PREMIUM_PRICE) || PREMIUM_PRICE <= 0) {
  throw new Error(
    'PREMIUM_PRICE must be a positive number.'
  );
}

const SUPPORTED_CURRENCIES = new Set([
  'NGN',
  'USD',
  'GHS',
  'KES',
  'ZAR',
  'XOF'
]);

if (!SUPPORTED_CURRENCIES.has(PREMIUM_CURRENCY)) {
  throw new Error(
    `Unsupported PREMIUM_CURRENCY: ${PREMIUM_CURRENCY}`
  );
}

/*
 * Paystack expects amounts in subunits.
 * For the currencies used by this application, the transaction
 * amount is therefore multiplied by 100.
 */
const PREMIUM_AMOUNT_SUBUNIT = Math.round(
  PREMIUM_PRICE * 100
);

/* =========================================================
   DATABASE
========================================================= */

const pool = new Pool({
  connectionString: DATABASE_URL || undefined,
  ssl: IS_PRODUCTION
    ? { rejectUnauthorized: false }
    : undefined,
  max: Number(process.env.DB_POOL_MAX || 10),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

pool.on('error', (error) => {
  console.error('[PostgreSQL pool error]', error);
});

/* =========================================================
   EXPRESS
========================================================= */

const app = express();

app.disable('x-powered-by');

if (TRUST_PROXY) {
  app.set('trust proxy', TRUST_PROXY);
}

/* =========================================================
   SECURITY HEADERS
========================================================= */

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

/* =========================================================
   CORS
========================================================= */

const corsOptions = {
  origin(origin, callback) {
    /*
     * Same-origin browser requests normally have no Origin header.
     */
    if (!origin) {
      return callback(null, true);
    }

    if (!FRONTEND_ORIGIN) {
      /*
       * If no explicit frontend origin is configured, allow the
       * same deployed application to operate normally.
       */
      return callback(null, true);
    }

    const allowed = FRONTEND_ORIGIN
      .split(',')
      .map((value) => value.trim())
      .filter(Boolean);

    if (allowed.includes(origin)) {
      return callback(null, true);
    }

    return callback(
      new Error('Origin not allowed by CORS.')
    );
  },
  credentials: false
};

app.use(cors(corsOptions));

/* =========================================================
   RAW BODY FOR PAYSTACK WEBHOOK
========================================================= */

app.use(
  express.json({
    limit: '1mb',
    verify: (req, res, buffer) => {
      if (
        req.originalUrl === '/api/payments/webhook' ||
        req.path === '/api/payments/webhook'
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

/* =========================================================
   RATE LIMITERS
========================================================= */

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please try again later.'
  }
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'Too many authentication attempts. Please try again later.'
  }
});

const paymentLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'Too many payment requests. Please try again later.'
  }
});

const questionLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  limit: 100,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: {
    error: 'Too many question requests. Please slow down.'
  }
});

app.use('/api', generalLimiter);

/* =========================================================
   HELPERS
========================================================= */

function createId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function cleanString(value, maxLength = 500) {
  return String(value == null ? '' : value)
    .trim()
    .slice(0, maxLength);
}

function normalizeCountry(value) {
  return cleanString(value, 100);
}

function normalizeLevel(value) {
  return cleanString(value, 50);
}

function normalizeSubject(value) {
  return cleanString(value, 200);
}

function normalizeTopic(value) {
  return cleanString(value, 200);
}

function safeInteger(value, fallback = 0) {
  const number = Number(value);

  if (!Number.isInteger(number)) {
    return fallback;
  }

  return number;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongEnoughPassword(password) {
  return typeof password === 'string' &&
    password.length >= 6 &&
    password.length <= 200;
}

function publicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    university: user.university || '',
    country: user.country || '',
    level: user.level || '200',
    xp: Number(user.xp || 0),
    premium: Boolean(user.premium),
    is_admin: Boolean(user.is_admin)
  };
}

function signToken(user) {
  return jwt.sign(
    {
      sub: user.id,
      email: user.email
    },
    JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES_IN || '7d'
    }
  );
}

function getBearerToken(req) {
  const header = String(
    req.headers.authorization || ''
  );

  if (!header.startsWith('Bearer ')) {
    return '';
  }

  return header.slice(7).trim();
}

async function getUserById(id) {
  const result = await pool.query(
    `
      SELECT
        id,
        email,
        name,
        university,
        country,
        level,
        xp,
        premium,
        is_admin,
        created_at,
        updated_at
      FROM users
      WHERE id = $1
      LIMIT 1
    `,
    [id]
  );

  return result.rows[0] || null;
}

async function getUserByEmail(email) {
  const result = await pool.query(
    `
      SELECT
        id,
        email,
        name,
        university,
        country,
        level,
        xp,
        premium,
        is_admin,
        created_at,
        updated_at
      FROM users
      WHERE email = $1
      LIMIT 1
    `,
    [email]
  );

  return result.rows[0] || null;
}

async function authenticate(req, res, next) {
  try {
    const token = getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: 'Authentication required.'
      });
    }

    const payload = jwt.verify(token, JWT_SECRET);

    if (!payload || !payload.sub) {
      return res.status(401).json({
        error: 'Invalid authentication token.'
      });
    }

    const user = await getUserById(payload.sub);

    if (!user) {
      return res.status(401).json({
        error: 'User account not found.'
      });
    }

    req.user = user;

    next();
  } catch (error) {
    return res.status(401).json({
      error: 'Invalid or expired authentication token.'
    });
  }
}

function isAdmin(user) {
  if (!user) {
    return false;
  }

  if (Boolean(user.is_admin)) {
    return true;
  }

  if (
    ADMIN_EMAIL &&
    normalizeEmail(user.email) === ADMIN_EMAIL
  ) {
    return true;
  }

  return false;
}

function requireAdmin(req, res, next) {
  if (!isAdmin(req.user)) {
    return res.status(403).json({
      error: 'Administrator access required.'
    });
  }

  next();
}

async function auditLog({
  userId = null,
  action,
  details = {}
}) {
  try {
    await pool.query(
      `
        INSERT INTO audit_logs
        (
          id,
          user_id,
          action,
          details,
          created_at
        )
        VALUES
        ($1, $2, $3, $4::jsonb, NOW())
      `,
      [
        createId('audit'),
        userId,
        cleanString(action, 150),
        JSON.stringify(details || {})
      ]
    );
  } catch (error) {
    console.error(
      '[audit log error]',
      error.message
    );
  }
}

function questionPayload(question) {
  return {
    id: question.id,
    country: question.country,
    level: question.level,
    subject: question.subject,
    topic: question.topic,
    question: question.question,
    options: Array.isArray(question.options)
      ? question.options
      : [],
    answer_index: Number(question.answer_index),
    explanation: question.explanation || ''
  };
}

function sanitizeQuestionForClient(question) {
  return questionPayload(question);
}

function buildQuestionWhere(query) {
  const conditions = [];
  const values = [];

  const country = normalizeCountry(query.country);
  const level = normalizeLevel(query.level);
  const subject = normalizeSubject(query.subject);
  const topic = normalizeTopic(query.topic);

  if (country) {
    values.push(country);
    conditions.push(
      `LOWER(country) = LOWER($${values.length})`
    );
  }

  if (level) {
    values.push(level);
    conditions.push(
      `LOWER(level) = LOWER($${values.length})`
    );
  }

  if (subject) {
    values.push(subject);
    conditions.push(
      `LOWER(subject) = LOWER($${values.length})`
    );
  }

  if (topic) {
    values.push(topic);
    conditions.push(
      `LOWER(topic) = LOWER($${values.length})`
    );
  }

  conditions.push('active = TRUE');

  return {
    where: conditions.length
      ? `WHERE ${conditions.join(' AND ')}`
      : '',
    values
  };
}

function validQuestionObject(question) {
  if (!question || typeof question !== 'object') {
    return false;
  }

  if (!cleanString(question.question, 10000)) {
    return false;
  }

  if (
    !Array.isArray(question.options) ||
    question.options.length < 2
  ) {
    return false;
  }

  const answerIndex = Number(question.answer_index);

  if (
    !Number.isInteger(answerIndex) ||
    answerIndex < 0 ||
    answerIndex >= question.options.length
  ) {
    return false;
  }

  if (!cleanString(question.subject, 200)) {
    return false;
  }

  return true;
}

/* =========================================================
   PAYSTACK HELPERS
========================================================= */

async function paystackRequest(endpoint, options = {}) {
  if (!PAYSTACK_SECRET_KEY) {
    throw new Error(
      'Paystack secret key is not configured.'
    );
  }

  const response = await fetch(
    `https://api.paystack.co${endpoint}`,
    {
      method: options.method || 'GET',
      headers: {
        Authorization: `Bearer ${PAYSTACK_SECRET_KEY}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      },
      body:
        options.body === undefined
          ? undefined
          : JSON.stringify(options.body)
    }
  );

  let data = {};

  try {
    data = await response.json();
  } catch {
    data = {};
  }

  if (!response.ok || data.status === false) {
    const message =
      data.message ||
      `Paystack request failed with status ${response.status}.`;

    const error = new Error(message);
    error.paystack = data;
    error.status = response.status;

    throw error;
  }

  return data;
}

function createPaymentReference() {
  /*
   * Paystack references may contain alphanumeric characters and
   * -, ., = according to its API documentation.
   */
  return `DENEX-${Date.now()}-${crypto
    .randomBytes(8)
    .toString('hex')}`;
}

function verifyPaystackSignature(req) {
  const signature = String(
    req.headers['x-paystack-signature'] || ''
  ).trim();

  if (!signature || !req.rawBody) {
    return false;
  }

  const expected = crypto
    .createHmac('sha512', PAYSTACK_SECRET_KEY)
    .update(req.rawBody)
    .digest('hex');

  if (signature.length !== expected.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    return false;
  }
}

function transactionMatchesExpected(
  transaction,
  payment
) {
  if (!transaction || !payment) {
    return false;
  }

  const transactionReference = String(
    transaction.reference || ''
  );

  const paymentReference = String(
    payment.reference || ''
  );

  if (
    !transactionReference ||
    transactionReference !== paymentReference
  ) {
    return false;
  }

  const transactionCurrency = String(
    transaction.currency || ''
  ).toUpperCase();

  const paymentCurrency = String(
    payment.currency || ''
  ).toUpperCase();

  if (
    transactionCurrency !== paymentCurrency
  ) {
    return false;
  }

  const transactionAmount = Number(
    transaction.amount
  );

  const expectedAmount = Number(
    payment.amount_subunit
  );

  if (
    !Number.isFinite(transactionAmount) ||
    transactionAmount !== expectedAmount
  ) {
    return false;
  }

  return true;
}

async function verifyPaystackTransaction(reference) {
  const data = await paystackRequest(
    `/transaction/verify/${encodeURIComponent(reference)}`
  );

  if (!data || !data.data) {
    throw new Error(
      'Paystack returned an invalid verification response.'
    );
  }

  return data.data;
}

async function activatePaymentByReference(
  reference,
  source = 'unknown'
) {
  const paymentResult = await pool.query(
    `
      SELECT
        id,
        user_id,
        reference,
        amount,
        currency,
        status,
        provider_status,
        paid_at,
        metadata
      FROM payments
      WHERE reference = $1
      LIMIT 1
    `,
    [reference]
  );

  const payment = paymentResult.rows[0];

  if (!payment) {
    throw new Error(
      'Payment record was not found.'
    );
  }

  /*
   * If already fulfilled, don't award Premium twice.
   */
  if (
    payment.status === 'success' &&
    payment.paid_at
  ) {
    return {
      alreadyProcessed: true,
      payment
    };
  }

  const transaction =
    await verifyPaystackTransaction(reference);

  const amountSubunit =
    Math.round(Number(payment.amount) * 100);

  const verificationPayment = {
    reference: payment.reference,
    currency: payment.currency,
    amount_subunit: amountSubunit
  };

  if (
    !transactionMatchesExpected(
      transaction,
      verificationPayment
    )
  ) {
    await pool.query(
      `
        UPDATE payments
        SET
          status = $2,
          provider_status = $3
        WHERE reference = $1
      `,
      [
        reference,
        String(transaction.status || 'invalid'),
        String(transaction.status || 'invalid')
      ]
    );

    throw new Error(
      'Payment verification did not match the expected amount, currency, or reference.'
    );
  }

  if (
    String(transaction.status || '').toLowerCase() !==
    'success'
  ) {
    await pool.query(
      `
        UPDATE payments
        SET
          status = $2,
          provider_status = $3
        WHERE reference = $1
      `,
      [
        reference,
        String(transaction.status || 'pending'),
        String(transaction.status || 'pending')
      ]
    );

    return {
      alreadyProcessed: false,
      activated: false,
      payment: {
        ...payment,
        status: String(
          transaction.status || 'pending'
        )
      },
      transaction
    };
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const lockedPayment = await client.query(
      `
        SELECT
          id,
          user_id,
          reference,
          amount,
          currency,
          status,
          paid_at
        FROM payments
        WHERE reference = $1
        FOR UPDATE
      `,
      [reference]
    );

    if (!lockedPayment.rows[0]) {
      throw new Error(
        'Payment disappeared during verification.'
      );
    }

    const locked = lockedPayment.rows[0];

    if (
      locked.status === 'success' &&
      locked.paid_at
    ) {
      await client.query('COMMIT');

      return {
        alreadyProcessed: true,
        activated: true,
        payment: locked,
        transaction
      };
    }

    await client.query(
      `
        UPDATE payments
        SET
          status = 'success',
          provider_status = $2,
          paid_at = COALESCE(
            paid_at,
            NOW()
          ),
          metadata = COALESCE(
            metadata,
            '{}'::jsonb
          ) || $3::jsonb
        WHERE reference = $1
      `,
      [
        reference,
        String(transaction.status || 'success'),
        JSON.stringify({
          verification_source: source,
          paystack_transaction_id:
            transaction.id || null,
          paid_at:
            transaction.paid_at ||
            transaction.paidAt ||
            null,
          gateway_response:
            transaction.gateway_response ||
            null
        })
      ]
    );

    await client.query(
      `
        UPDATE users
        SET
          premium = TRUE,
          updated_at = NOW()
        WHERE id = $1
      `,
      [locked.user_id]
    );

    await client.query(
      `
        INSERT INTO audit_logs
        (
          id,
          user_id,
          action,
          details,
          created_at
        )
        VALUES
        ($1, $2, $3, $4::jsonb, NOW())
      `,
      [
        createId('audit'),
        locked.user_id,
        'premium_activated',
        JSON.stringify({
          reference,
          source,
          paystack_transaction_id:
            transaction.id || null
        })
      ]
    );

    await client.query('COMMIT');

    return {
      alreadyProcessed: false,
      activated: true,
      payment: {
        ...locked,
        status: 'success',
        paid_at: new Date().toISOString()
      },
      transaction
    };
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Ignore rollback error.
    }

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function verifyCanonicalSchema() {
  /*
   * This intentionally verifies the ID types instead of silently
   * trying to convert an existing incompatible database.
   */
  const checks = [
    {
      table: 'users',
      column: 'id',
      expected: 'text'
    },
    {
      table: 'questions',
      column: 'id',
      expected: 'text'
    },
    {
      table: 'scores',
      column: 'id',
      expected: 'text'
    },
    {
      table: 'payments',
      column: 'id',
      expected: 'text'
    }
  ];

  for (const check of checks) {
    const result = await pool.query(
      `
        SELECT data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = $1
          AND column_name = $2
        LIMIT 1
      `,
      [
        check.table,
        check.column
      ]
    );

    if (!result.rows.length) {
      continue;
    }

    const actual =
      result.rows[0].data_type;

    if (actual !== check.expected) {
      throw new Error(
        `Database schema mismatch: ${check.table}.${check.column} is ${actual}, but this server requires ${check.expected}. Replace/migrate the old SERIAL schema with the canonical TEXT-ID schema before deploying this server.`
      );
    }
  }
}

async function initializeDatabase() {
  if (!DATABASE_URL) {
    if (IS_PRODUCTION) {
      throw new Error(
        'DATABASE_URL is required in production.'
      );
    }

    console.warn(
      '[database] DATABASE_URL not configured. Database features will not work.'
    );

    return;
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    /*
     * USERS
     */
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
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
      )
    `);

    /*
     * QUESTIONS
     */
    await client.query(`
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
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    /*
     * SCORES
     */
    await client.query(`
      CREATE TABLE IF NOT EXISTS scores (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        subject TEXT NOT NULL,
        score INTEGER NOT NULL,
        total INTEGER NOT NULL,
        xp_awarded INTEGER NOT NULL DEFAULT 0,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    /*
     * PAYMENTS
     */
    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        reference TEXT UNIQUE NOT NULL,
        amount NUMERIC(14,2) NOT NULL,
        currency TEXT NOT NULL,
        status TEXT NOT NULL,
        provider_status TEXT DEFAULT '',
        paid_at TIMESTAMPTZ,
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    /*
     * AUDIT LOGS
     */
    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        details JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    /*
     * Helpful indexes.
     */
    await client.query(`
      CREATE INDEX IF NOT EXISTS users_country_level_idx
      ON users(country, level)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS users_xp_idx
      ON users(xp DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS questions_country_level_subject_idx
      ON questions(country, level, subject)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS questions_country_level_topic_idx
      ON questions(country, level, topic)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS questions_subject_idx
      ON questions(subject)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS questions_active_idx
      ON questions(active)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS scores_user_idx
      ON scores(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS scores_score_idx
      ON scores(score DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS payments_user_idx
      ON payments(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS payments_status_idx
      ON payments(status)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS payments_created_idx
      ON payments(created_at DESC)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS audit_logs_user_idx
      ON audit_logs(user_id)
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS audit_logs_created_idx
      ON audit_logs(created_at DESC)
    `);

    /*
     * Repair ordinary nullable values if an older compatible TEXT
     * schema had them.
     */
    await client.query(`
      UPDATE users
      SET
        university = COALESCE(university, ''),
        country = COALESCE(country, ''),
        level = CASE
          WHEN level IS NULL OR BTRIM(level) = ''
          THEN '200'
          ELSE level
        END,
        xp = COALESCE(xp, 0),
        premium = COALESCE(premium, FALSE),
        is_admin = COALESCE(is_admin, FALSE),
        updated_at = COALESCE(updated_at, NOW())
    `);

    await client.query(`
      UPDATE questions
      SET
        country = CASE
          WHEN country IS NULL OR BTRIM(country) = ''
          THEN 'Nigeria'
          ELSE country
        END,
        level = CASE
          WHEN level IS NULL OR BTRIM(level) = ''
          THEN '200'
          ELSE level
        END,
        topic = COALESCE(topic, ''),
        explanation = COALESCE(explanation, ''),
        active = COALESCE(active, TRUE),
        updated_at = COALESCE(updated_at, NOW())
    `);

    await client.query('COMMIT');

    /*
     * Check existing schema types after initialization.
     */
    await verifyCanonicalSchema();

    console.log('[database] PostgreSQL initialized successfully.');
  } catch (error) {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Ignore rollback error.
    }

    console.error(
      '[database initialization failed]',
      error
    );

    throw error;
  } finally {
    client.release();
  }
}

/* =========================================================
   QUESTION IMPORT
========================================================= */

function normalizeQuestionFromFile(item, index) {
  if (!item || typeof item !== 'object') {
    return null;
  }

  const question = {
    id:
      cleanString(item.id, 200) ||
      `q-${crypto
        .createHash('sha256')
        .update(
          JSON.stringify({
            index,
            question: item.question,
            subject: item.subject,
            country: item.country,
            level: item.level
          })
        )
        .digest('hex')
        .slice(0, 32)}`,
    country:
      normalizeCountry(item.country) ||
      'Nigeria',
    level:
      normalizeLevel(item.level) ||
      '200',
    subject:
      normalizeSubject(item.subject) ||
      'General',
    topic:
      normalizeTopic(item.topic),
    question:
      cleanString(item.question, 10000),
    options:
      Array.isArray(item.options)
        ? item.options
            .map((option) =>
              cleanString(option, 2000)
            )
            .filter(Boolean)
        : [],
    answer_index:
      Number(item.answer_index),
    explanation:
      cleanString(
        item.explanation,
        10000
      ),
    active:
      item.active !== false
  };

  if (!validQuestionObject(question)) {
    return null;
  }

  return question;
}

async function importQuestionsFromFile() {
  if (!fs.existsSync(QUESTION_FILE)) {
    console.log(
      `[questions] No question file found at ${QUESTION_FILE}.`
    );
    return {
      imported: 0,
      skipped: 0
    };
  }

  let raw;

  try {
    raw = JSON.parse(
      fs.readFileSync(
        QUESTION_FILE,
        'utf8'
      )
    );
  } catch (error) {
    console.error(
      '[questions] Could not parse question.json:',
      error.message
    );

    return {
      imported: 0,
      skipped: 0
    };
  }

  let items = [];

  if (Array.isArray(raw)) {
    items = raw;
  } else if (
    raw &&
    Array.isArray(raw.questions)
  ) {
    items = raw.questions;
  }

  if (!items.length) {
    console.log(
      '[questions] question.json contains no questions.'
    );

    return {
      imported: 0,
      skipped: 0
    };
  }

  let imported = 0;
  let skipped = 0;

  for (let index = 0; index < items.length; index += 1) {
    const question =
      normalizeQuestionFromFile(
        items[index],
        index
      );

    if (!question) {
      skipped += 1;
      continue;
    }

    try {
      await pool.query(
        `
          INSERT INTO questions
          (
            id,
            country,
            level,
            subject,
            topic,
            question,
            options,
            answer_index,
            explanation,
            active,
            created_at,
            updated_at
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7::jsonb,
            $8,
            $9,
            $10,
            NOW(),
            NOW()
          )
          ON CONFLICT (id)
          DO UPDATE SET
            country = EXCLUDED.country,
            level = EXCLUDED.level,
            subject = EXCLUDED.subject,
            topic = EXCLUDED.topic,
            question = EXCLUDED.question,
            options = EXCLUDED.options,
            answer_index = EXCLUDED.answer_index,
            explanation = EXCLUDED.explanation,
            active = EXCLUDED.active,
            updated_at = NOW()
        `,
        [
          question.id,
          question.country,
          question.level,
          question.subject,
          question.topic,
          question.question,
          JSON.stringify(question.options),
          question.answer_index,
          question.explanation,
          question.active
        ]
      );

      imported += 1;
    } catch (error) {
      skipped += 1;

      if (skipped <= 10) {
        console.error(
          `[questions] Failed question ${index}:`,
          error.message
        );
      }
    }
  }

  console.log(
    `[questions] Imported/updated: ${imported}; skipped: ${skipped}.`
  );

  return {
    imported,
    skipped
  };
}

/* =========================================================
   HEALTH
========================================================= */

app.get('/api/health', async (req, res) => {
  let database = 'ok';

  try {
    await pool.query('SELECT 1');
  } catch {
    database = 'error';
  }

  res.json({
    ok: database === 'ok',
    service: 'DENexpharm',
    version: '6.0.0',
    environment: NODE_ENV,
    database,
    premiumPrice: PREMIUM_PRICE,
    premiumCurrency: PREMIUM_CURRENCY,
    premiumFreeLimit: PREMIUM_FREE_LIMIT,
    paystackConfigured: Boolean(
      PAYSTACK_SECRET_KEY
    ),
    paystackPublicKey:
      PAYSTACK_PUBLIC_KEY || null
  });
});

/*
 * Simple root health endpoint as well.
 */
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');

    res.json({
      ok: true,
      service: 'DENexpharm',
      version: '6.0.0'
    });
  } catch {
    res.status(503).json({
      ok: false,
      service: 'DENexpharm',
      version: '6.0.0'
    });
  }
});

/* =========================================================
   AUTH
========================================================= */

app.post(
  '/api/auth/register',
  authLimiter,
  async (req, res) => {
    try {
      const name = cleanString(
        req.body.name,
        120
      );

      const email = normalizeEmail(
        req.body.email
      );

      const password =
        typeof req.body.password === 'string'
          ? req.body.password
          : '';

      const university = cleanString(
        req.body.university,
        200
      );

      const country =
        normalizeCountry(
          req.body.country
        ) || 'Nigeria';

      const level =
        normalizeLevel(
          req.body.level
        ) || '200';

      if (!name) {
        return res.status(400).json({
          error: 'Full name is required.'
        });
      }

      if (!isValidEmail(email)) {
        return res.status(400).json({
          error: 'Please provide a valid email address.'
        });
      }

      if (!isStrongEnoughPassword(password)) {
        return res.status(400).json({
          error:
            'Password must be between 6 and 200 characters.'
        });
      }

      const existing =
        await getUserByEmail(email);

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

      const id = createId('user');

      const isAdmin =
        ADMIN_EMAIL &&
        email === ADMIN_EMAIL;

      const result = await pool.query(
        `
          INSERT INTO users
          (
            id,
            email,
            password_hash,
            name,
            university,
            country,
            level,
            xp,
            premium,
            is_admin,
            created_at,
            updated_at
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7,
            0,
            FALSE,
            $8,
            NOW(),
            NOW()
          )
          RETURNING
            id,
            email,
            name,
            university,
            country,
            level,
            xp,
            premium,
            is_admin,
            created_at,
            updated_at
        `,
        [
          id,
          email,
          passwordHash,
          name,
          university,
          country,
          level,
          Boolean(isAdmin)
        ]
      );

      const user = result.rows[0];
      const token = signToken(user);

      await auditLog({
        userId: user.id,
        action: 'account_created',
        details: {
          country: user.country,
          level: user.level
        }
      });

      return res.status(201).json({
        token,
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        '[register error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not create the account.'
      });
    }
  }
);

app.post(
  '/api/auth/login',
  authLimiter,
  async (req, res) => {
    try {
      const email = normalizeEmail(
        req.body.email
      );

      const password =
        typeof req.body.password === 'string'
          ? req.body.password
          : '';

      if (
        !isValidEmail(email) ||
        !password
      ) {
        return res.status(400).json({
          error:
            'Email and password are required.'
        });
      }

      const result = await pool.query(
        `
          SELECT
            id,
            email,
            password_hash,
            name,
            university,
            country,
            level,
            xp,
            premium,
            is_admin,
            created_at,
            updated_at
          FROM users
          WHERE email = $1
          LIMIT 1
        `,
        [email]
      );

      const user = result.rows[0];

      if (!user) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.password_hash
        );

      if (!valid) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      const token = signToken(user);

      await auditLog({
        userId: user.id,
        action: 'login',
        details: {}
      });

      return res.json({
        token,
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        '[login error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not complete login.'
      });
    }
  }
);

/* =========================================================
   CURRENT USER
========================================================= */

app.get(
  '/api/me',
  authenticate,
  async (req, res) => {
    try {
      const user =
        await getUserById(
          req.user.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User account not found.'
        });
      }

      return res.json({
        user: publicUser(user)
      });
    } catch (error) {
      console.error(
        '[/api/me]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load your account.'
      });
    }
  }
);

/* =========================================================
   QUESTION FILTERS
========================================================= */

app.get(
  '/api/question-filters',
  questionLimiter,
  async (req, res) => {
    try {
      const countriesResult =
        await pool.query(`
          SELECT DISTINCT country
          FROM questions
          WHERE active = TRUE
            AND country IS NOT NULL
            AND BTRIM(country) <> ''
          ORDER BY country ASC
        `);

      const subjectsResult =
        await pool.query(`
          SELECT DISTINCT subject
          FROM questions
          WHERE active = TRUE
            AND subject IS NOT NULL
            AND BTRIM(subject) <> ''
          ORDER BY subject ASC
        `);

      const topicsResult =
        await pool.query(`
          SELECT DISTINCT
            country,
            level,
            subject,
            topic
          FROM questions
          WHERE active = TRUE
            AND topic IS NOT NULL
            AND BTRIM(topic) <> ''
          ORDER BY
            country ASC,
            level ASC,
            subject ASC,
            topic ASC
        `);

      const countries =
        countriesResult.rows.map(
          (row) => row.country
        );

      const subjects =
        subjectsResult.rows.map(
          (row) => row.subject
        );

      const topics =
        topicsResult.rows.map(
          (row) => ({
            country: row.country,
            level: String(row.level),
            subject: row.subject,
            topic: row.topic
          })
        );

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
        '[question-filters error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load question filters.'
      });
    }
  }
);

/* =========================================================
   QUESTIONS
========================================================= */

app.get(
  '/api/questions',
  questionLimiter,
  authenticate,
  async (req, res) => {
    try {
      const {
        where,
        values
      } = buildQuestionWhere(
        req.query
      );

      const requestedLimit =
        Math.min(
          MAX_QUESTION_LIMIT,
          Math.max(
            1,
            Number(
              req.query.limit || MAX_QUESTION_LIMIT
            )
          )
        );

      const isPremium =
        Boolean(req.user.premium);

      /*
       * Free users receive at most the configured number.
       * Premium users can request the full configured maximum.
       */
      const effectiveLimit =
        isPremium
          ? requestedLimit
          : Math.min(
              requestedLimit,
              PREMIUM_FREE_LIMIT
            );

      const random =
        String(
          req.query.random || ''
        ).toLowerCase() === 'true';

      const orderBy = random
        ? 'ORDER BY RANDOM()'
        : 'ORDER BY updated_at DESC, id ASC';

      values.push(effectiveLimit);

      const result = await pool.query(
        `
          SELECT
            id,
            country,
            level,
            subject,
            topic,
            question,
            options,
            answer_index,
            explanation,
            active,
            updated_at
          FROM questions
          ${where}
          ${orderBy}
          LIMIT $${values.length}
        `,
        values
      );

      const questions =
        result.rows.map(
          sanitizeQuestionForClient
        );

      /*
       * Determine whether additional questions exist for the same
       * selection. This lets the frontend explain the free limit.
       */
      let premiumRequired = false;

      if (!isPremium) {
        const countResult =
          await pool.query(
            `
              SELECT COUNT(*)::INTEGER AS count
              FROM questions
              ${where}
            `,
            values.slice(0, -1)
          );

        premiumRequired =
          Number(
            countResult.rows[0]?.count || 0
          ) > PREMIUM_FREE_LIMIT;
      }

      return res.json({
        questions,
        premium: isPremium,
        premium_required:
          premiumRequired,
        free_limit:
          PREMIUM_FREE_LIMIT,
        total_returned:
          questions.length
      });
    } catch (error) {
      console.error(
        '[questions error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load questions.'
      });
    }
  }
);

/* =========================================================
   SAVE SCORE
========================================================= */

app.post(
  '/api/scores',
  authenticate,
  async (req, res) => {
    try {
      const subject =
        normalizeSubject(
          req.body.subject
        ) || 'General';

      const score =
        safeInteger(
          req.body.score,
          -1
        );

      const total =
        safeInteger(
          req.body.total,
          -1
        );

      /*
       * Basic validation prevents obviously fraudulent values.
       *
       * The frontend should not be trusted as a security boundary.
       * For a future hardened competitive mode, use server-issued
       * quiz/session IDs so the server can calculate the score
       * itself rather than accepting a client-submitted score.
       */
      if (
        total < 1 ||
        total > MAX_QUESTION_LIMIT
      ) {
        return res.status(400).json({
          error:
            'Invalid quiz total.'
        });
      }

      if (
        score < 0 ||
        score > total
      ) {
        return res.status(400).json({
          error:
            'Invalid quiz score.'
        });
      }

      const percentage =
        Math.round(
          (score / total) * 100
        );

      /*
       * Simple XP formula:
       * base XP = 5 per correct answer
       * performance bonus = up to 20
       */
      const xpAwarded =
        (score * 5) +
        Math.floor(
          percentage / 20
        );

      const client =
        await pool.connect();

      try {
        await client.query(
          'BEGIN'
        );

        await client.query(
          `
            INSERT INTO scores
            (
              id,
              user_id,
              subject,
              score,
              total,
              xp_awarded,
              created_at
            )
            VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6,
              NOW()
            )
          `,
          [
            createId('score'),
            req.user.id,
            subject,
            score,
            total,
            xpAwarded
          ]
        );

        const xpResult =
          await client.query(
            `
              UPDATE users
              SET
                xp = COALESCE(xp, 0) + $2,
                updated_at = NOW()
              WHERE id = $1
              RETURNING xp
            `,
            [
              req.user.id,
              xpAwarded
            ]
          );

        await client.query(
          'COMMIT'
        );

        await auditLog({
          userId: req.user.id,
          action: 'quiz_completed',
          details: {
            subject,
            score,
            total,
            percentage,
            xp_awarded:
              xpAwarded
          }
        });

        return res.status(201).json({
          success: true,
          score,
          total,
          percentage,
          xp: xpAwarded,
          total_xp:
            Number(
              xpResult.rows[0]?.xp || 0
            )
        });
      } catch (error) {
        try {
          await client.query(
            'ROLLBACK'
          );
        } catch {
          // Ignore rollback errors.
        }

        throw error;
      } finally {
        client.release();
      }
    } catch (error) {
      console.error(
        '[scores error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not save your score.'
      });
    }
  }
);

/* =========================================================
   LEADERBOARD
========================================================= */

app.get(
  '/api/leaderboard',
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            id,
            name,
            university,
            country,
            xp
          FROM users
          ORDER BY
            xp DESC,
            created_at ASC
          LIMIT 100
        `);

      const leaderboard =
        result.rows.map(
          (student) => ({
            id: student.id,
            name: student.name,
            university:
              student.university || '',
            country:
              student.country || '',
            xp:
              Number(student.xp || 0)
          })
        );

      return res.json({
        leaderboard
      });
    } catch (error) {
      console.error(
        '[leaderboard error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load leaderboard.'
      });
    }
  }
);

/* =========================================================
   PREMIUM PAYMENT INITIALIZATION
========================================================= */

app.post(
  '/api/payments/initialize',
  paymentLimiter,
  authenticate,
  async (req, res) => {
    try {
      if (req.user.premium) {
        return res.status(400).json({
          error:
            'This account already has Premium access.'
        });
      }

      if (!PAYSTACK_SECRET_KEY) {
        return res.status(503).json({
          error:
            'Payment service is not configured.'
        });
      }

      const reference =
        createPaymentReference();

      /*
       * The amount is taken ONLY from server configuration.
       * Never trust an amount sent by the browser.
       */
      const amount =
        PREMIUM_AMOUNT_SUBUNIT;

      const callbackUrl =
        `${PUBLIC_APP_URL}/api/payments/callback`;

      const metadata = {
        user_id: req.user.id,
        product: 'DENexpharm Premium',
        currency: PREMIUM_CURRENCY,
        amount: PREMIUM_PRICE,
        custom_fields: [
          {
            display_name:
              'DENexpharm User ID',
            variable_name:
              'denexpharm_user_id',
            value:
              req.user.id
          },
          {
            display_name:
              'Product',
            variable_name:
              'product',
            value:
              'DENexpharm Premium'
          }
        ]
      };

      /*
       * Store the payment before redirecting to Paystack.
       */
      await pool.query(
        `
          INSERT INTO payments
          (
            id,
            user_id,
            reference,
            amount,
            currency,
            status,
            provider_status,
            metadata,
            created_at,
            updated_at
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            'initialized',
            'initialized',
            $6::jsonb,
            NOW(),
            NOW()
          )
        `,
        [
          createId('payment'),
          req.user.id,
          reference,
          PREMIUM_PRICE,
          PREMIUM_CURRENCY,
          JSON.stringify({
            product:
              'DENexpharm Premium',
            amount_subunit:
              amount,
            created_by:
              'denexpharm_server'
          })
        ]
      );

      try {
        const data =
          await paystackRequest(
            '/transaction/initialize',
            {
              method: 'POST',
              body: {
                email:
                  req.user.email,
                amount:
                  String(amount),
                currency:
                  PREMIUM_CURRENCY,
                reference,
                callback_url:
                  callbackUrl,
                metadata
              }
            }
          );

        if (
          !data ||
          !data.status ||
          !data.data ||
          !data.data.authorization_url
        ) {
          throw new Error(
            'Paystack did not return an authorization URL.'
          );
        }

        await pool.query(
          `
            UPDATE payments
            SET
              provider_status = $2,
              metadata = metadata || $3::jsonb,
              updated_at = NOW()
            WHERE reference = $1
          `,
          [
            reference,
            'initialized',
            JSON.stringify({
              paystack_access_code:
                data.data.access_code ||
                null
            })
          ]
        );

        await auditLog({
          userId: req.user.id,
          action: 'premium_payment_initialized',
          details: {
            reference,
            currency:
              PREMIUM_CURRENCY
          }
        });

        return res.json({
          authorization_url:
            data.data.authorization_url,
          access_code:
            data.data.access_code || null,
          reference
        });
      } catch (paystackError) {
        await pool.query(
          `
            UPDATE payments
            SET
              status = 'failed',
              provider_status = $2,
              updated_at = NOW()
            WHERE reference = $1
          `,
          [
            reference,
            cleanString(
              paystackError.message,
              500
            )
          ]
        );

        throw paystackError;
      }
    } catch (error) {
      console.error(
        '[payment initialize error]',
        error
      );

      return res.status(500).json({
        error:
          error.message ||
          'Could not initialize payment.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK WEBHOOK
========================================================= */

app.post(
  '/api/payments/webhook',
  async (req, res) => {
    try {
      /*
       * Paystack recommends validating the webhook signature
       * before processing the event.
       */
      if (!verifyPaystackSignature(req)) {
        return res.status(401).json({
          error:
            'Invalid webhook signature.'
        });
      }

      /*
       * Respond successfully once the event has been authenticated.
       * Processing continues synchronously below so Premium is updated
       * before this request completes.
       */
      const event = req.body || {};

      const eventType =
        String(event.event || '');

      const data =
        event.data || {};

      if (
        eventType !==
        'charge.success'
      ) {
        return res.status(200).json({
          received: true,
          ignored: true
        });
      }

      const reference =
        String(
          data.reference || ''
        ).trim();

      if (!reference) {
        return res.status(400).json({
          error:
            'Webhook payment reference missing.'
        });
      }

      try {
        await activatePaymentByReference(
          reference,
          'webhook'
        );
      } catch (error) {
        /*
         * Do not silently activate Premium if verification fails.
         */
        console.error(
          '[webhook verification error]',
          error.message
        );

        return res.status(400).json({
          error:
            'Payment verification failed.'
        });
      }

      return res.status(200).json({
        received: true
      });
    } catch (error) {
      console.error(
        '[webhook error]',
        error
      );

      return res.status(500).json({
        error:
          'Webhook processing failed.'
      });
    }
  }
);

/* =========================================================
   PAYSTACK CALLBACK
========================================================= */

app.get(
  '/api/payments/callback',
  async (req, res) => {
    const reference =
      String(
        req.query.reference || ''
      ).trim();

    if (!reference) {
      return res.redirect(
        '/?payment=missing'
      );
    }

    try {
      const result =
        await activatePaymentByReference(
          reference,
          'callback'
        );

      if (result.activated) {
        return res.redirect(
          '/?payment=success'
        );
      }

      return res.redirect(
        '/?payment=failed'
      );
    } catch (error) {
      console.error(
        '[payment callback error]',
        error
      );

      return res.redirect(
        '/?payment=failed'
      );
    }
  }
);

/* =========================================================
   PAYMENT STATUS
========================================================= */

app.get(
  '/api/payments/status/:reference',
  authenticate,
  async (req, res) => {
    try {
      const reference =
        String(
          req.params.reference || ''
        ).trim();

      if (!reference) {
        return res.status(400).json({
          error:
            'Payment reference is required.'
        });
      }

      const result =
        await pool.query(
          `
            SELECT
              reference,
              amount,
              currency,
              status,
              provider_status,
              paid_at,
              created_at
            FROM payments
            WHERE reference = $1
              AND user_id = $2
            LIMIT 1
          `,
          [
            reference,
            req.user.id
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            'Payment not found.'
        });
      }

      return res.json({
        payment:
          result.rows[0]
      });
    } catch (error) {
      console.error(
        '[payment status error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load payment status.'
      });
    }
  }
);

/* =========================================================
   ADMIN: USERS
========================================================= */

app.get(
  '/api/admin/users',
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            id,
            email,
            name,
            university,
            country,
            level,
            xp,
            premium,
            is_admin,
            created_at,
            updated_at
          FROM users
          ORDER BY created_at DESC
          LIMIT 500
        `);

      return res.json({
        users:
          result.rows.map(
            publicUser
          )
      });
    } catch (error) {
      console.error(
        '[admin users error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load users.'
      });
    }
  }
);

/* =========================================================
   ADMIN: QUESTIONS
========================================================= */

app.post(
  '/api/admin/questions',
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const question =
        normalizeQuestionFromFile(
          req.body,
          0
        );

      if (!question) {
        return res.status(400).json({
          error:
            'Invalid question data.'
        });
      }

      await pool.query(
        `
          INSERT INTO questions
          (
            id,
            country,
            level,
            subject,
            topic,
            question,
            options,
            answer_index,
            explanation,
            active,
            created_at,
            updated_at
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5,
            $6,
            $7::jsonb,
            $8,
            $9,
            $10,
            NOW(),
            NOW()
          )
          ON CONFLICT (id)
          DO UPDATE SET
            country = EXCLUDED.country,
            level = EXCLUDED.level,
            subject = EXCLUDED.subject,
            topic = EXCLUDED.topic,
            question = EXCLUDED.question,
            options = EXCLUDED.options,
            answer_index = EXCLUDED.answer_index,
            explanation = EXCLUDED.explanation,
            active = EXCLUDED.active,
            updated_at = NOW()
        `,
        [
          question.id,
          question.country,
          question.level,
          question.subject,
          question.topic,
          question.question,
          JSON.stringify(
            question.options
          ),
          question.answer_index,
          question.explanation,
          question.active
        ]
      );

      await auditLog({
        userId: req.user.id,
        action: 'question_upserted',
        details: {
          question_id:
            question.id
        }
      });

      return res.status(201).json({
        success: true,
        question:
          questionPayload(question)
      });
    } catch (error) {
      console.error(
        '[admin question error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not save question.'
      });
    }
  }
);

/* =========================================================
   ADMIN: PAYMENT RECORDS
========================================================= */

app.get(
  '/api/admin/payments',
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const result =
        await pool.query(`
          SELECT
            p.id,
            p.user_id,
            u.email,
            u.name,
            p.reference,
            p.amount,
            p.currency,
            p.status,
            p.provider_status,
            p.paid_at,
            p.created_at,
            p.updated_at
          FROM payments p
          LEFT JOIN users u
            ON u.id = p.user_id
          ORDER BY
            p.created_at DESC
          LIMIT 500
        `);

      return res.json({
        payments:
          result.rows
      });
    } catch (error) {
      console.error(
        '[admin payments error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not load payments.'
      });
    }
  }
);

/* =========================================================
   ADMIN: MANUALLY GRANT PREMIUM
========================================================= */

app.post(
  '/api/admin/users/:id/premium',
  authenticate,
  requireAdmin,
  async (req, res) => {
    try {
      const userId =
        cleanString(
          req.params.id,
          200
        );

      const premium =
        req.body.premium !== false;

      const result =
        await pool.query(
          `
            UPDATE users
            SET
              premium = $2,
              updated_at = NOW()
            WHERE id = $1
            RETURNING
              id,
              email,
              name,
              university,
              country,
              level,
              xp,
              premium,
              is_admin,
              created_at,
              updated_at
          `,
          [
            userId,
            premium
          ]
        );

      if (!result.rows.length) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      await auditLog({
        userId: req.user.id,
        action:
          premium
            ? 'admin_granted_premium'
            : 'admin_removed_premium',
        details: {
          target_user_id:
            userId
        }
      });

      return res.json({
        success: true,
        user:
          publicUser(
            result.rows[0]
          )
      });
    } catch (error) {
      console.error(
        '[admin premium error]',
        error
      );

      return res.status(500).json({
        error:
          'Could not update Premium status.'
      });
    }
  }
);

/* =========================================================
   404 API HANDLER
========================================================= */

app.use(
  '/api',
  (req, res) => {
    return res.status(404).json({
      error:
        'API endpoint not found.'
    });
  }
);

/* =========================================================
   FRONTEND STATIC FILES
========================================================= */

if (
  fs.existsSync(
    PUBLIC_DIR
  )
) {
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

/* =========================================================
   SPA FALLBACK
========================================================= */

app.get(
  /^\/(?!api(?:\/|$)).*/,
  (req, res, next) => {
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

    return next();
  }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (error, req, res, next) => {
    console.error(
      '[express error]',
      error
    );

    if (
      res.headersSent
    ) {
      return next(error);
    }

    const status =
      Number(error.status) >= 400 &&
      Number(error.status) < 600
        ? Number(error.status)
        : 500;

    return res.status(status).json({
      error:
        IS_PRODUCTION
          ? 'Internal server error.'
          : error.message ||
            'Internal server error.'
    });
  }
);

/* =========================================================
   STARTUP
========================================================= */

async function startServer() {
  try {
    console.log(
      '----------------------------------------'
    );

    console.log(
      'DENexpharm v6.0.0'
    );

    console.log(
      `Environment: ${NODE_ENV}`
    );

    console.log(
      `Port: ${PORT}`
    );

    console.log(
      `Premium: ${PREMIUM_PRICE} ${PREMIUM_CURRENCY}`
    );

    console.log(
      `Free question limit: ${PREMIUM_FREE_LIMIT}`
    );

    console.log(
      `Paystack configured: ${Boolean(
        PAYSTACK_SECRET_KEY
      )}`
    );

    console.log(
      `Database configured: ${Boolean(
        DATABASE_URL
      )}`
    );

    console.log(
      '----------------------------------------'
    );

    await initializeDatabase();

    /*
     * Import/update questions after the schema is ready.
     */
    if (DATABASE_URL) {
      await importQuestionsFromFile();
    }

    const server =
      app.listen(
        PORT,
        () => {
          console.log(
            `DENexpharm server running on port ${PORT}`
          );

          console.log(
            `Public app URL: ${
              PUBLIC_APP_URL ||
              `http://localhost:${PORT}`
            }`
          );
        }
      );

    const shutdown =
      async (signal) => {
        console.log(
          `${signal} received. Shutting down...`
        );

        server.close(
          async () => {
            try {
              await pool.end();
            } catch (error) {
              console.error(
                '[database shutdown error]',
                error.message
              );
            }

            process.exit(0);
          }
        );
      };

    process.on(
      'SIGTERM',
      () => shutdown('SIGTERM')
    );

    process.on(
      'SIGINT',
      () => shutdown('SIGINT')
    );
  } catch (error) {
    console.error(
      '========================================'
    );

    console.error(
      'DENexpharm startup failed.'
    );

    console.error(
      error
    );

    console.error(
      '========================================'
    );

    try {
      await pool.end();
    } catch {
      // Ignore database shutdown errors.
    }

    process.exit(1);
  }
}

startServer();
