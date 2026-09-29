'use strict';

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

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const QUESTION_FILE = path.join(ROOT, 'question.json');
const SCHEMA_FILE = path.join(ROOT, 'schema.sql');
const isProduction = process.env.NODE_ENV === 'production';

const JWT_SECRET =
  process.env.JWT_SECRET ||
  (isProduction ? '' : 'DENexPharm-development-secret-change-me');

const MAX_BODY = process.env.MAX_BODY || '1mb';
const FREE_QUESTIONS_PER_SUBJECT = 10;
const PREMIUM_PRICE = Number(process.env.PREMIUM_PRICE || 5000);
const PREMIUM_CURRENCY = String(
  process.env.PREMIUM_CURRENCY || 'NGN'
).trim().toUpperCase();

const SUPPORTED_LEVELS = ['100', '200', '300', '400', '500', '600'];

const frontendOrigin = process.env.FRONTEND_ORIGIN
  ? process.env.FRONTEND_ORIGIN
      .split(',')
      .map(v => v.trim())
      .filter(Boolean)
  : isProduction
    ? false
    : true;

function cleanText(value, fallback = '') {
  return String(value ?? fallback).trim();
}

if (isProduction) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error(
      'STARTUP ERROR: JWT_SECRET must be configured and at least 32 characters long in production.'
    );
    process.exit(1);
  }

  if (!process.env.DATABASE_URL) {
    console.error(
      'STARTUP ERROR: DATABASE_URL must be configured in production.'
    );
    process.exit(1);
  }
}

if (!Number.isFinite(PREMIUM_PRICE) || PREMIUM_PRICE <= 0) {
  console.error(
    'STARTUP ERROR: PREMIUM_PRICE must be a positive number.'
  );
  process.exit(1);
}

if (isProduction) {
  const paystackKey = String(
    process.env.PAYSTACK_SECRET_KEY || ''
  ).trim();

  if (!paystackKey) {
    console.warn(
      'WARNING: PAYSTACK_SECRET_KEY is not configured. Premium payments are disabled until it is added.'
    );
  } else if (!paystackKey.startsWith('sk_live_')) {
    console.warn(
      'WARNING: Production is using a non-live Paystack key. Real Premium payments require sk_live_.'
    );
  }

  const callback = cleanText(process.env.PAYSTACK_CALLBACK_URL);

  if (callback) {
    try {
      const callbackUrl = new URL(callback);
      if (callbackUrl.protocol !== 'https:') {
        console.warn(
          'WARNING: PAYSTACK_CALLBACK_URL should use HTTPS in production.'
        );
      }
    } catch {
      console.warn(
        'WARNING: PAYSTACK_CALLBACK_URL is not a valid URL.'
      );
    }
  } else {
    console.warn(
      'WARNING: PAYSTACK_CALLBACK_URL is not set. Configure the callback URL in Paystack.'
    );
  }
}

const DEFAULT_DB = {
  users: [],
  questions: [],
  scores: [],
  payments: []
};

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(DEFAULT_DB, null, 2),
    'utf8'
  );
}

function loadLocalDb() {
  try {
    const data = JSON.parse(
      fs.readFileSync(DB_FILE, 'utf8')
    );

    for (const key of Object.keys(DEFAULT_DB)) {
      if (!Array.isArray(data[key])) {
        data[key] = [];
      }
    }

    return data;
  } catch (error) {
    console.error(
      'Could not read data/db.json:',
      error.message
    );

    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(DEFAULT_DB, null, 2),
      'utf8'
    );

    return structuredClone(DEFAULT_DB);
  }
}

let db = loadLocalDb();

function saveLocalDb() {
  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2),
    'utf8'
  );
}

const pool = process.env.DATABASE_URL
  ? new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl:
        process.env.DATABASE_SSL === 'false'
          ? false
          : { rejectUnauthorized: false },
      max: Math.max(
        1,
        Number(process.env.DB_POOL_MAX || 10)
      )
    })
  : null;

async function sql(query, params = []) {
  if (!pool) return [];

  const result = await pool.query(query, params);
  return result.rows;
}

function generateId() {
  return crypto.randomUUID();
}

function canonical(value) {
  return cleanText(value).toLowerCase();
}

function validLevel(level) {
  return SUPPORTED_LEVELS.includes(String(level));
}

function safeUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    university: user.university || '',
    country: user.country || '',
    level: user.level || '200',
    xp: Number(user.xp || 0),
    premium: Boolean(user.premium),
    admin: Boolean(user.admin)
  };
}

function signUser(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      admin: Boolean(user.admin)
    },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}

function getTokenFromRequest(req) {
  const header = req.get('authorization') || '';

  return header.startsWith('Bearer ')
    ? header.slice(7).trim()
    : null;
}

function authenticate(req) {
  const token = getTokenFromRequest(req);

  if (!token) return null;

  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

function requireAuth(req, res, next) {
  const auth = authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error: 'Sign in required'
    });
  }

  req.auth = auth;
  next();
}

async function requireAdmin(req, res, next) {
  const auth = authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error: 'Sign in required'
    });
  }

  try {
    const user = await getUserById(auth.id);

    if (!user || !user.admin) {
      return res.status(403).json({
        error: 'Admin access required'
      });
    }

    req.auth = auth;
    req.currentUser = user;
    next();
  } catch (error) {
    next(error);
  }
}

function normalizeQuestion(question, fallbackId) {
  if (!question || typeof question !== 'object') {
    return null;
  }

  const numericId = Number(
    question.id ?? fallbackId
  );

  const country = cleanText(
    question.country || 'Nigeria'
  );

  const level = cleanText(
    question.level || '200'
  );

  const subject = cleanText(question.subject);
  const topic = cleanText(
    question.topic || 'General'
  );

  const questionText = cleanText(
    question.question
  );

  const options = Array.isArray(question.options)
    ? question.options.map(v => String(v))
    : [];

  const answerIndex = Number(
    question.answer_index
  );

  if (
    !Number.isInteger(numericId) ||
    numericId < 1
  ) {
    return null;
  }

  if (
    !country ||
    !level ||
    !subject ||
    !topic ||
    !questionText
  ) {
    return null;
  }

  if (options.length !== 4) {
    return null;
  }

  if (
    !Number.isInteger(answerIndex) ||
    answerIndex < 0 ||
    answerIndex > 3
  ) {
    return null;
  }

  return {
    id: numericId,
    country,
    level,
    subject,
    topic,
    question: questionText,
    options,
    answer_index: answerIndex,
    explanation: cleanText(
      question.explanation
    ),
    active: question.active !== false
  };
}

function loadQuestionBank() {
  if (!fs.existsSync(QUESTION_FILE)) {
    throw new Error(
      'question.json was not found. Place question.json beside server.js.'
    );
  }

  let parsed;

  try {
    parsed = JSON.parse(
      fs.readFileSync(
        QUESTION_FILE,
        'utf8'
      )
    );
  } catch (error) {
    throw new Error(
      `Could not parse question.json: ${error.message}`
    );
  }

  if (!Array.isArray(parsed)) {
    throw new Error(
      'question.json must contain a JSON array.'
    );
  }

  const seenIds = new Set();
  const validQuestions = [];

  for (
    let index = 0;
    index < parsed.length;
    index++
  ) {
    const normalized = normalizeQuestion(
      parsed[index],
      index + 1
    );

    if (!normalized) {
      console.warn(
        `Skipping invalid question at question.json index ${index}.`
      );
      continue;
    }

    if (seenIds.has(normalized.id)) {
      console.warn(
        `Skipping duplicate question ID ${normalized.id}.`
      );
      continue;
    }

    seenIds.add(normalized.id);
    validQuestions.push(normalized);
  }

  validQuestions.sort(
    (a, b) => a.id - b.id
  );

  console.log(
    `Loaded ${validQuestions.length} valid questions from question.json.`
  );

  return validQuestions;
}

let questionBank = [];

function normalizeStoredQuestion(
  question,
  fallbackId
) {
  return normalizeQuestion(
    question,
    fallbackId
  );
}

function getLocalQuestions() {
  return db.questions
    .map((q, i) =>
      normalizeStoredQuestion(q, i + 1)
    )
    .filter(
      q => q && q.active !== false
    );
}

function shuffle(array) {
  const result = [...array];

  for (
    let i = result.length - 1;
    i > 0;
    i--
  ) {
    const j = crypto.randomInt(i + 1);

    [result[i], result[j]] = [
      result[j],
      result[i]
    ];
  }

  return result;
}

function filterQuestions(
  questions,
  {
    country,
    level,
    subject,
    topic
  } = {}
) {
  const c = country
    ? canonical(country)
    : null;

  const l = level
    ? canonical(level)
    : null;

  const s = subject
    ? canonical(subject)
    : null;

  const t = topic
    ? canonical(topic)
    : null;

  return questions.filter(q =>
    (!c || canonical(q.country) === c) &&
    (!l || canonical(q.level) === l) &&
    (!s || canonical(q.subject) === s) &&
    (!t || canonical(q.topic) === t)
  );
}

function limitFreeQuestions(questions) {
  const groups = new Map();

  for (const question of questions) {
    const key = [
      canonical(question.country),
      canonical(question.level),
      canonical(question.subject)
    ].join('|');

    if (!groups.has(key)) {
      groups.set(key, []);
    }

    groups.get(key).push(question);
  }

  const result = [];

  for (const group of groups.values()) {
    result.push(
      ...group
        .sort((a, b) => a.id - b.id)
        .slice(
          0,
          FREE_QUESTIONS_PER_SUBJECT
        )
    );
  }

  return result.sort(
    (a, b) => a.id - b.id
  );
}

async function getAllQuestions() {
  if (pool) {
    const rows = await sql(`
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
        active
      FROM questions
      WHERE active = true
      ORDER BY id ASC
    `);

    return rows
      .map(row =>
        normalizeQuestion(
          row,
          row.id
        )
      )
      .filter(Boolean);
  }

  const merged = new Map();

  for (const q of questionBank) {
    if (q.active !== false) {
      merged.set(String(q.id), q);
    }
  }

  for (const q of getLocalQuestions()) {
    merged.set(String(q.id), q);
  }

  return Array.from(
    merged.values()
  ).filter(
    q => q.active !== false
  );
}

async function getQuestionById(
  questionId
) {
  if (pool) {
    const rows = await sql(
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
        active
      FROM questions
      WHERE id = $1
        AND active = true
      LIMIT 1
      `,
      [questionId]
    );

    return rows.length
      ? normalizeQuestion(
          rows[0],
          rows[0].id
        )
      : null;
  }

  return (
    questionBank.find(
      q =>
        String(q.id) ===
          String(questionId) &&
        q.active !== false
    ) || null
  );
}

async function getFilterData() {
  const questions =
    await getAllQuestions();

  const countries = [
    ...new Set(
      questions.map(q => q.country)
    )
  ].sort();

  const levels = [
    ...new Set(
      questions.map(q => q.level)
    )
  ].sort(
    (a, b) =>
      Number(a) - Number(b)
  );

  const subjects = [
    ...new Set(
      questions.map(q => q.subject)
    )
  ].sort();

  const topics = [
    ...new Set(
      questions.map(q => q.topic)
    )
  ].sort();

  return {
    countries,
    levels,
    subjects,
    topics
  };
}

async function countQuestions() {
  if (pool) {
    const rows = await sql(
      'SELECT COUNT(*)::int AS count FROM questions WHERE active = true'
    );

    return Number(
      rows[0]?.count || 0
    );
  }

  return questionBank.length;
}

async function getSubjects() {
  const questions =
    await getAllQuestions();

  const map = new Map();

  for (const q of questions) {
    map.set(
      q.subject,
      (map.get(q.subject) || 0) + 1
    );
  }

  return Array.from(
    map.entries()
  )
    .sort(([a], [b]) =>
      a.localeCompare(b)
    )
    .map(
      ([subject, count]) => ({
        subject,
        name: subject,
        count,
        total_questions: count,
        free_questions:
          Math.min(
            count,
            FREE_QUESTIONS_PER_SUBJECT
          )
      })
    );
}

async function getUserById(id) {
  if (pool) {
    const rows = await sql(
      'SELECT * FROM users WHERE id = $1 LIMIT 1',
      [id]
    );

    return rows[0] || null;
  }

  return (
    db.users.find(
      user =>
        String(user.id) ===
        String(id)
    ) || null
  );
}

async function getUserByEmail(email) {
  const normalized =
    canonical(email);

  if (pool) {
    const rows = await sql(
      'SELECT * FROM users WHERE LOWER(email) = $1 LIMIT 1',
      [normalized]
    );

    return rows[0] || null;
  }

  return (
    db.users.find(
      user =>
        canonical(user.email) ===
        normalized
    ) || null
  );
}

async function importQuestionsToDatabase() {
  if (!pool) {
    console.log(
      `Local mode: using ${questionBank.length} questions directly from question.json.`
    );
    return;
  }

  for (const q of questionBank) {
    await pool.query(
      `
      INSERT INTO questions (
        id,
        country,
        level,
        subject,
        topic,
        question,
        options,
        answer_index,
        explanation,
        active
      )
      VALUES (
        $1,$2,$3,$4,$5,$6,
        $7::jsonb,$8,$9,$10
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
        q.id,
        q.country,
        q.level,
        q.subject,
        q.topic,
        q.question,
        JSON.stringify(q.options),
        q.answer_index,
        q.explanation,
        q.active
      ]
    );
  }

  const sequenceResult =
    await pool.query(
      `
      SELECT pg_get_serial_sequence(
        'questions',
        'id'
      ) AS sequence_name
      `
    );

  const sequenceName =
    sequenceResult.rows[0]
      ?.sequence_name;

  if (sequenceName) {
    const maxResult =
      await pool.query(
        `
        SELECT COALESCE(
          MAX(id),
          0
        ) AS max_id
        FROM questions
        `
      );

    const nextId =
      Number(
        maxResult.rows[0]
          ?.max_id || 0
      ) + 1;

    await pool.query(
      'SELECT setval($1::regclass,$2,false)',
      [
        sequenceName,
        nextId
      ]
    );
  }

  console.log(
    `PostgreSQL question synchronization complete. ${questionBank.length} records processed.`
  );
}

/*
========================================================
CRITICAL DATABASE COMPATIBILITY FIX
========================================================

The deployment error was:

audit_logs.user_id = TEXT
users.id          = INTEGER

PostgreSQL does not allow a foreign key between those
different data types.

This function repairs an existing old audit_logs table
before schema.sql is executed.
*/

async function repairAuditLogUserIdType() {
  if (!pool) return;

  const usersColumn =
    await pool.query(`
      SELECT
        data_type,
        udt_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'users'
        AND column_name = 'id'
      LIMIT 1
    `);

  const auditTable =
    await pool.query(`
      SELECT EXISTS (
        SELECT 1
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_name = 'audit_logs'
      ) AS exists
    `);

  if (
    !auditTable.rows[0]?.exists ||
    !usersColumn.rows[0]
  ) {
    return;
  }

  const auditColumn =
    await pool.query(`
      SELECT
        data_type,
        udt_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name = 'audit_logs'
        AND column_name = 'user_id'
      LIMIT 1
    `);

  if (!auditColumn.rows[0]) {
    return;
  }

  const userType =
    usersColumn.rows[0].data_type;

  const auditType =
    auditColumn.rows[0].data_type;

  console.log(
    `Database ID types before schema: users.id=${userType}, audit_logs.user_id=${auditType}`
  );

  if (
    userType === 'integer' &&
    auditType === 'text'
  ) {
    console.log(
      'Repairing audit_logs.user_id TEXT -> INTEGER before schema initialization...'
    );

    await pool.query(`
      ALTER TABLE audit_logs
      DROP CONSTRAINT IF EXISTS
      audit_logs_user_id_fkey
    `);

    await pool.query(`
      ALTER TABLE audit_logs
      ALTER COLUMN user_id TYPE INTEGER
      USING (
        CASE
          WHEN user_id ~ '^[0-9]+$'
          THEN user_id::INTEGER
          ELSE NULL
        END
      )
    `);

    await pool.query(`
      ALTER TABLE audit_logs
      ADD CONSTRAINT
      audit_logs_user_id_fkey
      FOREIGN KEY (user_id)
      REFERENCES users(id)
      ON DELETE SET NULL
    `);

    console.log(
      'audit_logs.user_id repaired successfully.'
    );
  }
}

/*
If schema.sql itself contains an old audit_logs
definition with TEXT user_id, change only that
definition before PostgreSQL executes it.
*/
function makeSchemaCompatible(schema) {
  return schema.replace(
    /(CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+audit_logs\s*\([\s\S]*?\buser_id\s+)TEXT\b/ig,
    '$1INTEGER'
  );
}

async function initDb() {
  if (!pool) {
    console.log(
      'DATABASE_URL not configured. Using local JSON fallback.'
    );
    return;
  }

  if (!fs.existsSync(SCHEMA_FILE)) {
    throw new Error(
      'schema.sql was not found in the project root.'
    );
  }

  const schema =
    fs.readFileSync(
      SCHEMA_FILE,
      'utf8'
    );

  if (!schema.trim()) {
    throw new Error(
      'schema.sql is empty.'
    );
  }

  /*
  FIRST:
  Repair an already-existing old table.
  */
  await repairAuditLogUserIdType();

  /*
  SECOND:
  Make the schema itself compatible before
  sending it to PostgreSQL.
  */
  const compatibleSchema =
    makeSchemaCompatible(schema);

  await pool.query(
    compatibleSchema
  );

  /*
  THIRD:
  Verify/repair again in case the schema
  created audit_logs during initialization.
  */
  await repairAuditLogUserIdType();

  /*
  FOURTH:
  Import all 10,000 questions.
  */
  await importQuestionsToDatabase();

  /*
  Optional admin account.
  */
  const adminEmail =
    cleanText(
      process.env.ADMIN_EMAIL
    ).toLowerCase();

  const adminPassword =
    String(
      process.env.ADMIN_PASSWORD || ''
    );

  if (
    adminEmail &&
    adminPassword &&
    adminEmail !== 'admin@example.com'
  ) {
    const existing =
      await sql(
        `
        SELECT id
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [adminEmail]
      );

    if (!existing.length) {
      const passwordHash =
        await bcrypt.hash(
          adminPassword,
          12
        );

      await sql(
        `
        INSERT INTO users (
          email,
          password_hash,
          name,
          admin
        )
        VALUES (
          $1,$2,$3,true
        )
        `,
        [
          adminEmail,
          passwordHash,
          'DENexPharm Admin'
        ]
      );

      console.log(
        `Admin account created: ${adminEmail}`
      );
    } else {
      await sql(
        `
        UPDATE users
        SET admin = true
        WHERE email = $1
        `,
        [adminEmail]
      );

      console.log(
        `Admin privileges confirmed: ${adminEmail}`
      );
    }
  }
}

app.disable(
  'x-powered-by'
);

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(
  cors({
    origin: frontendOrigin,
    credentials: true
  })
);

app.use(
  express.json({
    limit: MAX_BODY,
    verify: (
      req,
      res,
      buffer
    ) => {
      req.rawBody = buffer;
    }
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: MAX_BODY
  })
);

app.use(
  rateLimit({
    windowMs:
      15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-8',
    legacyHeaders: false
  })
);

const authLimiter =
  rateLimit({
    windowMs:
      15 * 60 * 1000,
    limit: 20,
    standardHeaders: 'draft-8',
    legacyHeaders: false
  });

app.get(
  '/api/health',
  async (req, res) => {
    try {
      res.json({
        ok: true,
        version: '6.1.0',
        database: Boolean(pool),
        payments:
          paystackConfigured(),
        paystackMode:
          paystackConfigured()
            ? (
                paystackIsLive()
                  ? 'live'
                  : 'non-live'
              )
            : 'not-configured',
        questions:
          await countQuestions(),
        freeQuestionsPerSubject:
          FREE_QUESTIONS_PER_SUBJECT,
        premiumPrice:
          PREMIUM_PRICE,
        premiumCurrency:
          PREMIUM_CURRENCY
      });
    } catch {
      res.status(503).json({
        ok: false,
        database: Boolean(pool),
        error:
          'Health check failed.'
      });
    }
  }
);

app.get(
  '/api',
  (req, res) => {
    res.json({
      name: 'DENexPharm',
      version: '6.1.0',
      status: 'online'
    });
  }
);

app.post(
  '/api/auth/register',
  authLimiter,
  async (
    req,
    res,
    next
  ) => {
    try {
      const {
        name,
        email,
        password,
        university = '',
        country = '',
        level = '200'
      } = req.body || {};

      if (
        !cleanText(name) ||
        !cleanText(email) ||
        !password
      ) {
        return res.status(400).json({
          error:
            'Name, email and password are required.'
        });
      }

      if (
        String(password).length < 6
      ) {
        return res.status(400).json({
          error:
            'Password must be at least 6 characters.'
        });
      }

      const normalizedEmail =
        cleanText(email)
          .toLowerCase();

      if (
        await getUserByEmail(
          normalizedEmail
        )
      ) {
        return res.status(409).json({
          error:
            'Email already registered.'
        });
      }

      const cleanLevel =
        cleanText(
          level,
          '200'
        );

      if (
        !validLevel(cleanLevel)
      ) {
        return res.status(400).json({
          error:
            'Invalid level.'
        });
      }

      const passwordHash =
        await bcrypt.hash(
          String(password),
          12
        );

      if (pool) {
        const rows =
          await sql(
            `
            INSERT INTO users (
              email,
              password_hash,
              name,
              university,
              country,
              level
            )
            VALUES (
              $1,$2,$3,$4,$5,$6
            )
            RETURNING *
            `,
            [
              normalizedEmail,
              passwordHash,
              cleanText(name),
              cleanText(university),
              cleanText(country),
              cleanLevel
            ]
          );

        return res.status(201).json({
          token:
            signUser(rows[0]),
          user:
            safeUser(rows[0])
        });
      }

      const user = {
        id: generateId(),
        email: normalizedEmail,
        password_hash:
          passwordHash,
        name: cleanText(name),
        university:
          cleanText(university),
        country:
          cleanText(country),
        level: cleanLevel,
        xp: 0,
        premium: false,
        admin: false,
        created_at:
          new Date().toISOString()
      };

      db.users.push(user);
      saveLocalDb();

      return res.status(201).json({
        token:
          signUser(user),
        user:
          safeUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/auth/login',
  authLimiter,
  async (
    req,
    res,
    next
  ) => {
    try {
      const {
        email,
        password
      } = req.body || {};

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            'Email and password are required.'
        });
      }

      const user =
        await getUserByEmail(
          email
        );

      if (!user) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      const valid =
        await bcrypt.compare(
          String(password),
          String(
            user.password_hash || ''
          )
        );

      if (!valid) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      res.json({
        token:
          signUser(user),
        user:
          safeUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/auth/me',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const user =
        await getUserById(
          req.auth.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      res.json({
        user:
          safeUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/auth/profile',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const user =
        await getUserById(
          req.auth.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      res.json({
        user:
          safeUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.put(
  '/api/auth/profile',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const {
        name,
        university,
        country,
        level
      } = req.body || {};

      if (
        level !== undefined &&
        !validLevel(level)
      ) {
        return res.status(400).json({
          error:
            'Invalid level.'
        });
      }

      if (pool) {
        const rows =
          await sql(
            `
            UPDATE users
            SET
              name =
                COALESCE($1,name),
              university =
                COALESCE($2,university),
              country =
                COALESCE($3,country),
              level =
                COALESCE($4,level)
            WHERE id = $5
            RETURNING *
            `,
            [
              name !== undefined
                ? cleanText(name)
                : null,
              university !== undefined
                ? cleanText(university)
                : null,
              country !== undefined
                ? cleanText(country)
                : null,
              level !== undefined
                ? cleanText(level)
                : null,
              req.auth.id
            ]
          );

        if (!rows.length) {
          return res.status(404).json({
            error:
              'User not found.'
          });
        }

        return res.json({
          user:
            safeUser(rows[0])
        });
      }

      const user =
        db.users.find(
          u =>
            String(u.id) ===
            String(req.auth.id)
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      if (name !== undefined)
        user.name =
          cleanText(name);

      if (
        university !== undefined
      )
        user.university =
          cleanText(university);

      if (
        country !== undefined
      )
        user.country =
          cleanText(country);

      if (level !== undefined)
        user.level =
          cleanText(level);

      saveLocalDb();

      res.json({
        user:
          safeUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/subjects',
  async (
    req,
    res,
    next
  ) => {
    try {
      res.json({
        subjects:
          await getSubjects()
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/questions/filters',
  async (
    req,
    res,
    next
  ) => {
    try {
      res.json(
        await getFilterData()
      );
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/questions',
  async (
    req,
    res,
    next
  ) => {
    try {
      const {
        country,
        level,
        subject,
        topic,
        limit,
        mode
      } = req.query;

      const user =
        req.get('authorization')
          ? await getUserById(
              authenticate(req)?.id
            )
          : null;

      const all =
        await getAllQuestions();

      let filtered =
        filterQuestions(
          all,
          {
            country,
            level,
            subject,
            topic
          }
        );

      const isPremium =
        Boolean(user?.premium);

      if (!isPremium) {
        filtered =
          limitFreeQuestions(
            filtered
          );
      }

      filtered = shuffle(
        filtered
      );

      let max = Number(
        limit || 20
      );

      if (
        !Number.isFinite(max) ||
        max < 1
      ) {
        max = 20;
      }

      max = Math.min(
        Math.floor(max),
        isPremium ? 100 : FREE_QUESTIONS_PER_SUBJECT
      );

      const result =
        filtered.slice(
          0,
          max
        );

      res.json({
        questions: result,
        count: result.length,
        premium: isPremium,
        total_available:
          filtered.length
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/questions/:id',
  async (
    req,
    res,
    next
  ) => {
    try {
      const question =
        await getQuestionById(
          req.params.id
        );

      if (!question) {
        return res.status(404).json({
          error:
            'Question not found.'
        });
      }

      const auth =
        authenticate(req);

      const user =
        auth
          ? await getUserById(
              auth.id
            )
          : null;

      if (
        !user?.premium
      ) {
        const all =
          await getAllQuestions();

        const free =
          limitFreeQuestions(
            filterQuestions(
              all,
              {
                country:
                  question.country,
                level:
                  question.level,
                subject:
                  question.subject
              }
            )
          );

        const allowed =
          free.some(
            q =>
              String(q.id) ===
              String(question.id)
          );

        if (!allowed) {
          return res.status(403).json({
            error:
              'Premium access required for this question.'
          });
        }
      }

      res.json({
        question
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/access',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const user =
        await getUserById(
          req.auth.id
        );

      res.json({
        premium:
          Boolean(user?.premium),
        freeQuestionsPerSubject:
          FREE_QUESTIONS_PER_SUBJECT
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/scores',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const {
        score = 0,
        total = 0,
        subject = '',
        mode = 'practice',
        country = '',
        level = ''
      } = req.body || {};

      const cleanScore =
        Math.max(
          0,
          Number(score) || 0
        );

      const cleanTotal =
        Math.max(
          0,
          Number(total) || 0
        );

      const xp =
        cleanScore * 10;

      if (pool) {
        await sql(
          `
          INSERT INTO scores (
            user_id,
            score,
            total,
            subject,
            mode,
            country,
            level,
            xp
          )
          VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8
          )
          `,
          [
            req.auth.id,
            cleanScore,
            cleanTotal,
            cleanText(subject),
            cleanText(mode),
            cleanText(country),
            cleanText(level),
            xp
          ]
        );

        await sql(
          `
          UPDATE users
          SET xp =
            COALESCE(xp,0) + $1
          WHERE id = $2
          `,
          [
            xp,
            req.auth.id
          ]
        );
      } else {
        db.scores.push({
          id:
            generateId(),
          user_id:
            req.auth.id,
          score:
            cleanScore,
          total:
            cleanTotal,
          subject:
            cleanText(subject),
          mode:
            cleanText(mode),
          country:
            cleanText(country),
          level:
            cleanText(level),
          xp,
          created_at:
            new Date().toISOString()
        });

        const user =
          db.users.find(
            u =>
              String(u.id) ===
              String(req.auth.id)
          );

        if (user) {
          user.xp =
            Number(user.xp || 0) +
            xp;
        }

        saveLocalDb();
      }

      res.status(201).json({
        success: true,
        xp
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/leaderboard',
  async (
    req,
    res,
    next
  ) => {
    try {
      if (pool) {
        const rows =
          await sql(
            `
            SELECT
              u.id,
              u.name,
              u.country,
              u.level,
              COALESCE(
                u.xp,
                0
              ) AS xp
            FROM users u
            ORDER BY
              COALESCE(u.xp,0)
              DESC,
              u.id ASC
            LIMIT 100
            `
          );

        return res.json({
          leaderboard:
            rows.map(
              (row, index) => ({
                rank:
                  index + 1,
                id:
                  row.id,
                name:
                  row.name,
                country:
                  row.country || '',
                level:
                  row.level || '',
                xp:
                  Number(row.xp || 0)
              })
            )
        });
      }

      const rows =
        [...db.users]
          .sort(
            (a, b) =>
              Number(b.xp || 0) -
              Number(a.xp || 0)
          )
          .slice(0, 100)
          .map(
            (row, index) => ({
              rank:
                index + 1,
              id:
                row.id,
              name:
                row.name,
              country:
                row.country || '',
              level:
                row.level || '',
              xp:
                Number(row.xp || 0)
            })
          );

      res.json({
        leaderboard:
          rows
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/admin/questions',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const questions =
        await getAllQuestions();

      res.json({
        questions
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/admin/questions',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const question =
        normalizeQuestion(
          req.body,
          Date.now()
        );

      if (!question) {
        return res.status(400).json({
          error:
            'Invalid question data.'
        });
      }

      if (pool) {
        const rows =
          await sql(
            `
            INSERT INTO questions (
              id,
              country,
              level,
              subject,
              topic,
              question,
              options,
              answer_index,
              explanation,
              active
            )
            VALUES (
              $1,$2,$3,$4,$5,$6,
              $7::jsonb,$8,$9,$10
            )
            RETURNING *
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

        return res.status(201).json({
          question:
            rows[0]
        });
      }

      db.questions.push(
        question
      );

      saveLocalDb();

      res.status(201).json({
        question
      });
    } catch (error) {
      next(error);
    }
  }
);

app.put(
  '/api/admin/questions/:id',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const old =
        await getQuestionById(
          req.params.id
        );

      if (!old) {
        return res.status(404).json({
          error:
            'Question not found.'
        });
      }

      const merged =
        normalizeQuestion(
          {
            ...old,
            ...req.body,
            id:
              old.id
          },
          old.id
        );

      if (!merged) {
        return res.status(400).json({
          error:
            'Invalid question data.'
        });
      }

      if (pool) {
        const rows =
          await sql(
            `
            UPDATE questions
            SET
              country=$1,
              level=$2,
              subject=$3,
              topic=$4,
              question=$5,
              options=$6::jsonb,
              answer_index=$7,
              explanation=$8,
              active=$9,
              updated_at=NOW()
            WHERE id=$10
            RETURNING *
            `,
            [
              merged.country,
              merged.level,
              merged.subject,
              merged.topic,
              merged.question,
              JSON.stringify(
                merged.options
              ),
              merged.answer_index,
              merged.explanation,
              merged.active,
              merged.id
            ]
          );

        return res.json({
          question:
            rows[0]
        });
      }

      const index =
        db.questions.findIndex(
          q =>
            String(q.id) ===
            String(merged.id)
        );

      if (index === -1) {
        return res.status(404).json({
          error:
            'Question not found.'
        });
      }

      db.questions[index] =
        merged;

      saveLocalDb();

      res.json({
        question:
          merged
      });
    } catch (error) {
      next(error);
    }
  }
);

function paystackConfigured() {
  return Boolean(
    cleanText(
      process.env.PAYSTACK_SECRET_KEY
    )
  );
}

function paystackIsLive() {
  return String(
    process.env.PAYSTACK_SECRET_KEY || ''
  ).startsWith('sk_live_');
}

function makePaystackReference() {
  return (
    'DENEX-' +
    Date.now() +
    '-' +
    crypto
      .randomBytes(5)
      .toString('hex')
      .toUpperCase()
  );
}

function paymentAmountInMinorUnits(
  amount
) {
  return Math.round(
    Number(amount) * 100
  );
}

async function findPaymentByReference(
  reference
) {
  if (pool) {
    const rows =
      await sql(
        `
        SELECT *
        FROM payments
        WHERE reference=$1
        LIMIT 1
        `,
        [reference]
      );

    return rows[0] || null;
  }

  return (
    db.payments.find(
      p =>
        String(p.reference) ===
        String(reference)
    ) || null
  );
}

async function initializePaystackTransaction(
  user,
  reference
) {
  if (!paystackConfigured()) {
    throw new Error(
      'Paystack is not configured.'
    );
  }

  if (
    isProduction &&
    !paystackIsLive()
  ) {
    throw new Error(
      'Production payments require a Paystack live secret key.'
    );
  }

  const callbackUrl =
    cleanText(
      process.env.PAYSTACK_CALLBACK_URL
    ) ||
    (
      cleanText(
        process.env.PUBLIC_APP_URL
      ) +
      '/api/payments/callback'
    );

  const response =
    await fetch(
      'https://api.paystack.co/transaction/initialize',
      {
        method: 'POST',
        headers: {
          Authorization:
            `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          'Content-Type':
            'application/json'
        },
        body:
          JSON.stringify({
            email:
              user.email,
            amount:
              paymentAmountInMinorUnits(
                PREMIUM_PRICE
              ),
            currency:
              PREMIUM_CURRENCY,
            reference,
            callback_url:
              callbackUrl,
            metadata: {
              user_id:
                String(user.id),
              product:
                'DENexPharm Premium'
            }
          })
      }
    );

  let data;

  try {
    data =
      await response.json();
  } catch {
    throw new Error(
      'Invalid response from Paystack.'
    );
  }

  if (
    !response.ok ||
    !data?.status ||
    !data?.data
  ) {
    throw new Error(
      data?.message ||
      'Could not initialize Paystack transaction.'
    );
  }

  return data.data;
}

app.post(
  '/api/payments/initialize',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      if (
        !paystackConfigured()
      ) {
        return res.status(503).json({
          error:
            'Premium payments are not configured yet.'
        });
      }

      const user =
        await getUserById(
          req.auth.id
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      if (user.premium) {
        return res.json({
          already_paid: true,
          premium: true
        });
      }

      const amount =
        PREMIUM_PRICE;

      const currency =
        PREMIUM_CURRENCY;

      const reference =
        makePaystackReference();

      if (pool) {
        await sql(
          `
          INSERT INTO payments (
            reference,
            user_id,
            amount,
            currency,
            status,
            provider_reference
          )
          VALUES (
            $1,$2,$3,$4,$5,$6
          )
          `,
          [
            reference,
            req.auth.id,
            amount,
            currency,
            'initialized',
            reference
          ]
        );
      } else {
        db.payments.push({
          reference,
          user_id:
            req.auth.id,
          amount,
          currency,
          status:
            'initialized',
          provider_reference:
            reference,
          created_at:
            new Date().toISOString()
        });

        saveLocalDb();
      }

      try {
        const paystackData =
          await initializePaystackTransaction(
            user,
            reference
          );

        const providerReference =
          String(
            paystackData.reference ||
            reference
          );

        if (
          providerReference !==
          reference
        ) {
          throw new Error(
            'Paystack returned a mismatched transaction reference.'
          );
        }

        if (pool) {
          await sql(
            `
            UPDATE payments
            SET
              provider_reference=$1,
              status=$2
            WHERE reference=$3
            `,
            [
              providerReference,
              'pending',
              reference
            ]
          );
        } else {
          const stored =
            db.payments.find(
              p =>
                String(
                  p.reference
                ) === reference
            );

          if (stored) {
            stored.provider_reference =
              providerReference;
            stored.status =
              'pending';
          }

          saveLocalDb();
        }

        return res.json({
          authorization_url:
            paystackData.authorization_url,
          reference:
            providerReference
        });
      } catch (error) {
        if (pool) {
          await sql(
            `
            UPDATE payments
            SET status=$1
            WHERE reference=$2
            `,
            [
              'failed',
              reference
            ]
          );
        } else {
          const stored =
            db.payments.find(
              p =>
                String(
                  p.reference
                ) === reference
            );

          if (stored) {
            stored.status =
              'failed';
          }

          saveLocalDb();
        }

        throw error;
      }
    } catch (error) {
      next(error);
    }
  }
);

async function verifyPaystack(
  reference
) {
  const cleanReference =
    cleanText(reference);

  if (!cleanReference) {
    throw new Error(
      'Missing Paystack reference.'
    );
  }

  if (!paystackConfigured()) {
    throw new Error(
      'Paystack is not configured.'
    );
  }

  const response =
    await fetch(
      'https://api.paystack.co/transaction/verify/' +
        encodeURIComponent(
          cleanReference
        ),
      {
        headers: {
          Authorization:
            `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
        }
      }
    );

  let data;

  try {
    data =
      await response.json();
  } catch {
    throw new Error(
      'Invalid response from Paystack verification.'
    );
  }

  if (
    !response.ok ||
    !data?.status ||
    !data?.data
  ) {
    throw new Error(
      data?.message ||
      'Paystack verification failed.'
    );
  }

  return data.data;
}

async function markPremium(
  reference,
  paymentData
) {
  const cleanReference =
    cleanText(reference);

  if (
    !cleanReference ||
    !paymentData ||
    paymentData.status !==
      'success'
  ) {
    return false;
  }

  const payment =
    await findPaymentByReference(
      cleanReference
    );

  if (!payment) {
    return false;
  }

  const metadataUserId =
    paymentData.metadata?.user_id !=
    null
      ? String(
          paymentData.metadata.user_id
        )
      : '';

  const storedUserId =
    String(payment.user_id);

  if (
    !metadataUserId ||
    metadataUserId !==
      storedUserId
  ) {
    return false;
  }

  const providerReference =
    String(
      paymentData.reference ||
        cleanReference
    );

  if (
    providerReference !==
    cleanReference
  ) {
    return false;
  }

  const paidMinor =
    Number(
      paymentData.amount
    );

  const expectedMinor =
    paymentAmountInMinorUnits(
      PREMIUM_PRICE
    );

  const paidCurrency =
    String(
      paymentData.currency ||
        ''
    ).toUpperCase();

  if (
    !Number.isSafeInteger(
      paidMinor
    ) ||
    paidMinor !==
      expectedMinor
  ) {
    return false;
  }

  if (
    paidCurrency !==
    PREMIUM_CURRENCY
  ) {
    return false;
  }

  const storedAmount =
    Number(payment.amount);

  const storedCurrency =
    String(
      payment.currency || ''
    ).toUpperCase();

  if (
    storedAmount !==
      PREMIUM_PRICE ||
    storedCurrency !==
      PREMIUM_CURRENCY
  ) {
    return false;
  }

  const providerId =
    String(
      paymentData.id ||
        cleanReference
    );

  if (pool) {
    const users =
      await sql(
        `
        SELECT id,premium
        FROM users
        WHERE id=$1
        LIMIT 1
        `,
        [storedUserId]
      );

    if (!users.length) {
      return false;
    }

    if (
      String(
        payment.status
      ).toLowerCase() ===
        'success' &&
      users[0].premium
    ) {
      return true;
    }

    await sql(
      `
      WITH activated_user AS (
        UPDATE users
        SET premium=true
        WHERE id=$1
        RETURNING id
      )
      UPDATE payments
      SET
        status=$2,
        provider_reference=$3
      WHERE reference=$4
        AND user_id=$1
      `,
      [
        storedUserId,
        'success',
        providerId,
        cleanReference
      ]
    );

    return true;
  }

  const user =
    db.users.find(
      u =>
        String(u.id) ===
        storedUserId
    );

  if (!user) {
    return false;
  }

  const localPayment =
    db.payments.find(
      p =>
        String(
          p.reference
        ) === cleanReference
    );

  if (!localPayment) {
    return false;
  }

  if (
    String(
      localPayment.status
    ).toLowerCase() ===
      'success' &&
    user.premium
  ) {
    return true;
  }

  localPayment.status =
    'success';

  localPayment.provider_reference =
    providerId;

  localPayment.paid_at =
    new Date().toISOString();

  user.premium = true;

  saveLocalDb();

  return true;
}

app.get(
  '/api/payments/callback',
  async (
    req,
    res
  ) => {
    try {
      const reference =
        cleanText(
          req.query.reference
        );

      if (!reference) {
        return res.redirect(
          '/?payment=missing'
        );
      }

      const paymentData =
        await verifyPaystack(
          reference
        );

      const success =
        await markPremium(
          reference,
          paymentData
        );

      return res.redirect(
        success
          ? '/?payment=success'
          : '/?payment=failed'
      );
    } catch (error) {
      console.error(
        'Paystack callback error:',
        error.message
      );

      return res.redirect(
        '/?payment=failed'
      );
    }
  }
);

app.post(
  '/api/payments/webhook',
  async (
    req,
    res
  ) => {
    try {
      if (
        !paystackConfigured()
      ) {
        return res.sendStatus(
          204
        );
      }

      const signature =
        req.get(
          'x-paystack-signature'
        ) || '';

      const rawBody =
        req.rawBody ||
        Buffer.from(
          JSON.stringify(
            req.body || {}
          )
        );

      const expectedSignature =
        crypto
          .createHmac(
            'sha512',
            process.env
              .PAYSTACK_SECRET_KEY
          )
          .update(rawBody)
          .digest('hex');

      const received =
        Buffer.from(
          signature,
          'utf8'
        );

      const expected =
        Buffer.from(
          expectedSignature,
          'utf8'
        );

      if (
        received.length !==
          expected.length ||
        !crypto.timingSafeEqual(
          received,
          expected
        )
      ) {
        return res.sendStatus(
          401
        );
      }

      const event =
        req.body &&
        typeof req.body ===
          'object'
          ? req.body
          : JSON.parse(
              rawBody.toString(
                'utf8'
              )
            );

      if (
        event.event ===
          'charge.success' &&
        event.data?.reference
      ) {
        const verified =
          await verifyPaystack(
            String(
              event.data.reference
            )
          );

        const success =
          await markPremium(
            String(
              event.data.reference
            ),
            verified
          );

        if (!success) {
          console.error(
            'Paystack webhook rejected: payment/order validation failed.',
            String(
              event.data.reference
            )
          );

          return res.sendStatus(
            400
          );
        }
      }

      return res.sendStatus(
        200
      );
    } catch (error) {
      console.error(
        'Paystack webhook error:',
        error.message
      );

      return res.sendStatus(
        500
      );
    }
  }
);

app.post(
  '/api/upgrade',
  requireAuth,
  (req, res) =>
    res.status(410).json({
      error:
        'The old upgrade endpoint is disabled. Use /api/payments/initialize.'
    })
);

app.get(
  '/api/admin/users',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      if (pool) {
        const rows =
          await sql(`
            SELECT
              id,
              email,
              name,
              university,
              country,
              level,
              xp,
              premium,
              admin,
              created_at
            FROM users
            ORDER BY id DESC
            LIMIT 500
          `);

        return res.json({
          users:
            rows.map(
              safeUser
            )
        });
      }

      res.json({
        users:
          db.users.map(
            safeUser
          )
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  '/api/admin/users/:id/premium',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const enabled =
        req.body?.premium !==
          false;

      if (pool) {
        const rows =
          await sql(
            `
            UPDATE users
            SET premium=$1
            WHERE id=$2
            RETURNING *
            `,
            [
              enabled,
              req.params.id
            ]
          );

        if (!rows.length) {
          return res.status(404).json({
            error:
              'User not found.'
          });
        }

        return res.json({
          user:
            safeUser(rows[0])
        });
      }

      const user =
        db.users.find(
          u =>
            String(u.id) ===
            String(req.params.id)
        );

      if (!user) {
        return res.status(404).json({
          error:
            'User not found.'
        });
      }

      user.premium =
        enabled;

      saveLocalDb();

      res.json({
        user:
          safeUser(user)
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/admin/payments',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      if (pool) {
        const rows =
          await sql(`
            SELECT
              p.*,
              u.email,
              u.name
            FROM payments p
            LEFT JOIN users u
              ON u.id=p.user_id
            ORDER BY
              p.created_at DESC
            LIMIT 500
          `);

        return res.json({
          payments:
            rows
        });
      }

      res.json({
        payments:
          db.payments
      });
    } catch (error) {
      next(error);
    }
  }
);

app.get(
  '/api/admin/stats',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      if (pool) {
        const [
          users,
          premium,
          questions,
          payments
        ] =
          await Promise.all([
            sql(
              'SELECT COUNT(*)::int AS count FROM users'
            ),
            sql(
              'SELECT COUNT(*)::int AS count FROM users WHERE premium=true'
            ),
            sql(
              'SELECT COUNT(*)::int AS count FROM questions WHERE active=true'
            ),
            sql(
              "SELECT COUNT(*)::int AS count FROM payments WHERE status='success'"
            )
          ]);

        return res.json({
          users:
            Number(
              users[0]?.count || 0
            ),
          premium:
            Number(
              premium[0]?.count || 0
            ),
          questions:
            Number(
              questions[0]?.count || 0
            ),
          successfulPayments:
            Number(
              payments[0]?.count || 0
            )
        });
      }

      res.json({
        users:
          db.users.length,
        premium:
          db.users.filter(
            u => u.premium
          ).length,
        questions:
          questionBank.length,
        successfulPayments:
          db.payments.filter(
            p =>
              p.status ===
              'success'
          ).length
      });
    } catch (error) {
      next(error);
    }
  }
);

app.use(
  express.static(
    path.join(
      ROOT,
      'public'
    ),
    {
      extensions: ['html']
    }
  )
);

app.get(
  /^(?!\/api(?:\/|$)).*/,
  (
    req,
    res,
    next
  ) => {
    const indexPath =
      path.join(
        ROOT,
        'public',
        'index.html'
      );

    if (
      !fs.existsSync(
        indexPath
      )
    ) {
      return res.status(500).json({
        error:
          'public/index.html is missing.'
      });
    }

    res.sendFile(
      indexPath,
      error => {
        if (error) {
          next(error);
        }
      }
    );
  }
);

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(error);

    if (
      res.headersSent
    ) {
      return next(error);
    }

    res.status(500).json({
      error: isProduction
        ? 'Server error'
        : String(
            error.message ||
              'Server error'
          )
    });
  }
);

async function startServer() {
  try {
    questionBank =
      loadQuestionBank();

    if (
      !questionBank.length
    ) {
      throw new Error(
        'question.json contains no valid questions.'
      );
    }

    await initDb();

    app.listen(
      PORT,
      () => {
        console.log(
          '=========================================='
        );

        console.log(
          `DENexPharm running on port ${PORT}`
        );

        console.log(
          `Environment: ${
            isProduction
              ? 'production'
              : 'development'
          }`
        );

        console.log(
          `Database: ${
            pool
              ? 'PostgreSQL'
              : 'JSON fallback'
          }`
        );

        console.log(
          `Question bank: ${questionBank.length} questions`
        );

        console.log(
          `Free questions per country/level/subject: ${FREE_QUESTIONS_PER_SUBJECT}`
        );

        console.log(
          `Premium price: ${PREMIUM_PRICE} ${PREMIUM_CURRENCY}`
        );

        console.log(
          `Paystack: ${
            paystackConfigured()
              ? (
                  paystackIsLive()
                    ? 'LIVE'
                    : 'NON-LIVE'
                )
              : 'NOT CONFIGURED'
          }`
        );

        console.log(
          '=========================================='
        );
      }
    );
  } catch (error) {
    console.error(
      '=========================================='
    );

    console.error(
      'DENexPharm startup failed:'
    );

    console.error(error);

    console.error(
      '=========================================='
    );

    process.exit(1);
  }
}

startServer();
