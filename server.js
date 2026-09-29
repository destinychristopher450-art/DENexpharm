'use strict';

/*
 * DENexpharm Production Server
 * Corrected for the existing PostgreSQL schema.sql
 *
 * IMPORTANT:
 * - Existing DB uses SERIAL/INTEGER IDs.
 * - Existing users table uses "admin", not "is_admin".
 * - Existing questions table uses SERIAL IDs.
 * - Existing scores/payments use INTEGER user_id foreign keys.
 * - question.json question IDs are synchronized with the SERIAL sequence.
 * - Paystack Premium remains supported.
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

const SUPPORTED_LEVELS = [
  '100',
  '200',
  '300',
  '400',
  '500',
  '600'
];

const frontendOrigin = process.env.FRONTEND_ORIGIN
  ? process.env.FRONTEND_ORIGIN
      .split(',')
      .map(v => v.trim())
      .filter(Boolean)
  : isProduction
    ? false
    : true;

/* =========================================================
   PRODUCTION VALIDATION
   ========================================================= */

if (isProduction) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error(
      'STARTUP ERROR: JWT_SECRET must be configured and at least 32 characters long.'
    );
    process.exit(1);
  }

  if (!process.env.DATABASE_URL) {
    console.error(
      'STARTUP ERROR: DATABASE_URL must be configured in production.'
    );
    process.exit(1);
  }

  if (!process.env.PUBLIC_APP_URL && !process.env.APP_URL) {
    console.error(
      'STARTUP ERROR: PUBLIC_APP_URL must be configured in production.'
    );
    process.exit(1);
  }
}

if (!Number.isFinite(PREMIUM_PRICE) || PREMIUM_PRICE <= 0) {
  console.error('STARTUP ERROR: PREMIUM_PRICE must be a positive number.');
  process.exit(1);
}

/* =========================================================
   LOCAL FALLBACK
   ========================================================= */

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

/* =========================================================
   POSTGRESQL
   ========================================================= */

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

/* =========================================================
   GENERAL HELPERS
   ========================================================= */

function generateId() {
  return crypto.randomUUID();
}

function cleanText(value, fallback = '') {
  return String(value ?? fallback).trim();
}

function canonical(value) {
  return cleanText(value).toLowerCase();
}

function validLevel(level) {
  return SUPPORTED_LEVELS.includes(String(level));
}

/* =========================================================
   USER HELPERS
   ========================================================= */

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
    {
      expiresIn: '30d'
    }
  );
}

function getTokenFromRequest(req) {
  const header = req.get('authorization') || '';

  if (!header.startsWith('Bearer ')) {
    return null;
  }

  return header.slice(7).trim();
}

function authenticate(req) {
  const token = getTokenFromRequest(req);

  if (!token) {
    return null;
  }

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
      error: 'Sign in required.'
    });
  }

  req.auth = auth;
  next();
}

async function requireAdmin(req, res, next) {
  const auth = authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error: 'Sign in required.'
    });
  }

  try {
    const user = await getUserById(auth.id);

    if (!user || !user.admin) {
      return res.status(403).json({
        error: 'Admin access required.'
      });
    }

    req.auth = auth;
    req.currentUser = user;

    next();
  } catch (error) {
    next(error);
  }
}

async function getUserById(userId) {
  if (pool) {
    const rows = await sql(
      'SELECT * FROM users WHERE id = $1 LIMIT 1',
      [userId]
    );

    return rows[0] || null;
  }

  return (
    db.users.find(
      user => String(user.id) === String(userId)
    ) || null
  );
}

async function getUserByEmail(email) {
  const normalized = cleanText(email).toLowerCase();

  if (!normalized) {
    return null;
  }

  if (pool) {
    const rows = await sql(
      'SELECT * FROM users WHERE email = $1 LIMIT 1',
      [normalized]
    );

    return rows[0] || null;
  }

  return (
    db.users.find(
      user =>
        String(user.email || '').toLowerCase() === normalized
    ) || null
  );
}

/* =========================================================
   QUESTION HELPERS
   ========================================================= */

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

  const subject = cleanText(
    question.subject
  );

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

function getLocalQuestions() {
  return db.questions
    .map((q, i) =>
      normalizeQuestion(q, i + 1)
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

    [
      result[i],
      result[j]
    ] = [
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
    (!c ||
      canonical(q.country) === c) &&
    (!l ||
      canonical(q.level) === l) &&
    (!s ||
      canonical(q.subject) === s) &&
    (!t ||
      canonical(q.topic) === t)
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
        normalizeQuestion(row, row.id)
      )
      .filter(Boolean);
  }

  const merged = new Map();

  for (const q of questionBank) {
    if (q.active !== false) {
      merged.set(
        String(q.id),
        q
      );
    }
  }

  for (const q of getLocalQuestions()) {
    merged.set(
      String(q.id),
      q
    );
  }

  return Array.from(
    merged.values()
  ).filter(
    q => q.active !== false
  );
}

async function getQuestionById(questionId) {
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
      WHERE id = $1
        AND active = true
      LIMIT 1
    `, [questionId]);

    return rows.length
      ? normalizeQuestion(
          rows[0],
          rows[0].id
        )
      : null;
  }

  const idString = String(questionId);

  return (
    getLocalQuestions().find(
      q => String(q.id) === idString
    ) ||
    questionBank.find(
      q => String(q.id) === idString
    ) ||
    null
  );
}

async function getFilterData() {
  const questions =
    await getAllQuestions();

  const countryMap = new Map();
  const subjectMap = new Map();
  const topicMap = new Map();

  for (const q of questions) {
    countryMap.set(
      canonical(q.country),
      q.country
    );

    subjectMap.set(
      canonical(q.subject),
      q.subject
    );

    const topicKey = [
      canonical(q.country),
      canonical(q.level),
      canonical(q.subject),
      canonical(q.topic)
    ].join('|');

    topicMap.set(
      topicKey,
      q.topic
    );
  }

  return {
    countries:
      Array.from(
        countryMap.values()
      ).sort((a, b) =>
        a.localeCompare(b)
      ),

    levels: [
      ...SUPPORTED_LEVELS
    ],

    subjects:
      Array.from(
        subjectMap.values()
      ).sort((a, b) =>
        a.localeCompare(b)
      ),

    topics:
      Array.from(
        topicMap.entries()
      )
        .map(([key, topic]) => {
          const [
            country,
            level,
            subject
          ] = key.split('|');

          return {
            country,
            level,
            subject,
            topic
          };
        })
        .sort((a, b) =>
          a.topic.localeCompare(
            b.topic
          )
        )
  };
}

async function countQuestions(
  filters = {}
) {
  return filterQuestions(
    await getAllQuestions(),
    filters
  ).length;
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

/* =========================================================
   QUESTION DATABASE SYNCHRONIZATION
   ========================================================= */

async function importQuestionsToDatabase() {
  if (!pool) {
    console.log(
      `Local mode: using ${questionBank.length} questions directly from question.json.`
    );
    return;
  }

  /*
   * Existing schema uses SERIAL for questions.id.
   *
   * question.json may contain numeric IDs.
   * We preserve those IDs where possible so the question
   * bank remains stable.
   */

  for (const q of questionBank) {
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
        active
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
        $10
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

  /*
   * IMPORTANT:
   * Synchronize PostgreSQL SERIAL sequence after
   * inserting explicit question IDs.
   */
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

    const maxId = Number(
      maxResult.rows[0]
        ?.max_id || 0
    );

    /*
     * Set sequence so the next generated ID is maxId + 1.
     */
    await pool.query(
      `
      SELECT setval(
        $1::regclass,
        $2,
        false
      )
      `,
      [
        sequenceName,
        maxId + 1
      ]
    );
  }

  console.log(
    `PostgreSQL question synchronization complete. ${questionBank.length} records processed.`
  );
}

/* =========================================================
   DATABASE INITIALIZATION
   ========================================================= */

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
   * This is safe because the actual schema.sql already
   * defines the existing INTEGER/SERIAL structure.
   */
  await pool.query(schema);

  await importQuestionsToDatabase();

  /*
   * Optional production admin creation.
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
        INSERT INTO users
        (
          email,
          password_hash,
          name,
          admin
        )
        VALUES
        (
          $1,
          $2,
          $3,
          true
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

/* =========================================================
   EXPRESS CONFIGURATION
   ========================================================= */

app.disable(
  'x-powered-by'
);

app.set(
  'trust proxy',
  process.env.TRUST_PROXY === 'true'
    ? 1
    : false
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

/*
 * Capture raw body for Paystack webhook signature
 * verification while still allowing normal JSON routes.
 */
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

/* =========================================================
   RATE LIMITING
   ========================================================= */

app.use(
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    limit: 300,

    standardHeaders:
      'draft-8',

    legacyHeaders: false
  })
);

const authLimiter =
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    limit: 20,

    standardHeaders:
      'draft-8',

    legacyHeaders: false
  });

/* =========================================================
   HEALTH
   ========================================================= */

app.get(
  '/api/health',
  async (req, res) => {
    try {
      res.json({
        ok: true,
        version: '6.1.0',
        database: Boolean(pool),
        payments:
          Boolean(
            process.env.PAYSTACK_SECRET_KEY
          ),
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
  '/health',
  async (req, res) => {
    res.json({
      ok: true,
      database: Boolean(pool)
    });
  }
);

/* =========================================================
   AUTH - REGISTER
   ========================================================= */

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
        cleanText(
          email
        ).toLowerCase();

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

      const passwordHash =
        await bcrypt.hash(
          String(password),
          12
        );

      if (pool) {
        const rows =
          await sql(
            `
            INSERT INTO users
            (
              email,
              password_hash,
              name,
              university,
              country,
              level
            )
            VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6
            )
            RETURNING *
            `,
            [
              normalizedEmail,
              passwordHash,
              cleanText(name),
              cleanText(
                university
              ),
              cleanText(
                country
              ),
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
        email:
          normalizedEmail,
        password_hash:
          passwordHash,
        name:
          cleanText(name),
        university:
          cleanText(
            university
          ),
        country:
          cleanText(country),
        level:
          cleanLevel,
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

/* =========================================================
   AUTH - LOGIN
   ========================================================= */

app.post(
  '/api/auth/login',
  authLimiter,
  async (
    req,
    res,
    next
  ) => {
    try {
      const email =
        cleanText(
          req.body?.email
        ).toLowerCase();

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
        await getUserByEmail(
          email
        );

      if (
        !user ||
        !(
          await bcrypt.compare(
            password,
            user.password_hash
          )
        )
      ) {
        return res.status(401).json({
          error:
            'Invalid email or password.'
        });
      }

      return res.json({
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

/* =========================================================
   CURRENT USER
   ========================================================= */

app.get(
  '/api/me',
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

/* =========================================================
   USER PROFILE
   ========================================================= */

app.put(
  '/api/users/profile',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const cleanName =
        cleanText(
          req.body?.name
        );

      const cleanUniversity =
        cleanText(
          req.body?.university
        );

      const cleanCountry =
        cleanText(
          req.body?.country
        );

      const cleanLevel =
        cleanText(
          req.body?.level,
          '200'
        );

      if (!validLevel(cleanLevel)) {
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
                CASE
                  WHEN $1 <> ''
                  THEN $1
                  ELSE name
                END,
              university = $2,
              country = $3,
              level = $4
            WHERE id = $5
            RETURNING *
            `,
            [
              cleanName,
              cleanUniversity,
              cleanCountry,
              cleanLevel,
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

      if (cleanName) {
        user.name =
          cleanName;
      }

      user.university =
        cleanUniversity;

      user.country =
        cleanCountry;

      user.level =
        cleanLevel;

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

/* =========================================================
   SUBJECTS
   ========================================================= */

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

/* =========================================================
   QUESTION FILTERS
   ========================================================= */

app.get(
  '/api/question-filters',
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

/* =========================================================
   QUESTIONS
   ========================================================= */

app.get(
  '/api/questions',
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

      const premium =
        Boolean(user.premium);

      const country =
        cleanText(
          req.query.country ||
          user.country
        );

      const level =
        cleanText(
          req.query.level ||
          user.level
        );

      const subject =
        cleanText(
          req.query.subject
        );

      const topic =
        cleanText(
          req.query.topic
        );

      if (!country) {
        return res.status(400).json({
          error:
            'Select a country.'
        });
      }

      if (!validLevel(level)) {
        return res.status(400).json({
          error:
            'Level must be 100, 200, 300, 400, 500 or 600.'
        });
      }

      let questions =
        filterQuestions(
          await getAllQuestions(),
          {
            country,
            level,
            subject,
            topic
          }
        );

      const total =
        questions.length;

      if (!premium) {
        questions =
          limitFreeQuestions(
            questions
          );
      }

      const random =
        canonical(
          req.query.random
        ) === 'true';

      if (random) {
        questions =
          shuffle(
            questions
          );
      } else {
        questions.sort(
          (a, b) =>
            a.id - b.id
        );
      }

      const requestedLimit =
        Number(
          req.query.limit
        );

      const requestedOffset =
        Number(
          req.query.offset
        );

      const offset =
        Number.isInteger(
          requestedOffset
        ) &&
        requestedOffset >= 0
          ? requestedOffset
          : 0;

      const limit =
        Number.isInteger(
          requestedLimit
        ) &&
        requestedLimit > 0
          ? Math.min(
              requestedLimit,
              2000
            )
          : 2000;

      const returned =
        premium
          ? questions.slice(
              offset,
              offset + limit
            )
          : questions;

      res.json({
        questions:
          returned,

        premium,

        access:
          premium
            ? 'premium'
            : 'free',

        country,
        level,

        subject:
          subject || null,

        topic:
          topic || null,

        total_available:
          total,

        free_limit:
          FREE_QUESTIONS_PER_SUBJECT,

        returned:
          returned.length,

        offset:
          premium
            ? offset
            : 0,

        limit:
          premium
            ? limit
            : FREE_QUESTIONS_PER_SUBJECT,

        premium_required:
          !premium &&
          total >
            FREE_QUESTIONS_PER_SUBJECT
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   SINGLE QUESTION
   ========================================================= */

app.get(
  '/api/questions/:id',
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

      if (!user.premium) {
        const scoped =
          filterQuestions(
            await getAllQuestions(),
            {
              country:
                question.country,

              level:
                question.level,

              subject:
                question.subject
            }
          );

        const allowed =
          scoped
            .sort(
              (a, b) =>
                a.id - b.id
            )
            .slice(
              0,
              FREE_QUESTIONS_PER_SUBJECT
            )
            .some(
              q =>
                String(q.id) ===
                String(question.id)
            );

        if (!allowed) {
          return res.status(403).json({
            error:
              'This question requires Premium. Free accounts have access to the first 10 questions in each country, level and subject.'
          });
        }
      }

      res.json({
        question,
        premium:
          Boolean(user.premium)
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   QUESTION ACCESS
   ========================================================= */

app.get(
  '/api/questions/access',
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

      const country =
        cleanText(
          req.query.country ||
          user.country
        );

      const level =
        cleanText(
          req.query.level ||
          user.level
        );

      const subject =
        cleanText(
          req.query.subject
        );

      const topic =
        cleanText(
          req.query.topic
        );

      const total =
        await countQuestions({
          country,
          level,
          subject,
          topic
        });

      res.json({
        premium:
          Boolean(user.premium),

        country,
        level,

        subject:
          subject || null,

        topic:
          topic || null,

        total_questions:
          total,

        free_questions:
          Math.min(
            total,
            FREE_QUESTIONS_PER_SUBJECT
          ),

        remaining_after_free:
          Math.max(
            0,
            total -
              FREE_QUESTIONS_PER_SUBJECT
          ),

        premium_required:
          !user.premium &&
          total >
            FREE_QUESTIONS_PER_SUBJECT
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   SCORES
   ========================================================= */

app.post(
  '/api/scores',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      const subject =
        cleanText(
          req.body?.subject,
          'General'
        ) || 'General';

      const rawScore =
        Number(
          req.body?.score
        );

      const rawTotal =
        Number(
          req.body?.total
        );

      if (
        !Number.isFinite(
          rawScore
        ) ||
        !Number.isFinite(
          rawTotal
        ) ||
        rawTotal <= 0 ||
        rawScore < 0 ||
        rawScore > rawTotal
      ) {
        return res.status(400).json({
          error:
            'Invalid score or total.'
        });
      }

      const score =
        Math.floor(
          rawScore
        );

      const total =
        Math.floor(
          rawTotal
        );

      const xp =
        Math.min(
          score * 10,
          total * 10
        );

      if (pool) {
        /*
         * scores.id is SERIAL.
         * Therefore DO NOT insert an ID here.
         */
        await sql(
          `
          INSERT INTO scores
          (
            user_id,
            subject,
            score,
            total
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4
          )
          `,
          [
            req.auth.id,
            subject,
            score,
            total
          ]
        );

        await sql(
          `
          UPDATE users
          SET xp = xp + $1
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

          subject,
          score,
          total,

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
            Number(
              user.xp || 0
            ) + xp;
        }

        saveLocalDb();
      }

      res.status(201).json({
        ok: true,
        xp
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   LEADERBOARD
   ========================================================= */

app.get(
  '/api/leaderboard',
  async (
    req,
    res,
    next
  ) => {
    try {
      let leaderboard;

      if (pool) {
        leaderboard =
          await sql(
            `
            SELECT
              id,
              name,
              university,
              country,
              xp
            FROM users
            ORDER BY
              xp DESC,
              name ASC
            LIMIT 100
            `
          );

        leaderboard =
          leaderboard.map(
            u => ({
              id: u.id,
              name: u.name,
              university:
                u.university ||
                '',
              country:
                u.country ||
                '',
              xp:
                Number(
                  u.xp || 0
                )
            })
          );
      } else {
        leaderboard =
          db.users
            .map(
              safeUser
            )
            .sort(
              (a, b) =>
                b.xp - a.xp ||
                a.name.localeCompare(
                  b.name
                )
            )
            .slice(
              0,
              100
            );
      }

      res.json({
        leaderboard
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   ADMIN QUESTION VALIDATION
   ========================================================= */

function validateAdminQuestion(
  body,
  current = {}
) {
  const country =
    cleanText(
      body.country !== undefined
        ? body.country
        : current.country,
      'Nigeria'
    );

  const level =
    cleanText(
      body.level !== undefined
        ? body.level
        : current.level,
      '200'
    );

  const subject =
    cleanText(
      body.subject !== undefined
        ? body.subject
        : current.subject
    );

  const topic =
    cleanText(
      body.topic !== undefined
        ? body.topic
        : current.topic,
      'General'
    );

  const question =
    cleanText(
      body.question !== undefined
        ? body.question
        : current.question
    );

  const options =
    body.options !== undefined
      ? body.options
      : current.options;

  const answerIndex =
    body.answer_index !==
    undefined
      ? Number(
          body.answer_index
        )
      : Number(
          current.answer_index
        );

  const explanation =
    cleanText(
      body.explanation !==
      undefined
        ? body.explanation
        : current.explanation
    );

  const active =
    body.active !== undefined
      ? Boolean(
          body.active
        )
      : Boolean(
          current.active ??
          true
        );

  if (
    !country ||
    !validLevel(level) ||
    !subject ||
    !topic ||
    !question ||
    !Array.isArray(options) ||
    options.length !== 4 ||
    !Number.isInteger(
      answerIndex
    ) ||
    answerIndex < 0 ||
    answerIndex > 3
  ) {
    return null;
  }

  return {
    country,
    level,
    subject,
    topic,
    question,
    options:
      options.map(String),
    answer_index:
      answerIndex,
    explanation,
    active
  };
}

/* =========================================================
   ADMIN QUESTIONS
   ========================================================= */

app.get(
  '/api/admin/questions',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      if (pool) {
        return res.json({
          questions:
            await sql(
              `
              SELECT *
              FROM questions
              ORDER BY id DESC
              `
            )
        });
      }

      res.json({
        questions:
          db.questions
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
      const data =
        validateAdminQuestion(
          req.body || {}
        );

      if (!data) {
        return res.status(400).json({
          error:
            'Invalid question data. Country, level, subject, topic, question, four options and answer_index 0-3 are required.'
        });
      }

      if (pool) {
        const rows =
          await sql(
            `
            INSERT INTO questions
            (
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
            VALUES
            (
              $1,
              $2,
              $3,
              $4,
              $5,
              $6::jsonb,
              $7,
              $8,
              $9
            )
            RETURNING *
            `,
            [
              data.country,
              data.level,
              data.subject,
              data.topic,
              data.question,
              JSON.stringify(
                data.options
              ),
              data.answer_index,
              data.explanation,
              data.active
            ]
          );

        return res.status(201).json({
          question:
            rows[0]
        });
      }

      const newQuestion = {
        id:
          generateId(),
        ...data,
        updated_at:
          new Date().toISOString()
      };

      db.questions.push(
        newQuestion
      );

      saveLocalDb();

      res.status(201).json({
        question:
          newQuestion
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   ADMIN UPDATE QUESTION
   ========================================================= */

app.patch(
  '/api/admin/questions/:id',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const id =
        req.params.id;

      if (pool) {
        const rows =
          await sql(
            `
            SELECT *
            FROM questions
            WHERE id = $1
            LIMIT 1
            `,
            [id]
          );

        if (!rows.length) {
          return res.status(404).json({
            error:
              'Question not found.'
          });
        }

        const data =
          validateAdminQuestion(
            req.body || {},
            rows[0]
          );

        if (!data) {
          return res.status(400).json({
            error:
              'Invalid question data.'
          });
        }

        const updated =
          await sql(
            `
            UPDATE questions
            SET
              country = $1,
              level = $2,
              subject = $3,
              topic = $4,
              question = $5,
              options = $6::jsonb,
              answer_index = $7,
              explanation = $8,
              active = $9,
              updated_at = NOW()
            WHERE id = $10
            RETURNING *
            `,
            [
              data.country,
              data.level,
              data.subject,
              data.topic,
              data.question,
              JSON.stringify(
                data.options
              ),
              data.answer_index,
              data.explanation,
              data.active,
              id
            ]
          );

        return res.json({
          question:
            updated[0]
        });
      }

      const existing =
        db.questions.find(
          q =>
            String(q.id) ===
            String(id)
        );

      if (!existing) {
        return res.status(404).json({
          error:
            'Question not found.'
        });
      }

      const data =
        validateAdminQuestion(
          req.body || {},
          existing
        );

      if (!data) {
        return res.status(400).json({
          error:
            'Invalid question data.'
        });
      }

      Object.assign(
        existing,
        data,
        {
          updated_at:
            new Date().toISOString()
        }
      );

      saveLocalDb();

      res.json({
        question:
          existing
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   PAYSTACK HELPERS
   ========================================================= */

function paystackConfigured() {
  return Boolean(
    String(
      process.env.PAYSTACK_SECRET_KEY ||
      process.env.PAYSTACK_SECRET ||
      ''
    ).trim()
  );
}

function getPaystackSecret() {
  return String(
    process.env.PAYSTACK_SECRET_KEY ||
    process.env.PAYSTACK_SECRET ||
    ''
  ).trim();
}

function getPublicAppUrl() {
  return cleanText(
    process.env.PUBLIC_APP_URL ||
    process.env.APP_URL
  );
}

function createPaymentReference() {
  return (
    'DENEX_' +
    Date.now() +
    '_' +
    crypto
      .randomBytes(5)
      .toString('hex')
      .toUpperCase()
  );
}

async function paystackRequest(
  endpoint,
  options = {}
) {
  const secret =
    getPaystackSecret();

  if (!secret) {
    throw new Error(
      'Paystack is not configured.'
    );
  }

  const response =
    await fetch(
      `https://api.paystack.co${endpoint}`,
      {
        ...options,

        headers: {
          Authorization:
            `Bearer ${secret}`,

          'Content-Type':
            'application/json',

          ...(options.headers || {})
        }
      }
    );

  const data =
    await response.json();

  if (
    !response.ok ||
    !data.status
  ) {
    throw new Error(
      data.message ||
      'Paystack request failed.'
    );
  }

  return data;
}

async function verifyPaystack(
  reference
) {
  const data =
    await paystackRequest(
      `/transaction/verify/${encodeURIComponent(
        reference
      )}`,
      {
        method: 'GET'
      }
    );

  if (
    !data.data ||
    data.data.status !==
      'success'
  ) {
    throw new Error(
      'Paystack transaction was not successful.'
    );
  }

  return data.data;
}

/* =========================================================
   PAYMENT INITIALIZATION
   ========================================================= */

app.post(
  '/api/payments/initialize',
  requireAuth,
  async (
    req,
    res,
    next
  ) => {
    try {
      if (!paystackConfigured()) {
        return res.status(503).json({
          error:
            'Paystack is not configured. Add PAYSTACK_SECRET_KEY to your environment variables.'
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
        return res.status(409).json({
          error:
            'This account already has Premium access.'
        });
      }

      const amount =
        PREMIUM_PRICE;

      const currency =
        PREMIUM_CURRENCY;

      const reference =
        createPaymentReference();

      const callbackUrl =
        process.env.PAYSTACK_CALLBACK_URL ||
        (
          getPublicAppUrl()
            ? `${getPublicAppUrl()}/api/payments/callback`
            : undefined
        );

      const data =
        await paystackRequest(
          '/transaction/initialize',
          {
            method: 'POST',

            body: JSON.stringify({
              email:
                user.email,

              amount:
                Math.round(
                  amount * 100
                ),

              currency,

              reference,

              callback_url:
                callbackUrl,

              metadata: {
                user_id:
                  String(
                    req.auth.id
                  ),

                product:
                  'DENexPharm Premium'
              }
            })
          }
        );

      if (
        pool
      ) {
        /*
         * payments.id is SERIAL.
         * Do not provide an ID.
         */
        await sql(
          `
          INSERT INTO payments
          (
            reference,
            user_id,
            amount,
            currency,
            status
          )
          VALUES
          (
            $1,
            $2,
            $3,
            $4,
            $5
          )
          `,
          [
            reference,
            req.auth.id,
            amount,
            currency,
            'initialized'
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
            '',
          created_at:
            new Date().toISOString()
        });

        saveLocalDb();
      }

      res.json({
        authorization_url:
          data.data
            .authorization_url,

        reference:
          data.data.reference
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   PAYMENT ACTIVATION
   ========================================================= */

async function markPremium(
  reference,
  paymentData
) {
  const cleanReference =
    cleanText(
      reference
    );

  if (
    !cleanReference ||
    !paymentData
  ) {
    return false;
  }

  if (
    paymentData.status !==
    'success'
  ) {
    return false;
  }

  const metadataUserId =
    paymentData.metadata?.user_id !=
    null
      ? String(
          paymentData.metadata.user_id
        )
      : '';

  if (!metadataUserId) {
    return false;
  }

  const paidAmount =
    Number(
      paymentData.amount
    ) / 100;

  const paidCurrency =
    String(
      paymentData.currency ||
        ''
    ).toUpperCase();

  /*
   * Verify the transaction amount
   * and currency against our configured
   * Premium price.
   */
  if (
    paidAmount !==
      PREMIUM_PRICE ||
    paidCurrency !==
      PREMIUM_CURRENCY
  ) {
    return false;
  }

  if (pool) {
    const users =
      await sql(
        `
        SELECT id
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [metadataUserId]
      );

    if (!users.length) {
      return false;
    }

    const payments =
      await sql(
        `
        SELECT
          amount,
          currency,
          status
        FROM payments
        WHERE reference = $1
        LIMIT 1
        `,
        [cleanReference]
      );

    if (!payments.length) {
      return false;
    }

    const stored =
      payments[0];

    if (
      Number(
        stored.amount
      ) !== PREMIUM_PRICE
    ) {
      return false;
    }

    if (
      String(
        stored.currency
      ).toUpperCase() !==
      PREMIUM_CURRENCY
    ) {
      return false;
    }

    /*
     * Idempotent activation.
     * If already successful, keep Premium enabled.
     */
    await sql(
      `
      UPDATE users
      SET premium = true
      WHERE id = $1
      `,
      [metadataUserId]
    );

    await sql(
      `
      UPDATE payments
      SET
        status = $1,
        provider_reference = $2
      WHERE reference = $3
      `,
      [
        'success',
        String(
          paymentData.id ||
            cleanReference
        ),
        cleanReference
      ]
    );

    return true;
  }

  const user =
    db.users.find(
      u =>
        String(u.id) ===
        metadataUserId
    );

  const payment =
    db.payments.find(
      p =>
        String(
          p.reference
        ) ===
        cleanReference
    );

  if (
    !user ||
    !payment
  ) {
    return false;
  }

  if (
    Number(
      payment.amount
    ) !== PREMIUM_PRICE
  ) {
    return false;
  }

  if (
    String(
      payment.currency ||
        ''
    ).toUpperCase() !==
    PREMIUM_CURRENCY
  ) {
    return false;
  }

  payment.status =
    'success';

  payment.provider_reference =
    String(
      paymentData.id ||
        cleanReference
    );

  user.premium =
    true;

  saveLocalDb();

  return true;
}

/* =========================================================
   PAYSTACK CALLBACK
   ========================================================= */

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

      /*
       * Never grant Premium merely because
       * the browser returned from Paystack.
       *
       * Always verify with Paystack first.
       */
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

/* =========================================================
   PAYSTACK WEBHOOK
   ========================================================= */

app.post(
  '/api/payments/webhook',
  async (
    req,
    res
  ) => {
    try {
      if (!paystackConfigured()) {
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
            getPaystackSecret()
          )
          .update(
            rawBody
          )
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

      /*
       * For charge.success, re-fetch the
       * transaction directly from Paystack
       * instead of trusting the webhook body.
       */
      if (
        event.event ===
          'charge.success' &&
        event.data?.reference
      ) {
        const reference =
          String(
            event.data.reference
          );

        const verified =
          await verifyPaystack(
            reference
          );

        const success =
          await markPremium(
            reference,
            verified
          );

        if (!success) {
          console.error(
            'Paystack webhook payment validation failed:',
            reference
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

/* =========================================================
   OLD UPGRADE ENDPOINT
   ========================================================= */

app.post(
  '/api/upgrade',
  requireAuth,
  (req, res) => {
    res.status(410).json({
      error:
        'The old upgrade endpoint is disabled. Use /api/payments/initialize.'
    });
  }
);

/* =========================================================
   ADMIN USERS
   ========================================================= */

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
        const users =
          await sql(
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
              admin,
              created_at
            FROM users
            ORDER BY id DESC
            `
          );

        return res.json({
          users
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

/* =========================================================
   ADMIN PAYMENTS
   ========================================================= */

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
        const payments =
          await sql(
            `
            SELECT
              p.*,
              u.email,
              u.name
            FROM payments p
            LEFT JOIN users u
              ON u.id = p.user_id
            ORDER BY
              p.id DESC
            `
          );

        return res.json({
          payments
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

/* =========================================================
   ADMIN MANUAL PREMIUM
   ========================================================= */

app.patch(
  '/api/admin/users/:id/premium',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const enabled =
        Boolean(
          req.body?.premium
        );

      const userId =
        req.params.id;

      if (pool) {
        const rows =
          await sql(
            `
            UPDATE users
            SET premium = $1
            WHERE id = $2
            RETURNING *
            `,
            [
              enabled,
              userId
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
            safeUser(
              rows[0]
            )
        });
      }

      const user =
        db.users.find(
          u =>
            String(u.id) ===
            String(userId)
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

/* =========================================================
   API 404
   ========================================================= */

app.use(
  '/api',
  (req, res) => {
    res.status(404).json({
      error:
        'API endpoint not found.'
    });
  }
);

/* =========================================================
   STATIC FRONTEND
   ========================================================= */

app.use(
  express.static(
    path.join(
      ROOT,
      'public'
    ),
    {
      extensions: [
        'html'
      ]
    }
  )
);

/*
 * SPA fallback.
 *
 * RegExp is intentionally used here because
 * Express 5 path parsing can reject some
 * string wildcard patterns.
 */
app.get(
  /^(?!\/api(?:\/|$)).*/,
  (req, res, next) => {
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

/* =========================================================
   ERROR HANDLER
   ========================================================= */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    res.status(500).json({
      error:
        isProduction
          ? 'Server error.'
          : String(
              error.message ||
                'Server error.'
            )
    });
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

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

    console.error(
      error
    );

    console.error(
      '=========================================='
    );

    process.exit(1);
  }
}

startServer();
