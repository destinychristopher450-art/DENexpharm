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

/* =========================================================
   CONFIGURATION
========================================================= */

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

/*
  Premium price is controlled by the SERVER.
  The frontend cannot choose a cheaper price.
*/
const PREMIUM_PRICE = Number(
  process.env.PREMIUM_PRICE || 5000
);

const PREMIUM_CURRENCY = String(
  process.env.PREMIUM_CURRENCY || 'NGN'
).trim().toUpperCase();

/*
  FRONTEND_ORIGIN may contain multiple comma-separated origins.
  Example:
  https://denexpharm.pages.dev,https://denexpharm-1.onrender.com
*/
const frontendOrigin = process.env.FRONTEND_ORIGIN
  ? process.env.FRONTEND_ORIGIN
      .split(',')
      .map(value => value.trim())
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

if (
  !Number.isFinite(PREMIUM_PRICE) ||
  PREMIUM_PRICE <= 0
) {
  console.error(
    'STARTUP ERROR: PREMIUM_PRICE must be a positive number.'
  );
  process.exit(1);
}


/* =========================================================
   LOCAL JSON DATABASE
========================================================= */

const DEFAULT_DB = {
  users: [],
  questions: [],
  scores: [],
  payments: []
};

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, {
    recursive: true
  });
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

    return {
      users: [],
      questions: [],
      scores: [],
      payments: []
    };
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
      connectionString:
        process.env.DATABASE_URL,

      ssl:
        process.env.DATABASE_SSL === 'false'
          ? false
          : {
              rejectUnauthorized: false
            },

      max: Math.max(
        1,
        Number(
          process.env.DB_POOL_MAX || 10
        )
      )
    })
  : null;

async function sql(query, params = []) {
  if (!pool) return [];

  const result = await pool.query(
    query,
    params
  );

  return result.rows;
}


/* =========================================================
   GENERAL HELPERS
========================================================= */

function generateId() {
  return crypto.randomUUID();
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
    {
      expiresIn: '30d'
    }
  );
}

function getTokenFromRequest(req) {
  const header =
    req.get('authorization') || '';

  if (!header.startsWith('Bearer ')) {
    return null;
  }

  return header
    .slice(7)
    .trim();
}

function authenticate(req) {
  const token =
    getTokenFromRequest(req);

  if (!token) {
    return null;
  }

  try {
    return jwt.verify(
      token,
      JWT_SECRET
    );
  } catch {
    return null;
  }
}

function requireAuth(
  req,
  res,
  next
) {
  const auth = authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error: 'Sign in required'
    });
  }

  req.auth = auth;
  next();
}

async function requireAdmin(
  req,
  res,
  next
) {
  const auth = authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error: 'Sign in required'
    });
  }

  try {
    const user =
      await getUserById(auth.id);

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


/* =========================================================
   QUESTION VALIDATION
========================================================= */

function normalizeQuestion(
  question,
  fallbackId
) {
  if (
    !question ||
    typeof question !== 'object'
  ) {
    return null;
  }

  const numericId =
    Number(
      question.id ?? fallbackId
    );

  const subject =
    String(
      question.subject || ''
    ).trim();

  const questionText =
    String(
      question.question || ''
    ).trim();

  const options =
    Array.isArray(question.options)
      ? question.options.map(
          value => String(value)
        )
      : [];

  const answerIndex =
    Number(
      question.answer_index
    );

  if (
    !Number.isInteger(numericId) ||
    numericId < 1
  ) {
    return null;
  }

  if (!subject) {
    return null;
  }

  if (!questionText) {
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

    subject,

    question: questionText,

    options,

    answer_index:
      answerIndex,

    explanation:
      String(
        question.explanation || ''
      ),

    active:
      question.active !== false
  };
}


/* =========================================================
   LOAD THE 10,000+ QUESTION BANK
========================================================= */

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
    const normalized =
      normalizeQuestion(
        parsed[index],
        index + 1
      );

    if (!normalized) {
      console.warn(
        `Skipping invalid question at question.json index ${index}.`
      );

      continue;
    }

    if (
      seenIds.has(
        normalized.id
      )
    ) {
      console.warn(
        `Skipping duplicate question ID ${normalized.id}.`
      );

      continue;
    }

    seenIds.add(
      normalized.id
    );

    validQuestions.push(
      normalized
    );
  }

  validQuestions.sort(
    (a, b) =>
      a.id - b.id
  );

  console.log(
    `Loaded ${validQuestions.length} valid questions from question.json.`
  );

  return validQuestions;
}

let questionBank = [];


/* =========================================================
   QUESTION UTILITIES
========================================================= */

function getLocalQuestions() {
  return db.questions
    .map(
      (question, index) =>
        normalizeQuestion(
          question,
          index + 1
        )
    )
    .filter(
      question =>
        question &&
        question.active !== false
    );
}

function shuffle(array) {
  const result = [
    ...array
  ];

  for (
    let i = result.length - 1;
    i > 0;
    i--
  ) {
    const j =
      crypto.randomInt(
        i + 1
      );

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

function limitFreeQuestions(
  questions
) {
  const grouped =
    new Map();

  for (
    const question of questions
  ) {
    if (
      !grouped.has(
        question.subject
      )
    ) {
      grouped.set(
        question.subject,
        []
      );
    }

    grouped
      .get(question.subject)
      .push(question);
  }

  const result = [];

  for (
    const group of grouped.values()
  ) {
    result.push(
      ...group
        .sort(
          (a, b) =>
            a.id - b.id
        )
        .slice(
          0,
          FREE_QUESTIONS_PER_SUBJECT
        )
    );
  }

  return result.sort(
    (a, b) =>
      a.id - b.id
  );
}


/* =========================================================
   GET ALL QUESTIONS
========================================================= */

async function getAllQuestions() {
  /*
    PostgreSQL is the primary deployed question store.
    question.json is imported into it during startup.

    Local mode uses data/db.json.
  */

  if (pool) {
    const rows =
      await sql(`
        SELECT
          id,
          subject,
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
      .map(
        row =>
          normalizeQuestion(
            row,
            row.id
          )
      )
      .filter(Boolean);
  }

  /*
    Local fallback:
    question.json questions are the primary bank.
    db.json questions can contain admin-created additions.
  */

  const merged =
    new Map();

  for (
    const question of questionBank
  ) {
    if (question.active !== false) {
      merged.set(
        String(question.id),
        question
      );
    }
  }

  for (
    const question of getLocalQuestions()
  ) {
    /*
      Locally created questions normally
      use UUIDs, so they do not overwrite
      numeric question-bank IDs.
    */

    merged.set(
      String(question.id),
      question
    );
  }

  return Array.from(
    merged.values()
  ).filter(
    question =>
      question.active !== false
  );
}


async function getQuestionById(
  questionId
) {
  const idString =
    String(questionId);

  if (pool) {
    const rows =
      await sql(
        `
        SELECT
          id,
          subject,
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

    if (!rows.length) {
      return null;
    }

    return normalizeQuestion(
      rows[0],
      rows[0].id
    );
  }

  const local =
    getLocalQuestions()
      .find(
        question =>
          String(
            question.id
          ) === idString
      );

  if (local) {
    return local;
  }

  return (
    questionBank.find(
      question =>
        String(
          question.id
        ) === idString
    ) || null
  );
}


/* =========================================================
   USERS
========================================================= */

async function getUserById(
  userId
) {
  if (pool) {
    const rows =
      await sql(
        `
        SELECT *
        FROM users
        WHERE id = $1
        LIMIT 1
        `,
        [userId]
      );

    return rows[0] || null;
  }

  return (
    db.users.find(
      user =>
        String(user.id) ===
        String(userId)
    ) || null
  );
}

async function getUserByEmail(
  email
) {
  const normalized =
    String(email || '')
      .trim()
      .toLowerCase();

  if (!normalized) {
    return null;
  }

  if (pool) {
    const rows =
      await sql(
        `
        SELECT *
        FROM users
        WHERE email = $1
        LIMIT 1
        `,
        [normalized]
      );

    return rows[0] || null;
  }

  return (
    db.users.find(
      user =>
        String(
          user.email || ''
        ).toLowerCase() ===
        normalized
    ) || null
  );
}


/* =========================================================
   QUESTION COUNT
========================================================= */

async function countQuestions(
  subject = null
) {
  if (pool) {
    if (subject) {
      const rows =
        await sql(
          `
          SELECT COUNT(*)::int AS count
          FROM questions
          WHERE active = true
            AND subject = $1
          `,
          [subject]
        );

      return Number(
        rows[0]?.count || 0
      );
    }

    const rows =
      await sql(`
        SELECT COUNT(*)::int AS count
        FROM questions
        WHERE active = true
      `);

    return Number(
      rows[0]?.count || 0
    );
  }

  const questions =
    getLocalQuestions();

  if (!subject) {
    return questions.length;
  }

  return questions.filter(
    question =>
      question.subject ===
      subject
  ).length;
}


/* =========================================================
   SUBJECTS
========================================================= */

async function getSubjects() {
  const questions =
    await getAllQuestions();

  const map =
    new Map();

  for (
    const question of questions
  ) {
    if (
      !map.has(
        question.subject
      )
    ) {
      map.set(
        question.subject,
        0
      );
    }

    map.set(
      question.subject,
      map.get(
        question.subject
      ) + 1
    );
  }

  return Array.from(
    map.entries()
  )
    .sort(
      ([a], [b]) =>
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
   IMPORT question.json INTO POSTGRESQL
========================================================= */

async function importQuestionsToDatabase() {
  if (!pool) {
    /*
      Local mode does not need to copy the
      question bank into db.json.

      question.json remains the main bank.
    */

    console.log(
      `Local mode: using ${questionBank.length} questions directly from question.json.`
    );

    return;
  }

  let inserted = 0;
  let existing = 0;

  for (
    const question of questionBank
  ) {
    const result =
      await pool.query(
        `
        INSERT INTO questions
          (
            id,
            subject,
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
            $4::jsonb,
            $5,
            $6,
            $7
          )
        ON CONFLICT (id)
        DO UPDATE SET
          subject = EXCLUDED.subject,
          question = EXCLUDED.question,
          options = EXCLUDED.options,
          answer_index = EXCLUDED.answer_index,
          explanation = EXCLUDED.explanation,
          active = EXCLUDED.active
        `,
        [
          question.id,
          question.subject,
          question.question,
          JSON.stringify(
            question.options
          ),
          question.answer_index,
          question.explanation,
          question.active
        ]
      );

    if (
      result.rowCount === 1
    ) {
      inserted++;
    } else {
      existing++;
    }
  }

  console.log(
    `PostgreSQL question synchronization complete. ${questionBank.length} question-bank records processed.`
  );

  /*
    Align SERIAL sequence so that an admin-created
    question cannot receive an ID already used by
    question.json.
  */

  const sequenceResult =
    await pool.query(`
      SELECT
        pg_get_serial_sequence(
          'questions',
          'id'
        ) AS sequence_name
    `);

  const sequenceName =
    sequenceResult
      .rows[0]
      ?.sequence_name;

  if (sequenceName) {
    const maxResult =
      await pool.query(`
        SELECT
          COALESCE(
            MAX(id),
            0
          ) AS max_id
        FROM questions
      `);

    const maxDatabaseId =
      Number(
        maxResult
          .rows[0]
          ?.max_id || 0
      );

    const maxStaticId =
      questionBank.reduce(
        (max, question) =>
          Math.max(
            max,
            Number(
              question.id
            )
          ),
        0
      );

    const nextId =
      Math.max(
        maxDatabaseId,
        maxStaticId
      ) + 1;

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
        nextId
      ]
    );

    console.log(
      `Question sequence aligned. Next database question ID: ${nextId}`
    );
  }
}


/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDb() {
  if (pool) {
    if (!fs.existsSync(
      SCHEMA_FILE
    )) {
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
      Create tables first.
    */

    await pool.query(
      schema
    );

    /*
      Synchronize the actual 10,000+
      question.json bank.
    */

    await importQuestionsToDatabase();

    /*
      Configure admin.
    */

    const adminEmail =
      String(
        process.env.ADMIN_EMAIL ||
          ''
      )
        .trim()
        .toLowerCase();

    const adminPassword =
      String(
        process.env.ADMIN_PASSWORD ||
          ''
      );

    if (
      adminEmail &&
      adminPassword &&
      adminEmail !==
        'admin@example.com'
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

    return;
  }

  /*
    Local fallback.
  */

  console.log(
    'DATABASE_URL not configured. Using local JSON fallback.'
  );
}


/* =========================================================
   EXPRESS SECURITY / MIDDLEWARE
========================================================= */

app.disable(
  'x-powered-by'
);

app.use(
  helmet({
    contentSecurityPolicy:
      false
  })
);

app.use(
  cors({
    origin:
      frontendOrigin,
    credentials: true
  })
);

app.use(
  express.json({
    limit: MAX_BODY,

    verify:
      (
        req,
        res,
        buffer
      ) => {
        req.rawBody =
          buffer;
      }
  })
);

app.use(
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    limit: 300,

    standardHeaders:
      'draft-8',

    legacyHeaders:
      false
  })
);

const authLimiter =
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    limit: 20,

    standardHeaders:
      'draft-8',

    legacyHeaders:
      false
  });


/* =========================================================
   HEALTH
========================================================= */

app.get(
  '/api/health',
  async (
    req,
    res
  ) => {
    try {
      const questions =
        await countQuestions();

      res.json({
        ok: true,

        version:
          '5.0.0',

        database:
          Boolean(pool),

        payments:
          Boolean(
            process.env
              .PAYSTACK_SECRET_KEY
          ),

        questions,

        freeQuestionsPerSubject:
          FREE_QUESTIONS_PER_SUBJECT
      });
    } catch (error) {
      res.status(503).json({
        ok: false,
        database:
          Boolean(pool),
        error:
          'Health check failed.'
      });
    }
  }
);


/* =========================================================
   REGISTER
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
        !String(
          name || ''
        ).trim() ||
        !String(
          email || ''
        ).trim() ||
        !password
      ) {
        return res.status(400).json({
          error:
            'Name, email and password are required.'
        });
      }

      if (
        String(password).length <
        6
      ) {
        return res.status(400).json({
          error:
            'Password must be at least 6 characters.'
        });
      }

      const normalizedEmail =
        String(email)
          .trim()
          .toLowerCase();

      const existing =
        await getUserByEmail(
          normalizedEmail
        );

      if (existing) {
        return res.status(409).json({
          error:
            'Email already registered.'
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
              String(
                name
              ).trim(),
              String(
                university || ''
              ).trim(),
              String(
                country || ''
              ).trim(),
              String(
                level || '200'
              ).trim()
            ]
          );

        const user =
          rows[0];

        return res
          .status(201)
          .json({
            token:
              signUser(user),
            user:
              safeUser(user)
          });
      }

      const user = {
        id:
          generateId(),

        email:
          normalizedEmail,

        password_hash:
          passwordHash,

        name:
          String(
            name
          ).trim(),

        university:
          String(
            university || ''
          ).trim(),

        country:
          String(
            country || ''
          ).trim(),

        level:
          String(
            level || '200'
          ).trim(),

        xp: 0,

        premium:
          false,

        admin:
          false,

        created_at:
          new Date()
            .toISOString()
      };

      db.users.push(
        user
      );

      saveLocalDb();

      return res
        .status(201)
        .json({
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
   LOGIN
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
        String(
          req.body?.email ||
            ''
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password ||
            ''
        );

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
   PROFILE
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
      const {
        name,
        university,
        country,
        level
      } = req.body || {};

      const cleanName =
        String(
          name || ''
        ).trim();

      const cleanUniversity =
        String(
          university || ''
        ).trim();

      const cleanCountry =
        String(
          country || ''
        ).trim();

      const cleanLevel =
        String(
          level || '200'
        ).trim();

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
            safeUser(
              rows[0]
            )
        });
      }

      const user =
        db.users.find(
          item =>
            String(
              item.id
            ) ===
            String(
              req.auth.id
            )
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
      const subjects =
        await getSubjects();

      res.json({
        subjects
      });
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
        Boolean(
          user.premium
        );

      const subject =
        req.query.subject
          ? String(
              req.query.subject
            ).trim()
          : null;

      const random =
        String(
          req.query.random ||
            ''
        ).toLowerCase() ===
        'true';

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

      let questions =
        await getAllQuestions();

      /*
        Subject filter first.
      */

      if (subject) {
        questions =
          questions.filter(
            question =>
              question.subject ===
              subject
          );
      }

      /*
        IMPORTANT:
        FREE LIMIT IS APPLIED BEFORE RANDOMIZATION.

        This prevents:
        ?random=true
        ?limit=1000

        from bypassing the free allowance.
      */

      if (!premium) {
        questions =
          limitFreeQuestions(
            questions
          );
      }

      /*
        Randomize only after
        access restrictions.
      */

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

      let returnedQuestions;

      if (premium) {
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

        returnedQuestions =
          questions.slice(
            offset,
            offset + limit
          );
      } else {
        returnedQuestions =
          questions;
      }

      const total =
        await countQuestions(
          subject
        );

      res.json({
        questions:
          returnedQuestions,

        premium,

        access:
          premium
            ? 'premium'
            : 'free',

        subject:
          subject || null,

        total_available:
          total,

        free_limit:
          FREE_QUESTIONS_PER_SUBJECT,

        returned:
          returnedQuestions.length,

        offset:
          premium
            ? offset
            : 0,

        limit:
          premium
            ? (
                Number.isInteger(
                  requestedLimit
                ) &&
                requestedLimit > 0
                  ? Math.min(
                      requestedLimit,
                      2000
                    )
                  : 2000
              )
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

      /*
        A direct URL must not bypass
        the Free 10-question rule.
      */

      if (!user.premium) {
        const all =
          await getAllQuestions();

        const subjectQuestions =
          all
            .filter(
              item =>
                item.subject ===
                question.subject
            )
            .sort(
              (a, b) =>
                a.id - b.id
            )
            .slice(
              0,
              FREE_QUESTIONS_PER_SUBJECT
            );

        const allowed =
          subjectQuestions.some(
            item =>
              String(
                item.id
              ) ===
              String(
                question.id
              )
          );

        if (!allowed) {
          return res.status(403).json({
            error:
              'This question requires Premium. Free accounts have access to the first 10 questions in each subject.'
          });
        }
      }

      res.json({
        question,

        premium:
          Boolean(
            user.premium
          )
      });
    } catch (error) {
      next(error);
    }
  }
);


/* =========================================================
   QUESTION ACCESS INFORMATION
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

      const subject =
        req.query.subject
          ? String(
              req.query.subject
            ).trim()
          : null;

      const total =
        await countQuestions(
          subject
        );

      res.json({
        premium:
          Boolean(
            user.premium
          ),

        subject,

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
        String(
          req.body?.subject ||
            'General'
        ).trim();

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
            subject ||
              'General',
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

          subject:
            subject ||
            'General',

          score,

          total,

          created_at:
            new Date()
              .toISOString()
        });

        const user =
          db.users.find(
            item =>
              String(
                item.id
              ) ===
              String(
                req.auth.id
              )
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
          await sql(`
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
          `);

        leaderboard =
          leaderboard.map(
            user => ({
              id: user.id,
              name:
                user.name,
              university:
                user.university ||
                '',
              country:
                user.country ||
                '',
              xp:
                Number(
                  user.xp || 0
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
                b.xp -
                  a.xp ||
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
   ADMIN: QUESTIONS
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
        const rows =
          await sql(`
            SELECT *
            FROM questions
            ORDER BY id DESC
          `);

        return res.json({
          questions:
            rows
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


/* =========================================================
   ADMIN: ADD QUESTION
========================================================= */

app.post(
  '/api/admin/questions',
  requireAdmin,
  async (
    req,
    res,
    next
  ) => {
    try {
      const body =
        req.body || {};

      const subject =
        String(
          body.subject || ''
        ).trim();

      const question =
        String(
          body.question || ''
        ).trim();

      const options =
        Array.isArray(
          body.options
        )
          ? body.options.map(
              value =>
                String(value)
            )
          : [];

      const answerIndex =
        Number(
          body.answer_index
        );

      const explanation =
        String(
          body.explanation ||
            ''
        );

      const active =
        body.active !== false;

      if (!subject) {
        return res.status(400).json({
          error:
            'Subject is required.'
        });
      }

      if (!question) {
        return res.status(400).json({
          error:
            'Question text is required.'
        });
      }

      if (
        options.length !== 4
      ) {
        return res.status(400).json({
          error:
            'Exactly four options are required.'
        });
      }

      if (
        !Number.isInteger(
          answerIndex
        ) ||
        answerIndex < 0 ||
        answerIndex > 3
      ) {
        return res.status(400).json({
          error:
            'answer_index must be an integer from 0 to 3.'
        });
      }

      if (pool) {
        const rows =
          await sql(
            `
            INSERT INTO questions
              (
                subject,
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
                $3::jsonb,
                $4,
                $5,
                $6
              )
            RETURNING *
            `,
            [
              subject,
              question,
              JSON.stringify(
                options
              ),
              answerIndex,
              explanation,
              active
            ]
          );

        return res
          .status(201)
          .json({
            question:
              rows[0]
          });
      }

      const newQuestion = {
        id:
          generateId(),

        subject,

        question,

        options,

        answer_index:
          answerIndex,

        explanation,

        active,

        updated_at:
          new Date()
            .toISOString()
      };

      db.questions.push(
        newQuestion
      );

      saveLocalDb();

      res
        .status(201)
        .json({
          question:
            newQuestion
        });
    } catch (error) {
      next(error);
    }
  }
);


/* =========================================================
   ADMIN: UPDATE QUESTION
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

      const body =
        req.body || {};

      if (pool) {
        const currentRows =
          await sql(
            `
            SELECT *
            FROM questions
            WHERE id = $1
            LIMIT 1
            `,
            [id]
          );

        if (!currentRows.length) {
          return res.status(404).json({
            error:
              'Question not found.'
          });
        }

        const current =
          currentRows[0];

        const subject =
          body.subject !== undefined
            ? String(
                body.subject
              ).trim()
            : current.subject;

        const question =
          body.question !== undefined
            ? String(
                body.question
              ).trim()
            : current.question;

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
          body.explanation !==
          undefined
            ? String(
                body.explanation
              )
            : String(
                current.explanation ||
                  ''
              );

        const active =
          body.active !== undefined
            ? Boolean(
                body.active
              )
            : Boolean(
                current.active
              );

        if (
          !subject ||
          !question ||
          !Array.isArray(
            options
          ) ||
          options.length !== 4 ||
          !Number.isInteger(
            answerIndex
          ) ||
          answerIndex < 0 ||
          answerIndex > 3
        ) {
          return res.status(400).json({
            error:
              'Invalid question data.'
          });
        }

        const rows =
          await sql(
            `
            UPDATE questions
            SET
              subject = $1,
              question = $2,
              options = $3::jsonb,
              answer_index = $4,
              explanation = $5,
              active = $6,
              updated_at = NOW()
            WHERE id = $7
            RETURNING *
            `,
            [
              subject,
              question,
              JSON.stringify(
                options
              ),
              answerIndex,
              explanation,
              active,
              id
            ]
          );

        return res.json({
          question:
            rows[0]
        });
      }

      const question =
        db.questions.find(
          item =>
            String(
              item.id
            ) ===
            String(id)
        );

      if (!question) {
        return res.status(404).json({
          error:
            'Question not found.'
        });
      }

      Object.assign(
        question,
        body
      );

      question.updated_at =
        new Date()
          .toISOString();

      saveLocalDb();

      res.json({
        question
      });
    } catch (error) {
      next(error);
    }
  }
);


/* =========================================================
   PAYSTACK: INITIALIZE PAYMENT
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
      if (
        !process.env
          .PAYSTACK_SECRET_KEY
      ) {
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

      /*
        DO NOT accept amount or currency
        from the client.

        The server controls the price.
      */

      const amount =
        PREMIUM_PRICE;

      const currency =
        PREMIUM_CURRENCY;

      const reference =
        'DENEX_' +
        Date.now() +
        '_' +
        crypto
          .randomBytes(5)
          .toString('hex')
          .toUpperCase();

      const response =
        await fetch(
          'https://api.paystack.co/transaction/initialize',
          {
            method:
              'POST',

            headers: {
              Authorization:
                'Bearer ' +
                process.env
                  .PAYSTACK_SECRET_KEY,

              'Content-Type':
                'application/json'
            },

            body:
              JSON.stringify({
                email:
                  user.email,

                amount:
                  Math.round(
                    amount * 100
                  ),

                currency,

                reference,

                metadata: {
                  user_id:
                    String(
                      req.auth.id
                    ),

                  product:
                    'DENexPharm Premium'
                },

                callback_url:
                  process.env
                    .PAYSTACK_CALLBACK_URL ||
                  undefined
              })
          }
        );

      const data =
        await response.json();

      if (
        !response.ok ||
        !data.status ||
        !data.data
      ) {
        return res.status(502).json({
          error:
            data.message ||
            'Payment initialization failed.'
        });
      }

      if (pool) {
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
            new Date()
              .toISOString()
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
   PAYSTACK: VERIFY
========================================================= */

async function verifyPaystack(
  reference
) {
  if (
    !process.env
      .PAYSTACK_SECRET_KEY
  ) {
    throw new Error(
      'Paystack is not configured.'
    );
  }

  const response =
    await fetch(
      'https://api.paystack.co/transaction/verify/' +
        encodeURIComponent(
          reference
        ),
      {
        headers: {
          Authorization:
            'Bearer ' +
            process.env
              .PAYSTACK_SECRET_KEY
        }
      }
    );

  const data =
    await response.json();

  if (
    !response.ok ||
    !data.status ||
    !data.data
  ) {
    throw new Error(
      data.message ||
        'Paystack verification failed.'
    );
  }

  return data.data;
}


/* =========================================================
   PAYSTACK: MARK PREMIUM
========================================================= */

async function markPremium(
  reference,
  paymentData
) {
  if (
    !paymentData ||
    paymentData.status !==
      'success'
  ) {
    return false;
  }

  const metadataUserId =
    paymentData.metadata &&
    paymentData.metadata
      .user_id != null
      ? String(
          paymentData.metadata
            .user_id
        )
      : '';

  if (!metadataUserId) {
    console.error(
      'Payment rejected: missing user_id metadata.'
    );

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
    EXACT amount check.
  */

  if (
    paidAmount !==
      PREMIUM_PRICE ||
    paidCurrency !==
      PREMIUM_CURRENCY
  ) {
    console.error(
      `Payment rejected: expected ${PREMIUM_PRICE} ${PREMIUM_CURRENCY}, received ${paidAmount} ${paidCurrency}.`
    );

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

    /*
      Only mark a payment that was initialized
      by this server.
    */

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
        [reference]
      );

    if (!payments.length) {
      console.error(
        `Payment ${reference} was not found in the local payment records.`
      );

      return false;
    }

    const stored =
      payments[0];

    if (
      Number(
        stored.amount
      ) !==
        PREMIUM_PRICE ||
      String(
        stored.currency
      ).toUpperCase() !==
        PREMIUM_CURRENCY
    ) {
      return false;
    }

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
            reference
        ),

        reference
      ]
    );

    return true;
  }

  /*
    Local fallback.
  */

  const user =
    db.users.find(
      item =>
        String(
          item.id
        ) ===
        metadataUserId
    );

  if (!user) {
    return false;
  }

  const payment =
    db.payments.find(
      item =>
        String(
          item.reference
        ) ===
        String(reference)
    );

  if (!payment) {
    return false;
  }

  if (
    Number(
      payment.amount
    ) !==
      PREMIUM_PRICE ||
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
        reference
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
        String(
          req.query.reference ||
            ''
        ).trim();

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
      if (
        !process.env
          .PAYSTACK_SECRET_KEY
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
          .update(
            rawBody
          )
          .digest('hex');

      const received =
        Buffer.from(
          signature
        );

      const expected =
        Buffer.from(
          expectedSignature
        );

      if (
        received.length !==
        expected.length
      ) {
        return res.sendStatus(
          401
        );
      }

      if (
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
        req.body || {};

      if (
        event.event ===
          'charge.success' &&
        event.data
      ) {
        await markPremium(
          String(
            event.data
              .reference ||
              ''
          ),
          event.data
        );
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
        400
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
  async (
    req,
    res
  ) => {
    res.status(410).json({
      error:
        'The old upgrade endpoint is disabled. Use /api/payments/initialize.'
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


/* =========================================================
   SPA FALLBACK
========================================================= */

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
          ? 'Server error'
          : String(
              error.message ||
                'Server error'
            )
    });
  }
);


/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
  try {
    /*
      Load the actual 10,000-question
      JSON file before the server starts.
    */

    questionBank =
      loadQuestionBank();

    if (
      questionBank.length === 0
    ) {
      throw new Error(
        'question.json contains no valid questions.'
      );
    }

    /*
      Create PostgreSQL tables,
      synchronize question bank,
      configure admin.
    */

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
          `Free questions per subject: ${FREE_QUESTIONS_PER_SUBJECT}`
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
