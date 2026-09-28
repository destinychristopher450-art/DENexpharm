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

const isProduction =
  process.env.NODE_ENV === 'production';

const JWT_SECRET =
  process.env.JWT_SECRET ||
  (isProduction
    ? ''
    : 'DENexPharm-development-secret-change-me');

const MAX_BODY =
  process.env.MAX_BODY || '1mb';

const FREE_QUESTIONS_PER_SUBJECT = 10;

const PREMIUM_PRICE = Number(
  process.env.PREMIUM_PRICE || 5000
);

const PREMIUM_CURRENCY = String(
  process.env.PREMIUM_CURRENCY || 'NGN'
)
  .trim()
  .toUpperCase();

const PRACTICE_LEVELS = [
  '100',
  '200',
  '300',
  '400',
  '500',
  '600'
];

const frontendOrigin =
  process.env.FRONTEND_ORIGIN
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
  if (
    !JWT_SECRET ||
    JWT_SECRET.length < 32
  ) {
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
    JSON.stringify(
      DEFAULT_DB,
      null,
      2
    ),
    'utf8'
  );
}

function loadLocalDb() {
  try {
    const data =
      JSON.parse(
        fs.readFileSync(
          DB_FILE,
          'utf8'
        )
      );

    for (
      const key of Object.keys(
        DEFAULT_DB
      )
    ) {
      if (
        !Array.isArray(
          data[key]
        )
      ) {
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
      JSON.stringify(
        DEFAULT_DB,
        null,
        2
      ),
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
    JSON.stringify(
      db,
      null,
      2
    ),
    'utf8'
  );
}


/* =========================================================
   POSTGRESQL
========================================================= */

const pool =
  process.env.DATABASE_URL
    ? new Pool({
        connectionString:
          process.env.DATABASE_URL,

        ssl:
          process.env.DATABASE_SSL ===
          'false'
            ? false
            : {
                rejectUnauthorized:
                  false
              },

        max: Math.max(
          1,
          Number(
            process.env.DB_POOL_MAX ||
              10
          )
        )
      })
    : null;

async function sql(
  query,
  params = []
) {
  if (!pool) {
    return [];
  }

  const result =
    await pool.query(
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

function cleanString(
  value,
  fallback = ''
) {
  return String(
    value ?? fallback
  ).trim();
}

function normalizeCountry(
  value
) {
  const country =
    cleanString(value);

  return country || 'Nigeria';
}

function normalizeLevel(
  value
) {
  const level =
    cleanString(value);

  if (
    PRACTICE_LEVELS.includes(
      level
    )
  ) {
    return level;
  }

  return '200';
}

function normalizeTopic(
  value
) {
  return (
    cleanString(value) ||
    'General'
  );
}

function safeUser(user) {
  return {
    id: user.id,
    email: user.email,
    name: user.name,
    university:
      user.university || '',
    country:
      user.country || '',
    level:
      user.level || '200',
    xp:
      Number(user.xp || 0),
    premium:
      Boolean(user.premium),
    admin:
      Boolean(user.admin)
  };
}

function signUser(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      admin: Boolean(
        user.admin
      )
    },
    JWT_SECRET,
    {
      expiresIn: '30d'
    }
  );
}

function getTokenFromRequest(
  req
) {
  const header =
    req.get('authorization') ||
    '';

  if (
    !header.startsWith(
      'Bearer '
    )
  ) {
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
  const auth =
    authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error:
        'Sign in required'
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
  const auth =
    authenticate(req);

  if (!auth) {
    return res.status(401).json({
      error:
        'Sign in required'
    });
  }

  try {
    const user =
      await getUserById(
        auth.id
      );

    if (
      !user ||
      !user.admin
    ) {
      return res.status(403).json({
        error:
          'Admin access required'
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
   QUESTION NORMALIZATION
========================================================= */

function normalizeQuestion(
  question,
  fallbackId
) {
  if (
    !question ||
    typeof question !==
      'object'
  ) {
    return null;
  }

  const numericId =
    Number(
      question.id ??
        fallbackId
    );

  const country =
    normalizeCountry(
      question.country
    );

  const level =
    normalizeLevel(
      question.level
    );

  const subject =
    cleanString(
      question.subject
    );

  const topic =
    normalizeTopic(
      question.topic
    );

  const questionText =
    cleanString(
      question.question
    );

  const options =
    Array.isArray(
      question.options
    )
      ? question.options.map(
          value =>
            String(value)
        )
      : [];

  const answerIndex =
    Number(
      question.answer_index
    );

  if (
    !Number.isInteger(
      numericId
    ) ||
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

  if (
    options.length !== 4
  ) {
    return null;
  }

  if (
    !Number.isInteger(
      answerIndex
    ) ||
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

    question:
      questionText,

    options,

    answer_index:
      answerIndex,

    explanation:
      cleanString(
        question.explanation
      ),

    active:
      question.active !== false
  };
}


/* =========================================================
   LOAD QUESTION BANK
========================================================= */

function loadQuestionBank() {
  if (
    !fs.existsSync(
      QUESTION_FILE
    )
  ) {
    throw new Error(
      'question.json was not found. Place question.json beside server.js.'
    );
  }

  let parsed;

  try {
    parsed =
      JSON.parse(
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

  if (
    !Array.isArray(parsed)
  ) {
    throw new Error(
      'question.json must contain a JSON array.'
    );
  }

  const seenIds =
    new Set();

  const validQuestions =
    [];

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
   LOCAL QUESTIONS
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


/* =========================================================
   SHUFFLE
========================================================= */

function shuffle(array) {
  const result = [
    ...array
  ];

  for (
    let i =
      result.length - 1;
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


/* =========================================================
   FILTER HELPERS
========================================================= */

function applyQuestionFilters(
  questions,
  filters = {}
) {
  const country =
    filters.country
      ? normalizeCountry(
          filters.country
        )
      : null;

  const level =
    filters.level
      ? normalizeLevel(
          filters.level
        )
      : null;

  const subject =
    filters.subject
      ? cleanString(
          filters.subject
        )
      : null;

  const topic =
    filters.topic
      ? cleanString(
          filters.topic
        )
      : null;

  return questions.filter(
    question => {
      if (
        country &&
        question.country
          .toLowerCase() !==
          country.toLowerCase()
      ) {
        return false;
      }

      if (
        level &&
        question.level !==
          level
      ) {
        return false;
      }

      if (
        subject &&
        question.subject !==
          subject
      ) {
        return false;
      }

      if (
        topic &&
        question.topic !==
          topic
      ) {
        return false;
      }

      return true;
    }
  );
}


/* =========================================================
   FREE QUESTION LIMIT
========================================================= */

function limitFreeQuestions(
  questions
) {
  /*
    The request is already scoped by
    country + level + subject/topic.

    We still group by subject so that
    a future multi-subject request cannot
    accidentally expose more than the
    configured free amount per subject.
  */

  const grouped =
    new Map();

  for (
    const question of questions
  ) {
    const key =
      [
        question.country,
        question.level,
        question.subject
      ]
        .join('|')
        .toLowerCase();

    if (
      !grouped.has(key)
    ) {
      grouped.set(
        key,
        []
      );
    }

    grouped
      .get(key)
      .push(question);
  }

  const result = [];

  for (
    const group of
      grouped.values()
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
  if (pool) {
    const rows =
      await sql(`
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
      .map(
        row =>
          normalizeQuestion(
            row,
            row.id
          )
      )
      .filter(Boolean);
  }

  const merged =
    new Map();

  for (
    const question of
      questionBank
  ) {
    if (
      question.active !== false
    ) {
      merged.set(
        String(
          question.id
        ),
        question
      );
    }
  }

  for (
    const question of
      getLocalQuestions()
  ) {
    merged.set(
      String(
        question.id
      ),
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


/* =========================================================
   GET ONE QUESTION
========================================================= */

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
        String(
          user.id
        ) ===
        String(userId)
    ) || null
  );
}

async function getUserByEmail(
  email
) {
  const normalized =
    cleanString(email)
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
   COUNT QUESTIONS
========================================================= */

async function countQuestions(
  filters = {}
) {
  if (pool) {
    const conditions = [
      'active = true'
    ];

    const params = [];

    if (filters.country) {
      params.push(
        normalizeCountry(
          filters.country
        )
      );

      conditions.push(
        `LOWER(country) = LOWER($${params.length})`
      );
    }

    if (filters.level) {
      params.push(
        normalizeLevel(
          filters.level
        )
      );

      conditions.push(
        `level = $${params.length}`
      );
    }

    if (filters.subject) {
      params.push(
        cleanString(
          filters.subject
        )
      );

      conditions.push(
        `subject = $${params.length}`
      );
    }

    if (filters.topic) {
      params.push(
        cleanString(
          filters.topic
        )
      );

      conditions.push(
        `topic = $${params.length}`
      );
    }

    const rows =
      await sql(
        `
        SELECT COUNT(*)::int AS count
        FROM questions
        WHERE ${conditions.join(
          ' AND '
        )}
        `,
        params
      );

    return Number(
      rows[0]?.count || 0
    );
  }

  return applyQuestionFilters(
    getLocalQuestions(),
    filters
  ).length;
}


/* =========================================================
   SUBJECTS
========================================================= */

async function getSubjects(
  filters = {}
) {
  const questions =
    applyQuestionFilters(
      await getAllQuestions(),
      filters
    );

  const map =
    new Map();

  for (
    const question of
      questions
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
        total_questions:
          count,
        free_questions:
          Math.min(
            count,
            FREE_QUESTIONS_PER_SUBJECT
          )
      })
    );
}


/* =========================================================
   QUESTION FILTER OPTIONS
========================================================= */

async function getQuestionFilters() {
  const questions =
    await getAllQuestions();

  const countries =
    new Set();

  const levels =
    new Set();

  const subjects =
    new Set();

  const topics =
    new Set();

  for (
    const question of
      questions
  ) {
    if (question.country) {
      countries.add(
        question.country
      );
    }

    if (question.level) {
      levels.add(
        question.level
      );
    }

    if (question.subject) {
      subjects.add(
        question.subject
      );
    }

    if (question.topic) {
      topics.add(
        question.topic
      );
    }
  }

  /*
    Always expose the six requested
    pharmacy academic levels, even if
    the current bank has no questions
    for one of them yet.
  */

  const sortedLevels =
    PRACTICE_LEVELS.filter(
      level =>
        levels.has(level)
    );

  /*
    If no questions currently exist
    for a level, the frontend can still
    display it and return zero questions.
  */

  for (
    const level of
      PRACTICE_LEVELS
  ) {
    if (
      !sortedLevels.includes(
        level
      )
    ) {
      sortedLevels.push(
        level
      );
    }
  }

  return {
    countries:
      Array.from(
        countries
      ).sort(
        (a, b) =>
          a.localeCompare(b)
      ),

    levels:
      sortedLevels,

    subjects:
      Array.from(
        subjects
      ).sort(
        (a, b) =>
          a.localeCompare(b)
      ),

    topics:
      Array.from(
        topics
      ).sort(
        (a, b) =>
          a.localeCompare(b)
      )
  };
}


/* =========================================================
   IMPORT QUESTION BANK INTO POSTGRES
========================================================= */

async function importQuestionsToDatabase() {
  if (!pool) {
    console.log(
      `Local mode: using ${questionBank.length} questions directly from question.json.`
    );

    return;
  }

  for (
    const question of
      questionBank
  ) {
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
          NOW()
        )
      ON CONFLICT (id)
      DO UPDATE SET
        country =
          EXCLUDED.country,

        level =
          EXCLUDED.level,

        subject =
          EXCLUDED.subject,

        topic =
          EXCLUDED.topic,

        question =
          EXCLUDED.question,

        options =
          EXCLUDED.options,

        answer_index =
          EXCLUDED.answer_index,

        explanation =
          EXCLUDED.explanation,

        active =
          EXCLUDED.active,

        updated_at =
          NOW()
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
  }

  /*
    Align PostgreSQL sequence with
    the highest question ID.
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

    const maxId =
      Number(
        maxResult.rows[0]
          ?.max_id || 0
      );

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
    `PostgreSQL question synchronization complete: ${questionBank.length} records processed.`
  );
}


/* =========================================================
   DATABASE MIGRATION
========================================================= */

async function migrateQuestionColumns() {
  if (!pool) {
    return;
  }

  /*
    This protects an existing Render/PostgreSQL
    database whose questions table was created
    using the older schema.
  */

  await pool.query(`
    ALTER TABLE questions
      ADD COLUMN IF NOT EXISTS
        country TEXT
        DEFAULT 'Nigeria'
  `);

  await pool.query(`
    ALTER TABLE questions
      ADD COLUMN IF NOT EXISTS
        level TEXT
        DEFAULT '200'
  `);

  await pool.query(`
    ALTER TABLE questions
      ADD COLUMN IF NOT EXISTS
        topic TEXT
        DEFAULT 'General'
  `);

  await pool.query(`
    UPDATE questions
    SET country = 'Nigeria'
    WHERE country IS NULL
       OR TRIM(country) = ''
  `);

  await pool.query(`
    UPDATE questions
    SET level = '200'
    WHERE level IS NULL
       OR TRIM(level) = ''
  `);

  await pool.query(`
    UPDATE questions
    SET topic = 'General'
    WHERE topic IS NULL
       OR TRIM(topic) = ''
  `);

  await pool.query(`
    ALTER TABLE questions
      ALTER COLUMN country
      SET DEFAULT 'Nigeria'
  `);

  await pool.query(`
    ALTER TABLE questions
      ALTER COLUMN level
      SET DEFAULT '200'
  `);

  await pool.query(`
    ALTER TABLE questions
      ALTER COLUMN topic
      SET DEFAULT 'General'
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      questions_country_level_subject_idx
    ON questions(
      country,
      level,
      subject
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      questions_country_level_topic_idx
    ON questions(
      country,
      level,
      topic
    )
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      questions_subject_idx
    ON questions(subject)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS
      questions_active_idx
    ON questions(active)
  `);

  console.log(
    'Question table migration completed.'
  );
}


/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initDb() {
  if (pool) {
    if (
      !fs.existsSync(
        SCHEMA_FILE
      )
    ) {
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
      Create missing tables.
    */

    await pool.query(
      schema
    );

    /*
      Upgrade an existing questions
      table if it was created with
      the old schema.
    */

    await migrateQuestionColumns();

    /*
      Import/synchronize question.json.
    */

    await importQuestionsToDatabase();

    /*
      Configure admin.
    */

    const adminEmail =
      cleanString(
        process.env.ADMIN_EMAIL
      ).toLowerCase();

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

  console.log(
    'DATABASE_URL not configured. Using local JSON fallback.'
  );
}


/* =========================================================
   EXPRESS SECURITY
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
          '6.0.0',

        database:
          Boolean(pool),

        payments:
          Boolean(
            process.env
              .PAYSTACK_SECRET_KEY
          ),

        questions,

        freeQuestionsPerSubject:
          FREE_QUESTIONS_PER_SUBJECT,

        premiumPrice:
          PREMIUM_PRICE,

        premiumCurrency:
          PREMIUM_CURRENCY,

        practiceLevels:
          PRACTICE_LEVELS
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
   PREMIUM INFORMATION
========================================================= */

app.get(
  '/api/premium/info',
  (
    req,
    res
  ) => {
    res.json({
      price:
        PREMIUM_PRICE,

      currency:
        PREMIUM_CURRENCY,

      freeQuestionsPerSubject:
        FREE_QUESTIONS_PER_SUBJECT,

      features: [
        'Expanded question access',
        'Country and level question banks',
        'More practice questions',
        'Mock examination access',
        'Performance analytics'
      ]
    });
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
        !cleanString(name) ||
        !cleanString(email) ||
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
        cleanString(
          email
        ).toLowerCase();

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

      const userCountry =
        cleanString(
          country
        );

      const userLevel =
        cleanString(
          level || '200'
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
              cleanString(
                name
              ),
              cleanString(
                university
              ),
              userCountry,
              userLevel
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
          cleanString(name),

        university:
          cleanString(
            university
          ),

        country:
          userCountry,

        level:
          userLevel,

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
        cleanString(
          req.body?.email
        ).toLowerCase();

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
