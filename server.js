"use strict";

/*
============================================================
DENexpharm
FULL STACK PHARMACY LEARNING, GPA, COMPETITION
& STUDENT PLATFORM
============================================================

Version: 3.0.0
Content Year: 2026
Node.js: >=18
Express: 5.x

CORE FEATURES
------------------------------------------------------------
- Authentication
- Student profiles
- International curriculum support
- Pharmacy subjects
- Question bank
- Detailed explanations
- Quiz system
- Quick Battle
- Timed Battle architecture
- Daily Challenge
- XP / Coins / Levels / Streaks
- Achievements
- Leaderboards
- GPA calculator
- Saved GPA records
- Mini Library
- Pharmacopoeia Hub
- Pharmacy Language Assistant
- Bookmarks
- Analytics
- Weak-topic detection
- Referral system
- Wallet
- Premium subscriptions
- Payment architecture
- Payment verification hooks
- Feedback
- Search
- Admin question management
- Admin user management
- Audit logs
- Public statistics
- Persistent JSON database
- Rate limiting
- Security middleware
- Static frontend
- Health endpoint
- Version endpoint

IMPORTANT
------------------------------------------------------------
This is an MVP/full-featured development server.

For serious production scale, replace the JSON database
with PostgreSQL/Supabase/Neon or another proper database.

Real payment verification must be connected to Paystack,
Flutterwave or another trusted payment provider before
premium access is activated in production.
============================================================
*/

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

/* ============================================================
   CONFIGURATION
============================================================ */

const PORT = Number(process.env.PORT) || 3000;

const APP_NAME = "DENexpharm";
const APP_VERSION = "3.0.0";
const CONTENT_YEAR = "2026";

const NODE_ENV =
  process.env.NODE_ENV || "development";

const IS_PRODUCTION =
  NODE_ENV === "production";

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "*";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  "CHANGE_THIS_SESSION_SECRET_IN_PRODUCTION";

const DATA_DIR =
  path.join(__dirname, "data");

const DB_FILE =
  path.join(DATA_DIR, "database.json");

const PUBLIC_DIR =
  path.join(__dirname, "public");

const SESSION_DAYS = 30;
const MAX_PAGE_SIZE = 100;

/* ============================================================
   DATABASE STRUCTURE
============================================================ */

const EMPTY_DATABASE = {
  users: [],
  sessions: [],
  questions: [],
  quizAttempts: [],
  quizResults: [],
  battles: [],
  leaderboards: [],
  achievements: [],
  userAchievements: [],
  dailyChallenges: [],
  wallets: [],
  walletTransactions: [],
  referrals: [],
  subscriptions: [],
  payments: [],
  library: [],
  pharmacopoeia: [],
  languages: [],
  languagePhrases: [],
  feedback: [],
  auditLogs: [],
  gpaRecords: [],
  analytics: [],
  bookmarks: [],
  notifications: []
};

/* ============================================================
   SUBJECTS
============================================================ */

const SUBJECTS = [
  "Pharmacology",
  "Pharmaceutics",
  "Pharmacognosy",
  "Pharmaceutical Microbiology",
  "Pharmaceutical Chemistry",
  "Pharmaceutical Physical Chemistry",
  "Pharmacy Practice",
  "Clinical Pharmacy",
  "Anatomy",
  "Physiology",
  "Biochemistry",
  "Pharmaceutical Entrepreneurship",
  "Public Health",
  "Medicinal Chemistry",
  "Pharmaceutical Analysis",
  "Pharmaceutical Technology",
  "Toxicology",
  "Immunology",
  "Pathophysiology",
  "Drug Delivery Systems",
  "Pharmacotherapy",
  "Hospital Pharmacy",
  "Community Pharmacy",
  "Industrial Pharmacy",
  "Regulatory Pharmacy",
  "Biopharmaceutics",
  "Pharmacokinetics",
  "Clinical Biochemistry",
  "Pharmaceutical Biotechnology",
  "Health Economics",
  "Pharmacy Law and Ethics",
  "Research Methods",
  "Statistics/Biostatistics",
  "Pharmacy Management",
  "Pharmaceutical Calculations"
];

/* ============================================================
   UTILITY FUNCTIONS
============================================================ */

function nowISO() {
  return new Date().toISOString();
}

function addDays(date, days) {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result.toISOString();
}

function todayKey() {
  return new Date()
    .toISOString()
    .slice(0, 10);
}

function generateId(prefix = "id") {
  return (
    prefix +
    "_" +
    Date.now().toString(36) +
    "_" +
    crypto.randomBytes(6).toString("hex")
  );
}

function generateSecureToken() {
  return crypto.randomBytes(48).toString("hex");
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function safeText(value, maxLength = 500) {
  return String(value ?? "")
    .trim()
    .slice(0, maxLength);
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function isValidPassword(password) {
  return (
    typeof password === "string" &&
    password.length >= 6 &&
    password.length <= 200
  );
}

function isValidUsername(username) {
  return /^[a-zA-Z0-9_]{3,30}$/.test(
    username
  );
}

function clampNumber(
  value,
  min,
  max,
  fallback = min
) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return fallback;
  }

  return Math.min(
    max,
    Math.max(min, number)
  );
}

function paginate(
  items,
  page = 1,
  limit = 20
) {
  page = Math.max(
    1,
    Number(page) || 1
  );

  limit = Math.min(
    MAX_PAGE_SIZE,
    Math.max(
      1,
      Number(limit) || 20
    )
  );

  const total = items.length;
  const totalPages =
    Math.max(
      1,
      Math.ceil(total / limit)
    );

  const start =
    (page - 1) * limit;

  return {
    items: items.slice(
      start,
      start + limit
    ),
    page,
    limit,
    total,
    totalPages
  };
}

/* ============================================================
   RESPONSE HELPERS
============================================================ */

function sendSuccess(
  res,
  data = {},
  message = "Success.",
  status = 200
) {
  return res.status(status).json({
    success: true,
    message,
    data
  });
}

function sendError(
  res,
  status = 400,
  message = "Request failed.",
  details = undefined
) {
  const payload = {
    success: false,
    message
  };

  if (details !== undefined) {
    payload.details = details;
  }

  return res
    .status(status)
    .json(payload);
}

/* ============================================================
   DATABASE
============================================================ */

function ensureDatabase() {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, {
        recursive: true
      });
    }

    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(
        DB_FILE,
        JSON.stringify(
          EMPTY_DATABASE,
          null,
          2
        ),
        "utf8"
      );
    }
  } catch (error) {
    console.error(
      "Database initialization error:",
      error
    );

    throw error;
  }
}

function normalizeDatabase(db) {
  const normalized = {
    ...EMPTY_DATABASE,
    ...(db || {})
  };

  Object.keys(
    EMPTY_DATABASE
  ).forEach((key) => {
    if (
      !Array.isArray(
        normalized[key]
      )
    ) {
      normalized[key] = [];
    }
  });

  return normalized;
}

function readDatabase() {
  ensureDatabase();

  try {
    const raw =
      fs.readFileSync(
        DB_FILE,
        "utf8"
      );

    return normalizeDatabase(
      JSON.parse(raw)
    );
  } catch (error) {
    console.error(
      "Database read error:",
      error
    );

    return normalizeDatabase({});
  }
}

function writeDatabase(db) {
  ensureDatabase();

  const normalized =
    normalizeDatabase(db);

  const temporaryFile =
    DB_FILE + ".tmp";

  fs.writeFileSync(
    temporaryFile,
    JSON.stringify(
      normalized,
      null,
      2
    ),
    "utf8"
  );

  fs.renameSync(
    temporaryFile,
    DB_FILE
  );
}

function updateDatabase(callback) {
  const db = readDatabase();

  const result =
    callback(db);

  writeDatabase(db);

  return result;
}

/* ============================================================
   PASSWORD SECURITY
============================================================ */

const PBKDF2_ITERATIONS = 210000;
const PBKDF2_KEY_LENGTH = 64;
const PBKDF2_DIGEST = "sha512";

function hashPassword(password) {
  const salt =
    crypto.randomBytes(32);

  const derivedKey =
    crypto.pbkdf2Sync(
      password,
      salt,
      PBKDF2_ITERATIONS,
      PBKDF2_KEY_LENGTH,
      PBKDF2_DIGEST
    );

  return {
    salt: salt.toString("hex"),
    hash: derivedKey.toString(
      "hex"
    ),
    iterations:
      PBKDF2_ITERATIONS
  };
}

function verifyPassword(
  password,
  stored
) {
  if (
    !stored ||
    !stored.salt ||
    !stored.hash
  ) {
    return false;
  }

  const derivedKey =
    crypto.pbkdf2Sync(
      password,
      Buffer.from(
        stored.salt,
        "hex"
      ),
      stored.iterations ||
        PBKDF2_ITERATIONS,
      PBKDF2_KEY_LENGTH,
      PBKDF2_DIGEST
    );

  const expected =
    Buffer.from(
      stored.hash,
      "hex"
    );

  if (
    expected.length !==
    derivedKey.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    expected,
    derivedKey
  );
}

function secureCompare(
  a,
  b
) {
  const bufferA =
    Buffer.from(String(a));

  const bufferB =
    Buffer.from(String(b));

  if (
    bufferA.length !==
    bufferB.length
  ) {
    return false;
  }

  return crypto.timingSafeEqual(
    bufferA,
    bufferB
  );
}

/* ============================================================
   RATE LIMITER
============================================================ */

const rateLimitStore =
  new Map();

function rateLimit(
  options = {}
) {
  const windowMs =
    options.windowMs ||
    15 * 60 * 1000;

  const max =
    options.max || 300;

  return (req, res, next) => {
    const ip =
      req.ip ||
      req.socket?.remoteAddress ||
      "unknown";

    const key =
      `${ip}:${req.path}`;

    const current =
      Date.now();

    let record =
      rateLimitStore.get(key);

    if (
      !record ||
      current - record.start >
        windowMs
    ) {
      record = {
        start: current,
        count: 0
      };
    }

    record.count += 1;

    rateLimitStore.set(
      key,
      record
    );

    if (record.count > max) {
      return sendError(
        res,
        429,
        "Too many requests. Please try again later."
      );
    }

    next();
  };
}

/* ============================================================
   USERS
============================================================ */

function getUserById(
  db,
  id
) {
  return db.users.find(
    (user) => user.id === id
  );
}

function getPublicUser(user) {
  if (!user) {
    return null;
  }

  return {
    id: user.id,
    username: user.username,
    displayName:
      user.displayName,
    email: user.email,
    country: user.country,
    institution:
      user.institution,
    curriculum:
      user.curriculum,
    yearLevel:
      user.yearLevel,
    semester:
      user.semester,
    xp: user.xp || 0,
    coins: user.coins || 0,
    level: user.level || 1,
    streak: user.streak || 0,
    questionsAnswered:
      user.questionsAnswered || 0,
    correctAnswers:
      user.correctAnswers || 0,
    quizzesCompleted:
      user.quizzesCompleted || 0,
    battlesWon:
      user.battlesWon || 0,
    battlesPlayed:
      user.battlesPlayed || 0,
    createdAt:
      user.createdAt,
    lastActiveAt:
      user.lastActiveAt
  };
}

function ensureUserDefaults(
  user
) {
  if (!user) {
    return;
  }

  user.xp =
    Number(user.xp) || 0;

  user.coins =
    Number(user.coins) || 0;

  user.level =
    Number(user.level) || 1;

  user.streak =
    Number(user.streak) || 0;

  user.questionsAnswered =
    Number(
      user.questionsAnswered
    ) || 0;

  user.correctAnswers =
    Number(
      user.correctAnswers
    ) || 0;

  user.quizzesCompleted =
    Number(
      user.quizzesCompleted
    ) || 0;

  user.battlesWon =
    Number(
      user.battlesWon
    ) || 0;

  user.battlesPlayed =
    Number(
      user.battlesPlayed
    ) || 0;

  user.referralCode =
    user.referralCode ||
    `DEN-${String(
      user.username || "USER"
    )
      .replace(/[^a-zA-Z0-9]/g, "")
      .slice(0, 10)
      .toUpperCase()}-${crypto
      .randomBytes(3)
      .toString("hex")
      .toUpperCase()}`;
}

function calculateLevel(xp) {
  return Math.max(
    1,
    Math.floor(
      Math.sqrt(
        Math.max(0, xp) / 100
      )
    ) + 1
  );
}

function awardXPAndCoins(
  userId,
  xp,
  coins,
  reason = "Reward"
) {
  const db = readDatabase();

  const user =
    getUserById(
      db,
      userId
    );

  if (!user) {
    return null;
  }

  ensureUserDefaults(user);

  const oldLevel =
    user.level;

  user.xp += Math.max(
    0,
    Number(xp) || 0
  );

  user.coins += Math.max(
    0,
    Number(coins) || 0
  );

  user.level =
    calculateLevel(
      user.xp
    );

  const wallet =
    db.wallets.find(
      (item) =>
        item.userId ===
        userId
    );

  if (wallet) {
    wallet.balance =
      user.coins;

    wallet.lifetimeEarned =
      Number(
        wallet.lifetimeEarned
      ) +
      Math.max(
        0,
        Number(coins) || 0
      );

    wallet.updatedAt =
      nowISO();
  }

  if (
    Number(coins) > 0
  ) {
    db.walletTransactions.push(
      {
        id: generateId(
          "wallet_tx"
        ),
        userId,
        type: "credit",
        amount:
          Number(coins),
        reason,
        createdAt:
          nowISO()
      }
    );
  }

  if (
    user.level > oldLevel
  ) {
    db.notifications.push({
      id: generateId(
        "notification"
      ),
      userId,
      type: "level_up",
      title:
        "Level Up!",
      message:
        `Congratulations! You reached level ${user.level}.`,
      read: false,
      createdAt:
        nowISO()
    });
  }

  writeDatabase(db);

  return user;
}

/* ============================================================
   ACTIVITY / STREAK
============================================================ */

function updateUserActivity(
  userId
) {
  const db = readDatabase();

  const user =
    getUserById(
      db,
      userId
    );

  if (!user) {
    return null;
  }

  ensureUserDefaults(user);

  const today =
    todayKey();

  const lastActive =
    user.lastActivityDate;

  if (
    lastActive !== today
  ) {
    if (lastActive) {
      const previous =
        new Date(
          `${lastActive}T00:00:00Z`
        );

      const current =
        new Date(
          `${today}T00:00:00Z`
        );

      const difference =
        Math.round(
          (
            current -
            previous
          ) /
            86400000
        );

      if (
        difference === 1
      ) {
        user.streak += 1;
      } else {
        user.streak = 1;
      }
    } else {
      user.streak = 1;
    }

    user.lastActivityDate =
      today;

    user.lastActiveAt =
      nowISO();

    writeDatabase(db);

    checkAchievements(
      userId
    );
  }

  return user;
}

/* ============================================================
   SESSIONS / AUTHENTICATION
============================================================ */

function createSession(
  userId
) {
  const db = readDatabase();

  const rawToken =
    generateSecureToken();

  const tokenHash =
    sha256(
      rawToken
    );

  const session = {
    id: generateId(
      "session"
    ),
    userId,
    tokenHash,
    createdAt: nowISO(),
    expiresAt:
      addDays(
        new Date(),
        SESSION_DAYS
      )
  };

  db.sessions.push(
    session
  );

  writeDatabase(db);

  return rawToken;
}

function getBearerToken(req) {
  const header =
    req.headers.authorization ||
    "";

  if (
    !header.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return header.slice(7).trim();
}

function getAuthenticatedUser(
  req
) {
  const token =
    getBearerToken(req);

  if (!token) {
    return null;
  }

  const db = readDatabase();

  const tokenHash =
    sha256(token);

  const session =
    db.sessions.find(
      (item) =>
        item.tokenHash ===
          tokenHash &&
        new Date(
          item.expiresAt
        ) > new Date()
    );

  if (!session) {
    return null;
  }

  const user =
    getUserById(
      db,
      session.userId
    );

  if (!user) {
    return null;
  }

  ensureUserDefaults(user);

  return user;
}

function authRequired(
  req,
  res,
  next
) {
  const user =
    getAuthenticatedUser(
      req
    );

  if (!user) {
    return sendError(
      res,
      401,
      "Authentication required."
    );
  }

  req.user = user;

  next();
}

function adminRequired(
  req,
  res,
  next
) {
  if (
    !req.user ||
    req.user.role !==
      "admin"
  ) {
    return sendError(
      res,
      403,
      "Administrator access required."
    );
  }

  next();
}

/* ============================================================
   ACHIEVEMENTS
============================================================ */

function checkAchievements(
  userId
) {
  const db = readDatabase();

  const user =
    getUserById(
      db,
      userId
    );

  if (!user) {
    return;
  }

  ensureUserDefaults(user);

  const unlocked =
    new Set(
      db.userAchievements
        .filter(
          (item) =>
            item.userId ===
            userId
        )
        .map(
          (item) =>
            item.achievementId
        )
    );

  const conditions = [
    {
      id: "first_quiz",
      condition:
        user.quizzesCompleted >= 1
    },
    {
      id: "questions_10",
      condition:
        user.questionsAnswered >= 10
    },
    {
      id: "questions_100",
      condition:
        user.questionsAnswered >= 100
    },
    {
      id: "perfect_score",
      condition:
        user.lastPerfectScore === true
    },
    {
      id: "streak_7",
      condition:
        user.streak >= 7
    },
    {
      id: "streak_30",
      condition:
        user.streak >= 30
    }
  ];

  let changed = false;

  for (
    const condition of conditions
  ) {
    if (
      condition.condition &&
      !unlocked.has(
        condition.id
      )
    ) {
      db.userAchievements.push({
        id: generateId(
          "userachievement"
        ),
        userId,
        achievementId:
          condition.id,
        unlockedAt:
          nowISO()
      });

      db.notifications.push({
        id: generateId(
          "notification"
        ),
        userId,
        type:
          "achievement",
        title:
          "Achievement Unlocked!",
        message:
          `You unlocked ${condition.id}.`,
        read: false,
        createdAt:
          nowISO()
      });

      changed = true;
    }
  }

  if (changed) {
    writeDatabase(db);
  }
}

/* ============================================================
   QUESTIONS
============================================================ */

function sanitizeQuestion(
  question
) {
  if (!question) {
    return null;
  }

  return {
    id: question.id,
    question:
      question.question,
    options:
      question.options || [],
    subject:
      question.subject,
    topic:
      question.topic,
    difficulty:
      question.difficulty,
    curriculum:
      question.curriculum,
    yearLevel:
      question.yearLevel,
    semester:
      question.semester,
    tags:
      question.tags || [],
    references:
      question.references || [],
    createdAt:
      question.createdAt
  };
}

function sanitizeQuestionWithAnswer(
  question
) {
  if (!question) {
    return null;
  }

  return {
    ...sanitizeQuestion(
      question
    ),
    answer:
      question.answer,
    explanation:
      question.explanation,
    whyCorrect:
      question.whyCorrect ||
      "",
    optionExplanations:
      question.optionExplanations ||
      {},
    learningPoints:
      question.learningPoints ||
      []
  };
}

function findQuestion(
  db,
  id
) {
  return db.questions.find(
    (question) =>
      question.id === id
  );
}

function calculateQuizScore(
  questions,
  answers
) {
  let correct = 0;

  questions.forEach(
    (question, index) => {
      const submitted =
        answers?.[index];

      if (
        String(
          submitted ?? ""
        ).trim().toLowerCase() ===
        String(
          question.answer
        )
          .trim()
          .toLowerCase()
      ) {
        correct++;
      }
    }
  );

  const total =
    questions.length;

  const percentage =
    total > 0
      ? Number(
          (
            (correct / total) *
            100
          ).toFixed(2)
        )
      : 0;

  return {
    correct,
    total,
    percentage
  };
}

function selectQuestions(
  db,
  options = {}
) {
  let questions =
    [...db.questions];

  if (
    options.subject
  ) {
    questions =
      questions.filter(
        (q) =>
          q.subject
            .toLowerCase() ===
          String(
            options.subject
          )
            .toLowerCase()
      );
  }

  if (
    options.topic
  ) {
    questions =
      questions.filter(
        (q) =>
          String(
            q.topic || ""
          )
            .toLowerCase()
            .includes(
              String(
                options.topic
              ).toLowerCase()
            )
      );
  }

  if (
    options.difficulty
  ) {
    questions =
      questions.filter(
        (q) =>
          String(
            q.difficulty
          ).toLowerCase() ===
          String(
            options.difficulty
          ).toLowerCase()
      );
  }

  if (
    options.curriculum
  ) {
    questions =
      questions.filter(
        (q) =>
          String(
            q.curriculum
          ).toLowerCase() ===
          String(
            options.curriculum
          ).toLowerCase()
      );
  }

  for (
    let i =
      questions.length - 1;
    i > 0;
    i--
  ) {
    const j =
      Math.floor(
        Math.random() *
          (i + 1)
      );

    [
      questions[i],
      questions[j]
    ] = [
      questions[j],
      questions[i]
    ];
  }

  return questions;
}

/* ============================================================
   DAILY CHALLENGE
============================================================ */

function getDailyChallenge() {
  const db = readDatabase();

  const key =
    todayKey();

  let challenge =
    db.dailyChallenges.find(
      (item) =>
        item.date === key
    );

  if (!challenge) {
    const questions =
      selectQuestions(
        db
      ).slice(0, 10);

    challenge = {
      id: generateId(
        "daily"
      ),
      date: key,
      questionIds:
        questions.map(
          (q) => q.id
        ),
      rewardXP: 100,
      rewardCoins: 25,
      createdAt:
        nowISO()
    };

    db.dailyChallenges.push(
      challenge
    );

    writeDatabase(db);
  }

  return challenge;
}

/* ============================================================
   SUBSCRIPTIONS
============================================================ */

function getActiveSubscription(
  userId
) {
  const db = readDatabase();

  const now =
    new Date();

  const subscription =
    db.subscriptions
      .filter(
        (item) =>
          item.userId ===
            userId &&
          item.status ===
            "active" &&
          new Date(
            item.expiresAt
          ) > now
      )
      .sort(
        (a, b) =>
          new Date(
            b.expiresAt
          ) -
          new Date(
            a.expiresAt
          )
      )[0];

  return subscription || null;
}

function isPremiumUser(
  userId
) {
  return Boolean(
    getActiveSubscription(
      userId
    )
  );
}

/* ============================================================
   SEED CONTENT
============================================================ */

function seedContent() {
  const db = readDatabase();

  if (
    db.questions.length === 0
  ) {
    db.questions.push(
      {
        id: generateId(
          "question"
        ),
        question:
          "Which receptor type is primarily responsible for the muscarinic effects of acetylcholine?",
        options: [
          "Muscarinic receptor",
          "Nicotinic receptor",
          "Alpha-1 receptor",
          "Beta-2 receptor"
        ],
        answer:
          "Muscarinic receptor",
        explanation:
          "Muscarinic receptors are G-protein-coupled cholinergic receptors that mediate many parasympathetic effects of acetylcholine.",
        whyCorrect:
          "Muscarinic receptors are activated by acetylcholine at many postganglionic parasympathetic target organs.",
        optionExplanations: {
          "Muscarinic receptor":
            "Correct. Muscarinic receptors mediate many parasympathetic responses.",
          "Nicotinic receptor":
            "Nicotinic receptors are ligand-gated ion channels found at autonomic ganglia and the neuromuscular junction.",
          "Alpha-1 receptor":
            "Alpha-1 receptors are adrenergic receptors activated mainly by norepinephrine and epinephrine.",
          "Beta-2 receptor":
            "Beta-2 receptors are adrenergic receptors associated with effects such as bronchodilation."
        },
        learningPoints: [
          "Muscarinic receptors are cholinergic receptors.",
          "They are G-protein-coupled receptors.",
          "They mediate many parasympathetic effects."
        ],
        subject:
          "Pharmacology",
        topic:
          "Cholinergic Pharmacology",
        difficulty:
          "easy",
        curriculum:
          "International",
        yearLevel:
          "200 Level",
        semester:
          "Any",
        tags: [
          "acetylcholine",
          "muscarinic",
          "receptors"
        ],
        references: [
          "Standard pharmacology textbooks",
          "Basic and Clinical Pharmacology"
        ],
        createdAt:
          nowISO()
      },
      {
        id: generateId(
          "question"
        ),
        question:
          "How many grams of a substance are required to prepare 200 mL of a 5% w/v solution?",
        options: [
          "5 g",
          "10 g",
          "20 g",
          "25 g"
        ],
        answer:
          "10 g",
        explanation:
          "A 5% w/v solution contains 5 g of solute in every 100 mL of solution. Therefore, 200 mL requires 10 g.",
        whyCorrect:
          "5 g/100 mL × 200 mL = 10 g.",
        optionExplanations: {
          "5 g":
            "This would correspond to 100 mL of a 5% w/v solution.",
          "10 g":
            "Correct. 5 × 200 / 100 = 10 g.",
          "20 g":
            "This would produce a 10% w/v concentration in 200 mL.",
          "25 g":
            "This would not correspond to a 5% w/v solution."
        },
        learningPoints: [
          "Percentage w/v means grams per 100 mL.",
          "Use proportion to scale solution quantities
