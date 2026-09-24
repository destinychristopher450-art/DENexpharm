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
          "Percentage w/v means grams per 100 mL of solution.",
          "Use proportion to scale solution quantities.",
          "A 5% w/v solution contains 5 g in every 100 mL."
        ],
        subject: "Pharmaceutical Calculations",
        topic: "Percentage Strength",
        difficulty: "easy",
        curriculum: "International",
        yearLevel: "200 Level",
        semester: "Any",
        tags: ["percentage", "w/v", "calculations"],
        references: [
          "Standard pharmaceutical calculations textbooks"
        ],
        createdAt: nowISO()
      });

      db.questions.push({
        id: generateId("question"),
        question: "Which method is commonly used to sterilize heat-stable aqueous pharmaceutical preparations?",
        options: [
          "Autoclaving",
          "Filtration",
          "Ultraviolet radiation",
          "Dry storage"
        ],
        answer: "Autoclaving",
        explanation:
          "Autoclaving uses saturated steam under pressure and is commonly used for sterilizing suitable heat-stable aqueous preparations and materials.",
        whyCorrect:
          "Moist heat under pressure effectively destroys microorganisms, including many bacterial spores.",
        optionExplanations: {
          "Autoclaving":
            "Correct. Steam under pressure provides effective moist-heat sterilization.",
          "Filtration":
            "Filtration is useful for heat-sensitive liquids but does not destroy microorganisms.",
          "Ultraviolet radiation":
            "UV radiation has limited penetration and is mainly useful for surface or air disinfection.",
          "Dry storage":
            "Dry storage is not a sterilization method."
        },
        learningPoints: [
          "Autoclaving is a moist-heat sterilization method.",
          "Steam pressure raises the temperature above the normal boiling point.",
          "Sterilization parameters depend on the material and validated process."
        ],
        subject: "Pharmaceutical Microbiology",
        topic: "Sterilization",
        difficulty: "easy",
        curriculum: "International",
        yearLevel: "200 Level",
        semester: "Any",
        tags: ["sterilization", "autoclave", "microbiology"],
        references: [
          "Standard pharmaceutical microbiology textbooks"
        ],
        createdAt: nowISO()
      });

      db.questions.push({
        id: generateId("question"),
        question:
          "Which organ is primarily responsible for the metabolism of many drugs?",
        options: [
          "Liver",
          "Spleen",
          "Pancreas",
          "Thyroid"
        ],
        answer: "Liver",
        explanation:
          "The liver contains numerous enzymes involved in Phase I and Phase II drug metabolism.",
        whyCorrect:
          "Hepatic enzymes, particularly cytochrome P450 enzymes, metabolize many drugs.",
        optionExplanations: {
          "Liver":
            "Correct. The liver is the major organ involved in metabolism of many drugs.",
          "Spleen":
            "The spleen is primarily involved in immune and hematological functions.",
          "Pancreas":
            "The pancreas has major digestive and endocrine functions.",
          "Thyroid":
            "The thyroid primarily produces thyroid hormones."
        },
        learningPoints: [
          "Drug metabolism commonly occurs in the liver.",
          "Phase I reactions include oxidation, reduction and hydrolysis.",
          "Phase II reactions commonly involve conjugation."
        ],
        subject: "Pharmacology",
        topic: "Drug Metabolism",
        difficulty: "easy",
        curriculum: "International",
        yearLevel: "200 Level",
        semester: "Any",
        tags: ["drug metabolism", "liver", "CYP450"],
        references: [
          "Basic and Clinical Pharmacology",
          "Goodman & Gilman's pharmacological references"
        ],
        createdAt: nowISO()
      });
    }

    if (db.achievements.length === 0) {
      db.achievements.push(
        {
          id: "first_quiz",
          name: "First Quiz",
          description: "Complete your first quiz.",
          rewardXP: 25,
          rewardCoins: 10
        },
        {
          id: "questions_10",
          name: "Getting Started",
          description: "Answer 10 questions.",
          rewardXP: 50,
          rewardCoins: 20
        },
        {
          id: "questions_100",
          name: "Century Scholar",
          description: "Answer 100 questions.",
          rewardXP: 250,
          rewardCoins: 100
        },
        {
          id: "perfect_score",
          name: "Perfect Score",
          description: "Complete a quiz with every answer correct.",
          rewardXP: 100,
          rewardCoins: 50
        },
        {
          id: "streak_7",
          name: "7-Day Scholar",
          description: "Maintain a 7-day learning streak.",
          rewardXP: 150,
          rewardCoins: 75
        },
        {
          id: "streak_30",
          name: "30-Day Scholar",
          description: "Maintain a 30-day learning streak.",
          rewardXP: 500,
          rewardCoins: 250
        }
      );
    }

    writeDatabase(db);
  } catch (error) {
    console.error("Content seeding error:", error);
  }
}

/* ============================================================
   MIDDLEWARE
============================================================ */

app.disable("x-powered-by");

app.use(
  cors({
    origin:
      FRONTEND_ORIGIN === "*"
        ? true
        : FRONTEND_ORIGIN.split(",").map((item) => item.trim()),
    credentials: true
  })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

app.use(rateLimit());

/* ============================================================
   AUDIT LOG
============================================================ */

function createAuditLog(userId, action, details = {}) {
  updateDatabase((db) => {
    db.auditLogs.push({
      id: generateId("audit"),
      userId: userId || null,
      action,
      details,
      createdAt: nowISO()
    });
  });
}

/* ============================================================
   HEALTH / VERSION
============================================================ */

app.get("/health", (req, res) => {
  sendSuccess(res, {
    app: APP_NAME,
    status: "healthy",
    environment: NODE_ENV,
    timestamp: nowISO()
  });
});

app.get("/api/health", (req, res) => {
  sendSuccess(res, {
    app: APP_NAME,
    status: "healthy",
    version: APP_VERSION,
    timestamp: nowISO()
  });
});

app.get("/api/version", (req, res) => {
  sendSuccess(res, {
    name: APP_NAME,
    version: APP_VERSION,
    contentYear: CONTENT_YEAR,
    node: process.version
  });
});

/* ============================================================
   PUBLIC CONFIGURATION
============================================================ */

app.get("/api/config", (req, res) => {
  sendSuccess(res, {
    appName: APP_NAME,
    version: APP_VERSION,
    contentYear: CONTENT_YEAR,
    subjects: SUBJECTS,
    premiumEnabled: true,
    paymentProvider:
      process.env.PAYMENT_PROVIDER || "not_configured"
  });
});

/* ============================================================
   AUTHENTICATION
============================================================ */

app.post(
  "/api/auth/register",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20
  }),
  (req, res) => {
    const email = normalizeEmail(req.body.email);
    const username = safeText(req.body.username, 30);
    const password = req.body.password;
    const displayName =
      safeText(req.body.displayName, 100) || username;
    const country = safeText(req.body.country, 100);
    const institution = safeText(req.body.institution, 150);
    const curriculum =
      safeText(req.body.curriculum, 100) || "International";
    const yearLevel = safeText(req.body.yearLevel, 50);
    const semester = safeText(req.body.semester, 50);

    if (!isValidEmail(email)) {
      return sendError(res, 400, "Please provide a valid email.");
    }

    if (!isValidUsername(username)) {
      return sendError(
        res,
        400,
        "Username must contain only letters, numbers and underscores."
      );
    }

    if (!isValidPassword(password)) {
      return sendError(
        res,
        400,
        "Password must contain between 6 and 200 characters."
      );
    }

    const result = updateDatabase((db) => {
      if (
        db.users.some(
          (user) => normalizeEmail(user.email) === email
        )
      ) {
        return {
          error: "An account with this email already exists."
        };
      }

      if (
        db.users.some(
          (user) =>
            String(user.username).toLowerCase() ===
            username.toLowerCase()
        )
      ) {
        return {
          error: "That username is already taken."
        };
      }

      const passwordData = hashPassword(password);

      const user = {
        id: generateId("user"),
        email,
        username,
        displayName,
        country,
        institution,
        curriculum,
        yearLevel,
        semester,
        role: "student",
        password: passwordData,
        xp: 0,
        coins: 0,
        level: 1,
        streak: 0,
        questionsAnswered: 0,
        correctAnswers: 0,
        quizzesCompleted: 0,
        battlesWon: 0,
        battlesPlayed: 0,
        createdAt: nowISO(),
        lastActiveAt: nowISO()
      };

      ensureUserDefaults(user);

      db.users.push(user);

      db.wallets.push({
        id: generateId("wallet"),
        userId: user.id,
        balance: 0,
        lifetimeEarned: 0,
        lifetimeSpent: 0,
        createdAt: nowISO(),
        updatedAt: nowISO()
      });

      return { user };
    });

    if (result.error) {
      return sendError(res, 409, result.error);
    }

    const token = createSession(result.user.id);

    createAuditLog(result.user.id, "register");

    return sendSuccess(
      res,
      {
        token,
        user: getPublicUser(result.user)
      },
      "Account created successfully.",
      201
    );
  }
);

app.post(
  "/api/auth/login",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20
  }),
  (req, res) => {
    const email = normalizeEmail(req.body.email);
    const password = req.body.password;

    const db = readDatabase();

    const user = db.users.find(
      (item) => normalizeEmail(item.email) === email
    );

    if (!user || !verifyPassword(password, user.password)) {
      return sendError(res, 401, "Invalid email or password.");
    }

    ensureUserDefaults(user);
    user.lastActiveAt = nowISO();
    writeDatabase(db);

    const token = createSession(user.id);

    createAuditLog(user.id, "login");

    return sendSuccess(res, {
      token,
      user: getPublicUser(user)
    });
  }
);

app.post("/api/auth/logout", authRequired, (req, res) => {
  const token = getBearerToken(req);

  updateDatabase((db) => {
    const hash = sha256(token);
    db.sessions = db.sessions.filter(
      (session) => session.tokenHash !== hash
    );
  });

  createAuditLog(req.user.id, "logout");

  return sendSuccess(res, {}, "Logged out successfully.");
});

app.get("/api/auth/me", authRequired, (req, res) => {
  return sendSuccess(res, {
    user: getPublicUser(req.user),
    premium: isPremiumUser(req.user.id)
  });
});

/* ============================================================
   PROFILE
============================================================ */

app.get("/api/profile", authRequired, (req, res) => {
  const db = readDatabase();
  const user = getUserById(db, req.user.id);

  return sendSuccess(res, {
    user: getPublicUser(user),
    premium: isPremiumUser(user.id)
  });
});

app.patch("/api/profile", authRequired, (req, res) => {
  const allowed = [
    "displayName",
    "country",
    "institution",
    "curriculum",
    "yearLevel",
    "semester"
  ];

  updateDatabase((db) => {
    const user = getUserById(db, req.user.id);

    allowed.forEach((field) => {
      if (req.body[field] !== undefined) {
        user[field] = safeText(req.body[field], 150);
      }
    });

    user.lastActiveAt = nowISO();
  });

  createAuditLog(req.user.id, "profile_update");

  return sendSuccess(res, {
    user: getPublicUser(
      getUserById(readDatabase(), req.user.id)
    )
  });
});

/* ============================================================
   SUBJECTS
============================================================ */

app.get("/api/subjects", (req, res) => {
  return sendSuccess(res, {
    subjects: SUBJECTS
  });
});

/* ============================================================
   QUESTIONS
============================================================ */

app.get("/api/questions", authRequired, (req, res) => {
  const db = readDatabase();

  const questions = selectQuestions(db, {
    subject: req.query.subject,
    topic: req.query.topic,
    difficulty: req.query.difficulty,
    curriculum: req.query.curriculum
  });

  const safeQuestions = questions.map(sanitizeQuestion);

  return sendSuccess(
    res,
    paginate(
      safeQuestions,
      req.query.page,
      req.query.limit
    )
  );
});

app.get("/api/questions/:id", authRequired, (req, res) => {
  const db = readDatabase();
  const question = findQuestion(db, req.params.id);

  if (!question) {
    return sendError(res, 404, "Question not found.");
  }

  return sendSuccess(res, {
    question: sanitizeQuestion(question)
  });
});

app.get(
  "/api/questions/:id/solution",
  authRequired,
  (req, res) => {
    const db = readDatabase();
    const question = findQuestion(db, req.params.id);

    if (!question) {
      return sendError(res, 404, "Question not found.");
    }

    return sendSuccess(res, {
      question: sanitizeQuestionWithAnswer(question)
    });
  }
);

/* ============================================================
   QUIZ
============================================================ */

app.post("/api/quiz/start", authRequired, (req, res) => {
  const db = readDatabase();

  const count = clampNumber(
    req.body.count || 10,
    1,
    50,
    10
  );

  const questions = selectQuestions(db, {
    subject: req.body.subject,
    topic: req.body.topic,
    difficulty: req.body.difficulty,
    curriculum: req.body.curriculum
  }).slice(0, count);

  if (questions.length === 0) {
    return sendError(
      res,
      404,
      "No questions are available for the selected filters."
    );
  }

  const quizId = generateId("quiz");

  const quiz = {
    id: quizId,
    userId: req.user.id,
    questionIds: questions.map((q) => q.id),
    subject: req.body.subject || "Mixed",
    startedAt: nowISO(),
    status: "active"
  };

  updateDatabase((database) => {
    database.quizAttempts.push(quiz);
  });

  updateUserActivity(req.user.id);

  return sendSuccess(res, {
    quizId,
    questions: questions.map(sanitizeQuestion),
    count: questions.length
  });
});

app.post("/api/quiz/:id/submit", authRequired, (req, res) => {
  const db = readDatabase();

  const quiz = db.quizAttempts.find(
    (item) =>
      item.id === req.params.id &&
      item.userId === req.user.id
  );

  if (!quiz) {
    return sendError(res, 404, "Quiz not found.");
  }

  if (quiz.status === "completed") {
    return sendError(res, 400, "This quiz has already been submitted.");
  }

  const answers = Array.isArray(req.body.answers)
    ? req.body.answers
    : [];

  const questions = quiz.questionIds
    .map((id) => findQuestion(db, id))
    .filter(Boolean);

  const score = calculateQuizScore(questions, answers);

  const detailedResults = questions.map((question, index) => {
    const submitted = answers[index];

    const correct =
      String(submitted ?? "")
        .trim()
        .toLowerCase() ===
      String(question.answer)
        .trim()
        .toLowerCase();

    return {
      question: sanitizeQuestion(question),
      submittedAnswer: submitted ?? null,
      correct,
      correctAnswer: correct ? undefined : question.answer,
      explanation: correct
        ? undefined
        : question.explanation,
      whyCorrect: correct
        ? undefined
        : question.whyCorrect,
      optionExplanations: correct
        ? undefined
        : question.optionExplanations,
      learningPoints: correct
        ? undefined
        : question.learningPoints
    };
  });

  quiz.status = "completed";
  quiz.completedAt = nowISO();
  quiz.score = score;

  const xpEarned = score.correct * 10;
  const coinsEarned = score.correct * 2;

  const user = getUserById(db, req.user.id);
  ensureUserDefaults(user);

  user.questionsAnswered += score.total;
  user.correctAnswers += score.correct;
  user.quizzesCompleted += 1;
  user.lastPerfectScore =
    score.total > 0 && score.correct === score.total;

  const wallet = db.wallets.find(
    (item) => item.userId === user.id
  );

  user.xp += xpEarned;
  user.coins += coinsEarned;

  const oldLevel = user.level;
  user.level = calculateLevel(user.xp);

  if (wallet) {
    wallet.balance = user.coins;
    wallet.lifetimeEarned += coinsEarned;
    wallet.updatedAt = nowISO();
  }

  if (coinsEarned > 0) {
    db.walletTransactions.push({
      id: generateId("wallet_tx"),
      userId: user.id,
      type: "credit",
      amount: coinsEarned,
      reason: "Quiz reward",
      createdAt: nowISO()
    });
  }

  db.quizResults.push({
    id: generateId("quiz_result"),
    quizId: quiz.id,
    userId: user.id,
    correct: score.correct,
    total: score.total,
    percentage: score.percentage,
    answers,
    completedAt: nowISO()
  });

  if (user.level > oldLevel) {
    db.notifications.push({
      id: generateId("notification"),
      userId: user.id,
      type: "level_up",
      title: "Level Up!",
      message: `You reached level ${user.level}.`,
      read: false,
      createdAt: nowISO()
    });
  }

  writeDatabase(db);

  updateUserActivity(user.id);
  checkAchievements(user.id);

  return sendSuccess(res, {
    score,
    xpEarned,
    coinsEarned,
    level: user.level,
    results: detailedResults
  }, "Quiz submitted successfully.");
});

/* ============================================================
   DAILY CHALLENGE
============================================================ */

app.get("/api/daily-challenge", authRequired, (req, res) => {
  const db = readDatabase();
  const challenge = getDailyChallenge();

  const questions = challenge.questionIds
    .map((id) => findQuestion(db, id))
    .filter(Boolean)
    .map(sanitizeQuestion);

  return sendSuccess(res, {
    challenge: {
      id: challenge.id,
      date: challenge.date,
      rewardXP: challenge.rewardXP,
      rewardCoins: challenge.rewardCoins,
      questions
    }
  });
});

app.post(
  "/api/daily-challenge/submit",
  authRequired,
  (req, res) => {
    const db = readDatabase();
    const challenge = getDailyChallenge();

    const answers = Array.isArray(req.body.answers)
      ? req.body.answers
      : [];

    const questions = challenge.questionIds
      .map((id) => findQuestion(db, id))
      .filter(Boolean);

    const score = calculateQuizScore(questions, answers);

    const alreadyCompleted = db.quizResults.some(
      (result) =>
        result.userId === req.user.id &&
        result.dailyChallengeId === challenge.id
    );

    if (alreadyCompleted) {
      return sendError(
        res,
        400,
        "You have already completed today's challenge."
      );
    }

    const user = getUserById(db, req.user.id);
    ensureUserDefaults(user);

    const xp =
      Math.round(
        (score.correct / Math.max(score.total, 1)) *
          challenge.rewardXP
      );

    const coins =
      Math.round(
        (score.correct / Math.max(score.total, 1)) *
          challenge.rewardCoins
      );

    user.questionsAnswered += score.total;
    user.correctAnswers += score.correct;
    user.xp += xp;
    user.coins += coins;
    user.level = calculateLevel(user.xp);

    db.quizResults.push({
      id: generateId("daily_result"),
      userId: user.id,
      dailyChallengeId: challenge.id,
      correct: score.correct,
      total: score.total,
      percentage: score.percentage,
      completedAt: nowISO()
    });

    const wallet = db.wallets.find(
      (item) => item.userId === user.id
    );

    if (wallet) {
      wallet.balance = user.coins;
      wallet.lifetimeEarned += coins;
      wallet.updatedAt = nowISO();
    }

    writeDatabase(db);
    updateUserActivity(user.id);

    return sendSuccess(res, {
      score,
      xpEarned: xp,
      coinsEarned: coins
    });
  }
);
/* ============================================================
   BATTLES
   ============================================================ */

/*
Battle structure:

{
  id,
  type,
  creatorId,
  opponentId,
  status,
  questionIds,
  creatorScore,
  opponentScore,
  submissions,
  createdAt,
  startedAt,
  endsAt,
  completedAt,
  winnerId
}
*/


/* ------------------------------------------------------------
   CREATE QUICK BATTLE
------------------------------------------------------------ */

app.post("/api/battles/quick", authRequired, (req, res) => {
  const db = readDatabase();

  const count = clampNumber(
    req.body.count || 10,
    1,
    30,
    10
  );

  const questions = selectQuestions(db, {
    subject: req.body.subject,
    difficulty: req.body.difficulty
  }).slice(0, count);

  if (!questions.length) {
    return sendError(
      res,
      404,
      "No battle questions available."
    );
  }

  const battle = {
    id: generateId("battle"),
    type: "quick",

    // The user who created the battle
    creatorId: req.user.id,

    // No opponent until somebody joins
    opponentId: null,

    // Waiting for another player
    status: "waiting",

    // Questions used in this battle
    questionIds: questions.map((q) => q.id),

    // Scores
    creatorScore: 0,
    opponentScore: 0,

    // Each player's submission is stored here
    submissions: {},

    createdAt: nowISO(),

    // These will be set when an opponent joins
    startedAt: null,
    endsAt: null,

    completedAt: null,
    winnerId: null
  };

  updateDatabase((database) => {
    database.battles.push(battle);
  });

  return sendSuccess(
    res,
    {
      battleId: battle.id,
      status: battle.status,
      creatorId: battle.creatorId,
      questions: questions.map(sanitizeQuestion)
    },
    "Quick battle created.",
    201
  );
});


/* ------------------------------------------------------------
   JOIN BATTLE
------------------------------------------------------------ */

app.post("/api/battles/:id/join", authRequired, (req, res) => {
  const db = readDatabase();

  const battle = db.battles.find(
    (item) => item.id === req.params.id
  );

  if (!battle) {
    return sendError(
      res,
      404,
      "Battle not found."
    );
  }

  // Do not allow the creator to join their own battle
  if (battle.creatorId === req.user.id) {
    return sendError(
      res,
      400,
      "You cannot join your own battle."
    );
  }

  // Only waiting battles can be joined
  if (battle.status !== "waiting") {
    return sendError(
      res,
      400,
      "This battle is no longer waiting for an opponent."
    );
  }

  // Prevent a second opponent
  if (battle.opponentId) {
    return sendError(
      res,
      400,
      "Battle already has an opponent."
    );
  }

  const startedAt = nowISO();

  /*
    Battle duration.
    Change 10 to another number of minutes if desired.
  */
  const endsAt = addMinutes(
    new Date(),
    10
  );

  battle.opponentId = req.user.id;
  battle.status = "active";
  battle.startedAt = startedAt;
  battle.endsAt = endsAt;

  writeDatabase(db);

  return sendSuccess(
    res,
    {
      battle: {
        id: battle.id,
        type: battle.type,
        creatorId: battle.creatorId,
        opponentId: battle.opponentId,
        status: battle.status,
        questionIds: battle.questionIds,
        creatorScore: battle.creatorScore,
        opponentScore: battle.opponentScore,
        startedAt: battle.startedAt,
        endsAt: battle.endsAt,
        createdAt: battle.createdAt
      }
    },
    "Battle joined successfully."
  );
});


/* ------------------------------------------------------------
   GET BATTLE STATUS
------------------------------------------------------------ */

app.get("/api/battles/:id", authRequired, (req, res) => {
  const db = readDatabase();

  const battle = db.battles.find(
    (item) => item.id === req.params.id
  );

  if (!battle) {
    return sendError(
      res,
      404,
      "Battle not found."
    );
  }

  /*
    Only the creator or opponent can view the battle.
  */
  const isParticipant =
    battle.creatorId === req.user.id ||
    battle.opponentId === req.user.id;

  if (!isParticipant) {
    return sendError(
      res,
      403,
      "You are not a participant in this battle."
    );
  }

  /*
    Automatically expire an active battle
    when its timer has finished.
  */
  if (
    battle.status === "active" &&
    battle.endsAt &&
    new Date(battle.endsAt).getTime() <= Date.now()
  ) {
    battle.status = "expired";
    battle.completedAt = nowISO();

    writeDatabase(db);
  }

  const responseBattle = {
    id: battle.id,
    type: battle.type,
    status: battle.status,

    creatorId: battle.creatorId,
    opponentId: battle.opponentId,

    questionIds: battle.questionIds,

    creatorScore: battle.creatorScore || 0,
    opponentScore: battle.opponentScore || 0,

    startedAt: battle.startedAt || null,
    endsAt: battle.endsAt || null,
    completedAt: battle.completedAt || null,

    winnerId: battle.winnerId || null,

    createdAt: battle.createdAt
  };

  return sendSuccess(
    res,
    {
      battle: responseBattle
    },
    "Battle status retrieved."
  );
});


/* ------------------------------------------------------------
   SUBMIT BATTLE
------------------------------------------------------------ */

app.post("/api/battles/:id/submit", authRequired, (req, res) => {
  const db = readDatabase();

  const battle = db.battles.find(
    (item) => item.id === req.params.id
  );

  if (!battle) {
    return sendError(
      res,
      404,
      "Battle not found."
    );
  }

  /*
    Only creator or opponent can submit.
  */
  const isParticipant =
    battle.creatorId === req.user.id ||
    battle.opponentId === req.user.id;

  if (!isParticipant) {
    return sendError(
      res,
      403,
      "You are not part of this battle."
    );
  }

  /*
    Battle must actually be active.
  */
  if (battle.status !== "active") {
    return sendError(
      res,
      400,
      `Battle is ${battle.status}. Submissions are not accepted.`
    );
  }

  /*
    Check whether the timer has expired.
  */
  if (
    battle.endsAt &&
    new Date(battle.endsAt).getTime() <= Date.now()
  ) {
    battle.status = "expired";
    battle.completedAt = nowISO();

    writeDatabase(db);

    return sendError(
      res,
      400,
      "Battle time has expired."
    );
  }

  /*
    Prevent the same player from submitting twice.
  */
  battle.submissions =
    battle.submissions || {};

  if (battle.submissions[req.user.id]) {
    return sendError(
      res,
      400,
      "You have already submitted this battle."
    );
  }

  const answers = Array.isArray(req.body.answers)
    ? req.body.answers
    : [];

  /*
    Get the actual questions.
  */
  const questions = battle.questionIds
    .map((id) => findQuestion(db, id))
    .filter(Boolean);

  if (!questions.length) {
    return sendError(
      res,
      400,
      "Battle questions could not be found."
    );
  }

  /*
    Calculate player's score.
  */
  const score = calculateQuizScore(
    questions,
    answers
  );

  /*
    Store submission.
  */
  battle.submissions[req.user.id] = {
    score,
    submittedAt: nowISO()
  };

  /*
    Store the score in the correct field.
  */
  if (req.user.id === battle.creatorId) {
    battle.creatorScore = score.correct;
  } else if (req.user.id === battle.opponentId) {
    battle.opponentScore = score.correct;
  }

  /*
    Check whether both players have submitted.
  */
  const participantIds = [
    battle.creatorId,
    battle.opponentId
  ].filter(Boolean);

  const bothSubmitted =
    participantIds.length === 2 &&
    participantIds.every(
      (id) => battle.submissions[id]
    );

  let winnerId = battle.winnerId || null;

  if (bothSubmitted) {
    const creatorSubmission =
      battle.submissions[battle.creatorId];

    const opponentSubmission =
      battle.submissions[battle.opponentId];

    /*
      Determine winner.
      A tie leaves winnerId as null.
    */
    if (
      creatorSubmission.score.correct >
      opponentSubmission.score.correct
    ) {
      winnerId = battle.creatorId;
    } else if (
      opponentSubmission.score.correct >
      creatorSubmission.score.correct
    ) {
      winnerId = battle.opponentId;
    } else {
      winnerId = null;
    }

    battle.winnerId = winnerId;
    battle.status = "completed";
    battle.completedAt = nowISO();

    /*
      Give battle rewards.
    */
    participantIds.forEach((id) => {
      const user = getUserById(db, id);

      if (!user) {
        return;
      }

      ensureUserDefaults(user);

      user.battlesPlayed += 1;

      if (winnerId === id) {
        user.battlesWon += 1;
        user.xp += 100;
        user.coins += 25;
      } else {
        user.xp += 25;
        user.coins += 5;
      }

      user.level = calculateLevel(
        user.xp
      );
    });
  }

  /*
    Save everything.
  */
  writeDatabase(db);

  /*
    Return result to the player.
  */
  return sendSuccess(
    res,
    {
      battleId: battle.id,
      status: battle.status,

      score,

      creatorScore:
        battle.creatorScore || 0,

      opponentScore:
        battle.opponentScore || 0,

      winnerId:
        battle.winnerId || null,

      completedAt:
        battle.completedAt || null
    },
    bothSubmitted
      ? "Battle completed."
      : "Battle submission recorded."
  );
});


/* ------------------------------------------------------------
   EXPIRE BATTLE
------------------------------------------------------------ */

app.post("/api/battles/:id/expire", authRequired, (req, res) => {
  const db = readDatabase();

  const battle = db.battles.find(
    (item) => item.id === req.params.id
  );

  if (!battle) {
    return sendError(
      res,
      404,
      "Battle not found."
    );
  }

  /*
    Only participants can expire/check the battle.
  */
  const isParticipant =
    battle.creatorId === req.user.id ||
    battle.opponentId === req.user.id;

  if (!isParticipant) {
    return sendError(
      res,
      403,
      "You are not a participant in this battle."
    );
  }

  /*
    If already completed or expired,
    simply return the current battle.
  */
  if (
    battle.status !== "active"
  ) {
    return sendSuccess(
      res,
      {
        battle
      },
      "Battle is not active."
    );
  }

  /*
    Do not allow premature expiration.
  */
  if (
    battle.endsAt &&
    new Date(battle.endsAt).getTime() > Date.now()
  ) {
    return sendError(
      res,
      400,
      "Battle has not expired yet."
    );
  }

  battle.status = "expired";
  battle.completedAt = nowISO();

  writeDatabase(db);

  createAuditLog(
    req.user.id,
    "battle_expired",
    {
      battleId: battle.id
    }
  );

  return sendSuccess(
    res,
    {
      battle
    },
    "Battle expired."
  );
});winnerId: battle.winnerId || null
    });
  }
);

/* ============================================================
   LEADERBOARD
============================================================ */

app.get("/api/leaderboard", (req, res) => {
  const db = readDatabase();

  const sorted = [...db.users]
    .map((user) => ({
      id: user.id,
      username: user.username,
      displayName: user.displayName,
      country: user.country,
      institution: user.institution,
      xp: Number(user.xp) || 0,
      level: Number(user.level) || 1,
      coins: Number(user.coins) || 0,
      battlesWon: Number(user.battlesWon) || 0
    }))
    .sort((a, b) => b.xp - a.xp);

  return sendSuccess(
    res,
    paginate(
      sorted,
      req.query.page,
      req.query.limit
    )
  );
});

/* ============================================================
   GPA CALCULATOR
============================================================ */

function calculateGPA(courses = []) {
  let totalQualityPoints = 0;
  let totalUnits = 0;

  const processed = courses.map((course) => {
    const unit = Number(course.unit);
    const gradePoint = Number(course.gradePoint);

    if (
      !Number.isFinite(unit) ||
      !Number.isFinite(gradePoint) ||
      unit <= 0
    ) {
      return {
        ...course,
        qualityPoint: 0
      };
    }

    const qualityPoint = unit * gradePoint;

    totalQualityPoints += qualityPoint;
    totalUnits += unit;

    return {
      ...course,
      qualityPoint
    };
  });

  return {
    courses: processed,
    totalUnits,
    totalQualityPoints,
    gpa:
      totalUnits > 0
        ? Number(
            (totalQualityPoints / totalUnits).toFixed(2)
          )
        : 0
  };
}

app.post("/api/gpa/calculate", authRequired, (req, res) => {
  const courses = Array.isArray(req.body.courses)
    ? req.body.courses
    : [];

  if (!courses.length) {
    return sendError(
      res,
      400,
      "Please provide at least one course."
    );
  }

  return sendSuccess(res, calculateGPA(courses));
});

app.post("/api/gpa/save", authRequired, (req, res) => {
  const courses = Array.isArray(req.body.courses)
    ? req.body.courses
    : [];

  const result = calculateGPA(courses);

  const record = {
    id: generateId("gpa"),
    userId: req.user.id,
    semester: safeText(req.body.semester, 100),
    session: safeText(req.body.session, 100),
    courses: result.courses,
    totalUnits: result.totalUnits,
    totalQualityPoints: result.totalQualityPoints,
    gpa: result.gpa,
    createdAt: nowISO()
  };

  updateDatabase((db) => {
    db.gpaRecords.push(record);
  });

  return sendSuccess(
    res,
    { record },
    "GPA record saved.",
    201
  );
});

app.get("/api/gpa/records", authRequired, (req, res) => {
  const db = readDatabase();

  const records = db.gpaRecords
    .filter((item) => item.userId === req.user.id)
    .sort(
      (a, b) =>
        new Date(b.createdAt) -
        new Date(a.createdAt)
    );

  return sendSuccess(res, {
    records
  });
});

/* ============================================================
   LIBRARY
============================================================ */

app.get("/api/library", authRequired, (req, res) => {
  const db = readDatabase();

  let items = [...db.library];

  if (req.query.subject) {
    items = items.filter(
      (item) =>
        String(item.subject || "").toLowerCase() ===
        String(req.query.subject).toLowerCase()
    );
  }

  if (req.query.search) {
    const search = String(req.query.search).toLowerCase();

    items = items.filter((item) =>
      `${item.title || ""} ${item.description || ""}`
        .toLowerCase()
        .includes(search)
    );
  }

  return sendSuccess(
    res,
    paginate(items, req.query.page, req.query.limit)
  );
});

/* ============================================================
   PHARMACOPOEIA HUB
============================================================ */

app.get(
  "/api/pharmacopoeia",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    let entries = [...db.pharmacopoeia];

    if (req.query.search) {
      const search = String(req.query.search).toLowerCase();

      entries = entries.filter((item) =>
        JSON.stringify(item)
          .toLowerCase()
          .includes(search)
      );
    }

    return sendSuccess(
      res,
      paginate(
        entries,
        req.query.page,
        req.query.limit
      )
    );
  }
);

/* ============================================================
   LANGUAGE ASSISTANT
============================================================ */

app.get(
  "/api/languages",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    return sendSuccess(res, {
      languages: db.languages,
      phrases: db.languagePhrases
    });
  }
);


/* ============================================================
   BOOKMARKS
============================================================ */

app.get("/api/bookmarks", authRequired, (req, res) => {
  const db = readDatabase();

  const bookmarks = db.bookmarks
    .filter((item) => item.userId === req.user.id)
    .map((bookmark) => {
      const question = findQuestion(
        db,
        bookmark.questionId
      );

      return {
        ...bookmark,
        question: sanitizeQuestion(question)
      };
    });

  return sendSuccess(res, { bookmarks });
});

    /* ============================================================
   BOOKMARKS — CONTINUED
============================================================ */

app.post(
  "/api/bookmarks/:questionId",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const question = findQuestion(
      db,
      req.params.questionId
    );

    if (!question) {
      return sendError(res, 404, "Question not found.");
    }

    const existing = db.bookmarks.find(
      (item) =>
        item.userId === req.user.id &&
        item.questionId === question.id
    );

    if (existing) {
      return sendSuccess(
        res,
        { bookmark: existing },
        "Question is already bookmarked."
      );
    }

    const bookmark = {
      id: generateId("bookmark"),
      userId: req.user.id,
      questionId: question.id,
      createdAt: nowISO()
    };

    db.bookmarks.push(bookmark);
    writeDatabase(db);

    createAuditLog(
      req.user.id,
      "bookmark_added",
      { questionId: question.id }
    );

    return sendSuccess(
      res,
      {
        bookmark,
        question: sanitizeQuestion(question)
      },
      "Question bookmarked.",
      201
    );
  }
);

app.delete(
  "/api/bookmarks/:questionId",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const before = db.bookmarks.length;

    db.bookmarks = db.bookmarks.filter(
      (item) =>
        !(
          item.userId === req.user.id &&
          item.questionId === req.params.questionId
        )
    );

    if (db.bookmarks.length === before) {
      return sendError(
        res,
        404,
        "Bookmark not found."
      );
    }

    writeDatabase(db);

    createAuditLog(
      req.user.id,
      "bookmark_removed",
      {
        questionId: req.params.questionId
      }
    );

    return sendSuccess(
      res,
      {},
      "Bookmark removed."
    );
  }
);


/* ============================================================
   ANALYTICS
============================================================ */

app.get(
  "/api/analytics/me",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const results = db.quizResults.filter(
      (item) => item.userId === req.user.id
    );

    const answered = results.reduce(
      (sum, item) => sum + (Number(item.total) || 0),
      0
    );

    const correct = results.reduce(
      (sum, item) => sum + (Number(item.correct) || 0),
      0
    );

    const quizzes = results.length;

    const averageScore =
      quizzes > 0
        ? Number(
            (
              results.reduce(
                (sum, item) =>
                  sum + (Number(item.percentage) || 0),
                0
              ) / quizzes
            ).toFixed(2)
          )
        : 0;

    const subjectStats = {};

    results.forEach((result) => {
      const quiz = db.quizAttempts.find(
        (item) => item.id === result.quizId
      );

      const subject =
        quiz?.subject || "Mixed";

      if (!subjectStats[subject]) {
        subjectStats[subject] = {
          subject,
          attempts: 0,
          correct: 0,
          total: 0,
          percentage: 0
        };
      }

      subjectStats[subject].attempts += 1;
      subjectStats[subject].correct +=
        Number(result.correct) || 0;
      subjectStats[subject].total +=
        Number(result.total) || 0;
    });

    Object.values(subjectStats).forEach((item) => {
      item.percentage =
        item.total > 0
          ? Number(
              ((item.correct / item.total) * 100).toFixed(2)
            )
          : 0;
    });

    return sendSuccess(res, {
      overview: {
        questionsAnswered: answered,
        correctAnswers: correct,
        quizzesCompleted: quizzes,
        averageScore
      },
      subjectPerformance:
        Object.values(subjectStats)
    });
  }
);


/* ============================================================
   WEAK TOPIC DETECTION
============================================================ */

app.get(
  "/api/analytics/weak-topics",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const userResults = db.quizResults.filter(
      (item) => item.userId === req.user.id
    );

    const topicStats = {};

    userResults.forEach((result) => {
      const quiz = db.quizAttempts.find(
        (item) => item.id === result.quizId
      );

      if (!quiz) return;

      quiz.questionIds.forEach((questionId) => {
        const question = findQuestion(
          db,
          questionId
        );

        if (!question) return;

        const topic =
          question.topic || "General";

        if (!topicStats[topic]) {
          topicStats[topic] = {
            topic,
            subject: question.subject,
            questions: 0,
            estimatedWeakness: 0
          };
        }

        topicStats[topic].questions += 1;
      });
    });

    const weakTopics = Object.values(topicStats)
      .map((item) => ({
        ...item,
        estimatedWeakness:
          Math.min(
            100,
            Math.max(
              0,
              100 -
                Math.min(
                  100,
                  item.questions * 10
                )
            )
          )
      }))
      .sort(
        (a, b) =>
          b.estimatedWeakness -
          a.estimatedWeakness
      );

    return sendSuccess(res, {
      weakTopics
    });
  }
);


/* ============================================================
   WALLET
============================================================ */

app.get(
  "/api/wallet",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const wallet =
      db.wallets.find(
        (item) =>
          item.userId === req.user.id
      ) ||
      {
        id: generateId("wallet"),
        userId: req.user.id,
        balance: req.user.coins || 0,
        lifetimeEarned: 0,
        lifetimeSpent: 0,
        createdAt: nowISO(),
        updatedAt: nowISO()
      };

    return sendSuccess(res, {
      wallet
    });
  }
);

app.get(
  "/api/wallet/transactions",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const transactions =
      db.walletTransactions
        .filter(
          (item) =>
            item.userId === req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    return sendSuccess(
      res,
      paginate(
        transactions,
        req.query.page,
        req.query.limit
      )
    );
  }
);


/* ============================================================
   REFERRAL SYSTEM
============================================================ */

app.get(
  "/api/referrals",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const referrals =
      db.referrals.filter(
        (item) =>
          item.referrerId === req.user.id ||
          item.referredUserId === req.user.id
      );

    return sendSuccess(res, {
      referralCode:
        req.user.referralCode,
      referrals
    });
  }
);

app.post(
  "/api/referrals/apply",
  authRequired,
  (req, res) => {
    const code = safeText(
      req.body.referralCode,
      100
    );

    if (!code) {
      return sendError(
        res,
        400,
        "Referral code is required."
      );
    }

    const db = readDatabase();

    const referrer = db.users.find(
      (user) =>
        user.referralCode &&
        user.referralCode.toLowerCase() ===
          code.toLowerCase()
    );

    if (!referrer) {
      return sendError(
        res,
        404,
        "Referral code not found."
      );
    }

    if (referrer.id === req.user.id) {
      return sendError(
        res,
        400,
        "You cannot use your own referral code."
      );
    }

    const alreadyReferred =
      db.referrals.find(
        (item) =>
          item.referredUserId ===
          req.user.id
      );

    if (alreadyReferred) {
      return sendError(
        res,
        400,
        "A referral has already been applied to this account."
      );
    }

    db.referrals.push({
      id: generateId("referral"),
      referrerId: referrer.id,
      referredUserId: req.user.id,
      referralCode: referrer.referralCode,
      status: "completed",
      createdAt: nowISO()
    });

    ensureUserDefaults(referrer);
    ensureUserDefaults(req.user);

    referrer.coins += 50;
    req.user.coins += 25;

    const referrerWallet =
      db.wallets.find(
        (item) =>
          item.userId === referrer.id
      );

    const userWallet =
      db.wallets.find(
        (item) =>
          item.userId === req.user.id
      );

    if (referrerWallet) {
      referrerWallet.balance =
        referrer.coins;
      referrerWallet.lifetimeEarned += 50;
      referrerWallet.updatedAt = nowISO();
    }

    if (userWallet) {
      userWallet.balance =
        req.user.coins;
      userWallet.lifetimeEarned += 25;
      userWallet.updatedAt = nowISO();
    }

    db.walletTransactions.push(
      {
        id: generateId("wallet_tx"),
        userId: referrer.id,
        type: "credit",
        amount: 50,
        reason: "Referral reward",
        createdAt: nowISO()
      },
      {
        id: generateId("wallet_tx"),
        userId: req.user.id,
        type: "credit",
        amount: 25,
        reason: "Referral signup reward",
        createdAt: nowISO()
      }
    );

    writeDatabase(db);

    return sendSuccess(
      res,
      {},
      "Referral applied successfully."
    );
  }
);


/* ============================================================
   PREMIUM SUBSCRIPTIONS
============================================================ */

app.get(
  "/api/premium/status",
  authRequired,
  (req, res) => {
    const subscription =
      getActiveSubscription(
        req.user.id
      );

    return sendSuccess(res, {
      premium: Boolean(subscription),
      subscription
    });
  }
);

app.get(
  "/api/premium/plans",
  (req, res) => {
    return sendSuccess(res, {
      plans: [
        {
          id: "monthly",
          name: "DENexpharm Premium Monthly",
          durationDays: 30,
          price: Number(
            process.env.PREMIUM_MONTHLY_PRICE ||
              2500
          ),
          currency: "NGN",
          features: [
            "Premium question banks",
            "Advanced analytics",
            "Expanded library",
            "Premium study resources",
            "Advanced competition features"
          ]
        },
        {
          id: "yearly",
          name: "DENexpharm Premium Yearly",
          durationDays: 365,
          price: Number(
            process.env.PREMIUM_YEARLY_PRICE ||
              20000
          ),
          currency: "NGN",
          features: [
            "All monthly premium features",
            "Year-long access",
            "Advanced learning analytics",
            "Premium educational resources"
          ]
        }
      ]
    });
  }
);


/* ============================================================
   PAYMENT ARCHITECTURE
============================================================ */

app.post(
  "/api/payments/initialize",
  authRequired,
  async (req, res) => {
    const planId = safeText(
      req.body.planId,
      50
    );

    const plans = {
      monthly: {
        durationDays: 30,
        amount: Number(
          process.env.PREMIUM_MONTHLY_PRICE ||
            2500
        )
      },
      yearly: {
        durationDays: 365,
        amount: Number(
          process.env.PREMIUM_YEARLY_PRICE ||
            20000
        )
      }
    };

    const plan = plans[planId];

    if (!plan) {
      return sendError(
        res,
        400,
        "Invalid premium plan."
      );
    }

    const provider =
      process.env.PAYMENT_PROVIDER ||
      "not_configured";

    const reference =
      `DENEX-${Date.now()}-${crypto
        .randomBytes(4)
        .toString("hex")
        .toUpperCase()}`;

    const payment = {
      id: generateId("payment"),
      userId: req.user.id,
      reference,
      planId,
      amount: plan.amount,
      currency: "NGN",
      provider,
      status: "pending",
      createdAt: nowISO()
    };

    updateDatabase((db) => {
      db.payments.push(payment);
    });

    /*
      IMPORTANT:
      This endpoint intentionally does NOT activate Premium.

      A real Paystack/Flutterwave integration should create the
      provider transaction here and return its authorization URL.
    */

    return sendSuccess(
      res,
      {
        payment,
        configured:
          provider !== "not_configured",
        message:
          provider === "not_configured"
            ? "Payment provider is not configured yet."
            : "Payment initialization hook created."
      },
      "Payment request created.",
      201
    );
  }
);


/* ============================================================
   PAYMENT VERIFICATION HOOK
============================================================ */

app.post(
  "/api/payments/verify",
  authRequired,
  async (req, res) => {
    const reference = safeText(
      req.body.reference,
      150
    );

    if (!reference) {
      return sendError(
        res,
        400,
        "Payment reference is required."
      );
    }

    const db = readDatabase();

    const payment =
      db.payments.find(
        (item) =>
          item.reference === reference &&
          item.userId === req.user.id
      );

    if (!payment) {
      return sendError(
        res,
        404,
        "Payment not found."
      );
    }

    /*
      SECURITY:
      Never trust a client-provided "paid" flag.

      The production implementation must verify the transaction
      directly with Paystack, Flutterwave, or the configured
      payment provider.
    */

    return sendSuccess(
      res,
      {
        payment,
        verified: false,
        message:
          "Provider verification must be connected before premium access can be activated."
      }
    );
  }
);


/* ============================================================
   PREMIUM-PROTECTED EXAMPLE
============================================================ */

function premiumRequired(
  req,
  res,
  next
) {
  if (!isPremiumUser(req.user.id)) {
    return sendError(
      res,
      402,
      "Premium subscription required."
    );
  }

  next();
}

app.get(
  "/api/premium/library",
  authRequired,
  premiumRequired,
  (req, res) => {
    const db = readDatabase();

    const items = db.library.filter(
      (item) =>
        item.premium === true
    );

    return sendSuccess(res, {
      items
    });
  }
);


/* ============================================================
   FEEDBACK
============================================================ */

app.post(
  "/api/feedback",
  authRequired,
  (req, res) => {
    const type = safeText(
      req.body.type,
      50
    );

    const message = safeText(
      req.body.message,
      2000
    );

    const rating = clampNumber(
      req.body.rating,
      1,
      5,
      0
    );

    if (!message) {
      return sendError(
        res,
        400,
        "Feedback message is required."
      );
    }

    const feedback = {
      id: generateId("feedback"),
      userId: req.user.id,
      type: type || "general",
      message,
      rating,
      status: "new",
      createdAt: nowISO()
    };

    updateDatabase((db) => {
      db.feedback.push(feedback);
    });

    return sendSuccess(
      res,
      { feedback },
      "Thank you for your feedback.",
      201
    );
  }
);

app.get(
  "/api/feedback/mine",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const feedback =
      db.feedback
        .filter(
          (item) =>
            item.userId === req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    return sendSuccess(res, {
      feedback
    });
  }
);


/* ============================================================
   SEARCH
============================================================ */

app.get(
  "/api/search",
  authRequired,
  (req, res) => {
    const query = safeText(
      req.query.q,
      200
    ).toLowerCase();

    if (!query) {
      return sendError(
        res,
        400,
        "Search query is required."
      );
    }

    const db = readDatabase();

    const questions =
      db.questions
        .filter((question) => {
          const searchable =
            [
              question.question,
              question.subject,
              question.topic,
              ...(question.tags || [])
            ]
              .join(" ")
              .toLowerCase();

          return searchable.includes(query);
        })
        .map(sanitizeQuestion)
        .slice(0, 50);

    const library =
      db.library
        .filter((item) => {
          const searchable =
            [
              item.title,
              item.description,
              item.subject,
              item.topic
            ]
              .join(" ")
              .toLowerCase();

          return searchable.includes(query);
        })
        .slice(0, 30);

    const pharmacopoeia =
      db.pharmacopoeia
        .filter((item) =>
          JSON.stringify(item)
            .toLowerCase()
            .includes(query)
        )
        .slice(0, 30);

    return sendSuccess(res, {
      query,
      results: {
        questions,
        library,
        pharmacopoeia
      }
    });
  }
);


/* ============================================================
   NOTIFICATIONS
============================================================ */

app.get(
  "/api/notifications",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const notifications =
      db.notifications
        .filter(
          (item) =>
            item.userId === req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    return sendSuccess(res, {
      unread: notifications.filter(
        (item) => !item.read
      ).length,
      notifications
    });
  }
);

app.patch(
  "/api/notifications/:id/read",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const notification =
      db.notifications.find(
        (item) =>
          item.id === req.params.id &&
          item.userId === req.user.id
      );

    if (!notification) {
      return sendError(
        res,
        404,
        "Notification not found."
      );
    }

    notification.read = true;

    writeDatabase(db);

    return sendSuccess(
      res,
      { notification },
      "Notification marked as read."
    );
  }
);


/* ============================================================
   ADMIN — QUESTIONS
============================================================ */

app.get(
  "/api/admin/questions",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    let questions = [...db.questions];

    if (req.query.subject) {
      questions = questions.filter(
        (item) =>
          String(item.subject)
            .toLowerCase() ===
          String(req.query.subject)
            .toLowerCase()
      );
    }

    if (req.query.search) {
      const search =
        String(req.query.search)
          .toLowerCase();

      questions = questions.filter(
        (item) =>
          JSON.stringify(item)
            .toLowerCase()
            .includes(search)
      );
    }

    return sendSuccess(
      res,
      paginate(
        questions,
        req.query.page,
        req.query.limit
      )
    );
  }
);

app.post(
  "/api/admin/questions",
  authRequired,
  adminRequired,
  (req, res) => {
    const questionText = safeText(
      req.body.question,
      2000
    );

    const options =
      Array.isArray(req.body.options)
        ? req.body.options
            .map((item) =>
              safeText(item, 500)
            )
            .filter(Boolean)
        : [];

    const answer = safeText(
      req.body.answer,
      500
    );

    if (
      !questionText ||
      options.length < 2 ||
      !answer
    ) {
      return sendError(
        res,
        400,
        "Question, at least two options, and an answer are required."
      );
    }

    if (!options.includes(answer)) {
      return sendError(
        res,
        400,
        "The answer must match one of the options."
      );
    }

    const question = {
      id: generateId("question"),
      question: questionText,
      options,
      answer,
      explanation: safeText(
        req.body.explanation,
        4000
      ),
      whyCorrect: safeText(
        req.body.whyCorrect,
        3000
      ),
      optionExplanations:
        req.body.optionExplanations || {},
      learningPoints:
        Array.isArray(
          req.body.learningPoints
        )
          ? req.body.learningPoints
              .map((item) =>
                safeText(item, 500)
              )
          : [],
      subject: safeText(
        req.body.subject,
        150
      ),
      topic: safeText(
        req.body.topic,
        150
      ),
      difficulty: safeText(
        req.body.difficulty,
        50
      ) || "medium",
      curriculum: safeText(
        req.body.curriculum,
        100
      ) || "International",
      yearLevel: safeText(
        req.body.yearLevel,
        50
      ),
      semester: safeText(
        req.body.semester,
        50
      ),
      tags: Array.isArray(req.body.tags)
        ? req.body.tags.map((tag) =>
            safeText(tag, 100)
          )
        : [],
      references:
        Array.isArray(
          req.body.references
        )
          ? req.body.references.map(
              (ref) =>
                safeText(ref, 500)
            )
          : [],
      createdAt: nowISO(),
      updatedAt: nowISO(),
      createdBy: req.user.id
    };

    updateDatabase((db) => {
      db.questions.push(question);
    });

    createAuditLog(
      req.user.id,
      "admin_question_created",
      {
        questionId: question.id
      }
    );

    return sendSuccess(
      res,
      { question: sanitizeQuestionWithAnswer(question) },
      "Question created successfully.",
      201
    );
  }
);

app.patch(
  "/api/admin/questions/:id",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    const question =
      findQuestion(
        db,
        req.params.id
      );

    if (!question) {
      return sendError(
        res,
        404,
        "Question not found."
      );
    }

    const fields = [
      "question",
      "subject",
      "topic",
      "difficulty",
      "curriculum",
      "yearLevel",
      "semester",
      "answer",
      "explanation",
      "whyCorrect"
    ];

    fields.forEach((field) => {
      if (req.body[field] !== undefined) {
        question[field] =
          safeText(
            req.body[field],
            4000
          );
      }
    });

    if (Array.isArray(req.body.options)) {
      question.options =
        req.body.options
          .map((item) =>
            safeText(item, 500)
          )
          .filter(Boolean);
    }

    if (
      Array.isArray(
        req.body.learningPoints
      )
    ) {
      question.learningPoints =
        req.body.learningPoints.map(
          (item) =>
            safeText(item, 500)
        );
    }

    if (Array.isArray(req.body.tags)) {
      question.tags =
        req.body.tags.map((item) =>
          safeText(item, 100)
        );
    }

    if (
      Array.isArray(
        req.body.references
      )
    ) {
      question.references =
        req.body.references.map(
          (item) =>
            safeText(item, 500)
        );
    }

    question.updatedAt = nowISO();

    writeDatabase(db);

    createAuditLog(
      req.user.id,
      "admin_question_updated",
      {
        questionId: question.id
      }
    );

    return sendSuccess(
      res,
      {
        question:
          sanitizeQuestionWithAnswer(
            question
          )
      },
      "Question updated."
    );
  }
);

app.delete(
  "/api/admin/questions/:id",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    const exists =
      db.questions.some(
        (item) =>
          item.id === req.params.id
      );

    if (!exists) {
      return sendError(
        res,
        404,
        "Question not found."
      );
    }

    db.questions =
      db.questions.filter(
        (item) =>
          item.id !== req.params.id
      );

    db.bookmarks =
      db.bookmarks.filter(
        (item) =>
          item.questionId !==
          req.params.id
      );

    writeDatabase(db);

    createAuditLog(
      req.user.id,
      "admin_question_deleted",
      {
        questionId: req.params.id
      }
    );

    return sendSuccess(
      res,
      {},
      "Question deleted."
    );
  }
);


/* ============================================================
   ADMIN — USERS
============================================================ */

app.get(
  "/api/admin/users",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    const users =
      db.users.map(
        getPublicUser
      );

    return sendSuccess(
      res,
      paginate(
        users,
        req.query.page,
        req.query.limit
      )
    );
  }
);

app.get(
  "/api/admin/users/:id",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    const user =
      getUserById(
        db,
        req.params.id
      );

    if (!user) {
      return sendError(
        res,
        404,
        "User not found."
      );
    }

    return sendSuccess(res, {
      user: getPublicUser(user)
    });
  }
);


/* ============================================================
   ADMIN — STATISTICS
============================================================ */

app.get(
  "/api/admin/statistics",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    return sendSuccess(res, {
      users: db.users.length,
      questions: db.questions.length,
      quizAttempts:
        db.quizAttempts.length,
      quizResults:
        db.quizResults.length,
      battles:
        db.battles.length,
      feedback:
        db.feedback.length,
      payments:
        db.payments.length,
      subscriptions:
        db.subscriptions.length,
      libraryItems:
        db.library.length,
      pharmacopoeiaEntries:
        db.pharmacopoeia.length
    });
  }
);


/* ============================================================
   ADMIN — AUDIT LOGS
============================================================ */

app.get(
  "/api/admin/audit-logs",
  authRequired,
  adminRequired,
  (req, res) => {
    const db = readDatabase();

    const logs =
      [...db.auditLogs]
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    return sendSuccess(
      res,
      paginate(
        logs,
        req.query.page,
        req.query.limit
      )
    );
  }
);


/* ============================================================
   PUBLIC STATISTICS
============================================================ */

app.get(
  "/api/statistics",
  (req, res) => {
    const db = readDatabase();

    return sendSuccess(res, {
      platform: APP_NAME,
      contentYear: CONTENT_YEAR,
      statistics: {
        registeredStudents:
          db.users.length,
        questions:
          db.questions.length,
        subjects:
          SUBJECTS.length,
        quizzesCompleted:
          db.quizResults.length,
        battles:
          db.battles.length,
        libraryResources:
          db.library.length,
        pharmacopoeiaResources:
          db.pharmacopoeia.length,
        supportedLanguages:
          db.languages.length
      }
    });
  }
);


/* ============================================================
   PUBLIC SUBJECT INFORMATION
============================================================ */

app.get(
  "/api/subjects/:subject",
  (req, res) => {
    const subject = SUBJECTS.find(
      (item) =>
        item.toLowerCase() ===
        String(
          req.params.subject
        ).toLowerCase()
    );

    if (!subject) {
      return sendError(
        res,
        404,
        "Subject not found."
      );
    }

    const db = readDatabase();

    const questionCount =
      db.questions.filter(
        (item) =>
          String(item.subject)
            .toLowerCase() ===
          subject.toLowerCase()
      ).length;

    return sendSuccess(res, {
      subject,
      questionCount
    });
  }
);


/* ============================================================
   ADMIN — LIBRARY MANAGEMENT
============================================================ */

app.post(
  "/api/admin/library",
  authRequired,
  adminRequired,
  (req, res) => {
    const item = {
      id: generateId("library"),
      title: safeText(
        req.body.title,
        300
      ),
      description: safeText(
        req.body.description,
        2000
      ),
      subject: safeText(
        req.body.subject,
        150
      ),
      topic: safeText(
        req.body.topic,
        150
      ),
      type: safeText(
        req.body.type,
        50
      ),
      url: safeText(
        req.body.url,
        1000
      ),
      premium:
        Boolean(req.body.premium),
      createdAt: nowISO(),
      updatedAt: nowISO(),
      createdBy: req.user.id
    };

    if (!item.title) {
      return sendError(
        res,
        400,
        "Library title is required."
      );
    }

    updateDatabase((db) => {
      db.library.push(item);
    });

    createAuditLog(
      req.user.id,
      "admin_library_created",
      {
        libraryId: item.id
      }
    );

    return sendSuccess(
      res,
      { item },
      "Library resource created.",
      201
    );
  }
);


/* ============================================================
   ADMIN — PHARMACOPOEIA MANAGEMENT
============================================================ */

app.post(
  "/api/admin/pharmacopoeia",
  authRequired,
  adminRequired,
  (req, res) => {
    const entry = {
      id: generateId(
        "pharmacopoeia"
      ),
      title: safeText(
        req.body.title,
        300
      ),
      pharmacopoeia: safeText(
        req.body.pharmacopoeia,
        100
      ),
      category: safeText(
        req.body.category,
        150
      ),
      description: safeText(
        req.body.description,
        3000
      ),
      notes: safeText(
        req.body.notes,
        5000
      ),
      references:
        Array.isArray(
          req.body.references
        )
          ? req.body.references.map(
              (item) =>
                safeText(item, 500)
            )
          : [],
      createdAt: nowISO(),
      updatedAt: nowISO(),
      createdBy: req.user.id
    };

    if (!entry.title) {
      return sendError(
        res,
        400,
        "Pharmacopoeia title is required."
      );
    }

    updateDatabase((db) => {
      db.pharmacopoeia.push(entry);
    });

    createAuditLog(
      req.user.id,
      "admin_pharmacopoeia_created",
      {
        entryId: entry.id
      }
    );

    return sendSuccess(
      res,
      { entry },
      "Pharmacopoeia entry created.",
      201
    );
  }
);


/* ============================================================
   ADMIN — LANGUAGE MANAGEMENT
============================================================ */

app.post(
  "/api/admin/languages",
  authRequired,
  adminRequired,
  (req, res) => {
    const language = {
      id: generateId("language"),
      name: safeText(
        req.body.name,
        100
      ),
      code: safeText(
        req.body.code,
        20
      ).toLowerCase(),
      nativeName: safeText(
        req.body.nativeName,
        100
      ),
      createdAt: nowISO()
    };

          if (!language.name || !language.code) {
        return sendError(
          res,
          400,
          "Language name and code are required."
        );
      }

      const existing = db.languages.find(
        (item) =>
          item.code.toLowerCase() === language.code.toLowerCase()
      );

      if (existing) {
        return sendError(
          res,
          409,
          "A language with this code already exists."
        );
      }

      db.languages.push(language);
      writeDatabase(db);

      createAuditLog(
        req.user.id,
        "language_created",
        {
          languageId: language.id,
          code: language.code
        }
      );

      return sendSuccess(
        res,
        { language },
        "Language created successfully.",
        201
      );
    }
  );

  /*
   * ============================================================
   * ADMIN LANGUAGE PHRASE MANAGEMENT
   * ============================================================
   */

  app.post(
    "/api/admin/languages/:languageId/phrases",
    authRequired,
    adminRequired,
    (req, res) => {
      const db = readDatabase();

      const language = db.languages.find(
        (item) => item.id === req.params.languageId
      );

      if (!language) {
        return sendError(res, 404, "Language not found.");
      }

      const phrase = {
        id: generateId("phrase"),
        languageId: language.id,
        category: safeText(req.body.category, 100),
        english: safeText(req.body.english, 500),
        translation: safeText(req.body.translation, 500),
        pronunciation: safeText(req.body.pronunciation, 500),
        counsellingNote: safeText(
          req.body.counsellingNote,
          1000
        ),
        createdAt: nowISO()
      };

      if (!phrase.english || !phrase.translation) {
        return sendError(
          res,
          400,
          "English phrase and translation are required."
        );
      }

      db.languagePhrases.push(phrase);
      writeDatabase(db);

      createAuditLog(
        req.user.id,
        "language_phrase_created",
        {
          languageId: language.id,
          phraseId: phrase.id
        }
      );

      return sendSuccess(
        res,
        { phrase },
        "Language phrase created successfully.",
        201
      );
    }
  );

  /*
   * ============================================================
   * BATTLE STATUS
   * ============================================================
   */

  app.get(
    "/api/battles/:id",
    authRequired,
    (req, res) => {
      const db = readDatabase();

      const battle = db.battles.find(
        (item) => item.id === req.params.id
      );

      if (!battle) {
        return sendError(res, 404, "Battle not found.");
      }

      const isParticipant =
        battle.creatorId === req.user.id ||
        battle.opponentId === req.user.id;

      if (!isParticipant) {
        return sendError(
          res,
          403,
          "You are not a participant in this battle."
        );
      }

      /*
       * Enforce battle expiration on status checks.
       */
      if (
        battle.status === "active" &&
        battle.endsAt &&
        new Date(battle.endsAt).getTime() <= Date.now()
      ) {
        battle.status = "expired";
        battle.completedAt = nowISO();

        writeDatabase(db);
      }

      const responseBattle = {
        id: battle.id,
        type: battle.type,
        status: battle.status,
        creatorId: battle.creatorId,
        opponentId: battle.opponentId,
        questionIds: battle.questionIds,
        startedAt: battle.startedAt,
        endsAt: battle.endsAt,
        completedAt: battle.completedAt,
        creatorScore: battle.creatorScore || 0,
        opponentScore: battle.opponentScore || 0,
        winnerId: battle.winnerId || null,
        createdAt: battle.createdAt
      };

      return sendSuccess(
        res,
        { battle: responseBattle },
        "Battle status retrieved."
      );
    }
  );

  /*
   * ============================================================
   * BATTLE SUBMISSION EXPIRATION / CLEANUP
   * ============================================================
   */

  app.post(
    "/api/battles/:id/expire",
    authRequired,
    (req, res) => {
      const db = readDatabase();

      const battle = db.battles.find(
        (item) => item.id === req.params.id
      );

      if (!battle) {
        return sendError(res, 404, "Battle not found.");
      }

      const isParticipant =
        battle.creatorId === req.user.id ||
        battle.opponentId === req.user.id;

      if (!isParticipant) {
        return sendError(
          res,
          403,
          "You are not a participant in this battle."
        );
      }

      if (battle.status !== "active") {
        return sendSuccess(
          res,
          { battle },
          "Battle is not active."
        );
      }

      if (
        battle.endsAt &&
        new Date(battle.endsAt).getTime() > Date.now()
      ) {
        return sendError(
          res,
          400,
          "Battle has not expired yet."
        );
      }

      battle.status = "expired";
      battle.completedAt = nowISO();

      writeDatabase(db);

      createAuditLog(
        req.user.id,
        "battle_expired",
        {
          battleId: battle.id
        }
      );

      return sendSuccess(
        res,
        { battle },
        "Battle expired."
      );
    }
  );

  /*
   * ============================================================
   * SESSION CLEANUP
   * ============================================================
   */

  function cleanupExpiredSessions() {
    const db = readDatabase();
    const before = db.sessions.length;

    db.sessions = db.sessions.filter(
      (session) =>
        session.expiresAt &&
        new Date(session.expiresAt).getTime() > Date.now()
    );

    if (db.sessions.length !== before) {
      writeDatabase(db);
    }

    return before - db.sessions.length;
  }

  /*
   * ============================================================
   * PERIODIC MAINTENANCE
   * ============================================================
   */

  const maintenanceInterval = setInterval(() => {
    try {
      cleanupExpiredSessions();
    } catch (error) {
      console.error(
        "DENexpharm maintenance error:",
        error
      );
    }
  }, 60 * 60 * 1000);

  /*
   * ============================================================
   * STATIC FRONTEND
   * ============================================================
   */

  app.use(express.static(PUBLIC_DIR));

  /*
   * ============================================================
   * SPA FALLBACK
   * ============================================================
   */

  app.use((req, res, next) => {
    if (
      req.method === "GET" &&
      !req.path.startsWith("/api") &&
      req.path !== "/health"
    ) {
      const indexFile = path.join(
        PUBLIC_DIR,
        "index.html"
      );

      if (fs.existsSync(indexFile)) {
        return res.sendFile(indexFile);
      }
    }

    return next();
  });

  /*
   * ============================================================
   * 404 HANDLER
   * ============================================================
   */

  app.use((req, res) => {
    if (req.path.startsWith("/api")) {
      return sendError(
        res,
        404,
        "API route not found."
      );
    }

    return res.status(404).send("Page not found.");
  });

  /*
   * ============================================================
   * GLOBAL ERROR HANDLER
   * ============================================================
   */

  app.use((err, req, res, next) => {
    console.error(
      "DENexpharm server error:",
      err
    );

    if (res.headersSent) {
      return next(err);
    }

    return sendError(
      res,
      500,
      IS_PRODUCTION
        ? "Internal server error."
        : err.message || "Internal server error."
    );
  });

  /*
   * ============================================================
   * DATABASE INITIALIZATION
   * ============================================================
   */

  ensureDatabase();
  seedContent();

  /*
   * ============================================================
   * START SERVER
   * ============================================================
   */

  const server = app.listen(PORT, () => {
    console.log("============================================================");
    console.log("DENexpharm server started");
    console.log("============================================================");
    console.log(`Application : ${APP_NAME}`);
    console.log(`Version     : ${APP_VERSION}`);
    console.log(`Content     : ${CONTENT_YEAR}`);
    console.log(`Environment : ${NODE_ENV}`);
    console.log(`Port        : ${PORT}`);
    console.log(`URL         : http://localhost:${PORT}`);
    console.log("============================================================");
  });

  /*
   * ============================================================
   * GRACEFUL SHUTDOWN
   * ============================================================
   */

  function gracefulShutdown(signal) {
    console.log(
      `\n${signal} received. Shutting down DENexpharm...`
    );

    clearInterval(maintenanceInterval);

    server.close((error) => {
      if (error) {
        console.error(
          "Error while shutting down server:",
          error
        );

        process.exit(1);
      }

      console.log(
        "DENexpharm server stopped successfully."
      );

      process.exit(0);
    });

    setTimeout(() => {
      console.error(
        "Forced shutdown after timeout."
      );

      process.exit(1);
    }, 10000).unref();
  }

  process.on(
    "SIGTERM",
    () => gracefulShutdown("SIGTERM")
  );

  process.on(
    "SIGINT",
    () => gracefulShutdown("SIGINT")
  );

  /*
   * ============================================================
   * PROCESS ERROR HANDLING
   * ============================================================
   */

  process.on(
    "unhandledRejection",
    (reason) => {
      console.error(
        "Unhandled promise rejection:",
        reason
      );
    }
  );

  process.on(
    "uncaughtException",
    (error) => {
      console.error(
        "Uncaught exception:",
        error
      );

      /*
       * Give the process a short opportunity to flush logs
       * before exiting. This prevents the application from
       * continuing in an unknown state.
       */
      setTimeout(() => {
        process.exit(1);
      }, 1000).unref();
    }
  );

  /*
   * ============================================================
   * EXPORT APP
   * ============================================================
   */

  module.exports = app;
       
