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
          "Use proportion to scale solution quantities        learningPoints: [
          "Percentage w/v means grams of solute per 100 mL of solution.",
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

app.post("/api/battles/quick", authRequired, (req, res) => {
  const db = readDatabase();

  const count = clampNumber(req.body.count || 10, 1, 30, 10);

  const questions = selectQuestions(db, {
    subject: req.body.subject,
    difficulty: req.body.difficulty
  }).slice(0, count);

  if (!questions.length) {
    return sendError(res, 404, "No battle questions available.");
  }

  const battle = {
    id: generateId("battle"),
    type: "quick",
    hostId: req.user.id,
    opponentId: null,
    status: "waiting",
    questionIds: questions.map((q) => q.id),
    createdAt: nowISO()
  };

  updateDatabase((database) => {
    database.battles.push(battle);
  });

  return sendSuccess(res, {
    battleId: battle.id,
    status: battle.status,
    questions: questions.map(sanitizeQuestion)
  }, "Quick battle created.", 201);
});

app.post("/api/battles/:id/join", authRequired, (req, res) => {
  const db = readDatabase();

  const battle = db.battles.find(
    (item) => item.id === req.params.id
  );

  if (!battle) {
    return sendError(res, 404, "Battle not found.");
  }

  if (battle.hostId === req.user.id) {
    return sendError(res, 400, "You cannot join your own battle.");
  }

  if (battle.opponentId) {
    return sendError(res, 400, "Battle already has an opponent.");
  }

  battle.opponentId = req.user.id;
  battle.status = "active";
  battle.startedAt = nowISO();

  writeDatabase(db);

  return sendSuccess(res, {
    battle
  });
});

app.post(
  "/api/battles/:id/submit",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const battle = db.battles.find(
      (item) => item.id === req.params.id
    );

    if (!battle) {
      return sendError(res, 404, "Battle not found.");
    }

    if (
      battle.hostId !== req.user.id &&
      battle.opponentId !== req.user.id
    ) {
      return sendError(res, 403, "You are not part of this battle.");
    }

    const answers = Array.isArray(req.body.answers)
      ? req.body.answers
      : [];

    const questions = battle.questionIds
      .map((id) => findQuestion(db, id))
      .filter(Boolean);

    const score = calculateQuizScore(questions, answers);

    battle.submissions = battle.submissions || {};

    battle.submissions[req.user.id] = {
      score,
      submittedAt: nowISO()
    };

    const participantIds = [
      battle.hostId,
      battle.opponentId
    ].filter(Boolean);

    if (
      participantIds.length === 2 &&
      participantIds.every(
        (id) => battle.submissions[id]
      )
    ) {
      const first = battle.submissions[participantIds[0]];
      const second = battle.submissions[participantIds[1]];

      battle.status = "completed";
      battle.completedAt = nowISO();

      let winnerId = null;

      if (first.score.correct > second.score.correct) {
        winnerId = participantIds[0];
      } else if (
        second.score.correct > first.score.correct
      ) {
        winnerId = participantIds[1];
      }

      battle.winnerId = winnerId;

      participantIds.forEach((id) => {
        const user = getUserById(db, id);

        if (!user) return;

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

        user.level = calculateLevel(user.xp);
      });

      writeDatabase(db);
    } else {
      writeDatabase(db);
    }

    return sendSuccess(res, {
      battleId: battle.id,
      status: battle.status,
      score,
      winnerId: battle.winnerId || null
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

app.get(
  "/api/languages/phrases",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    let phrases = [...db.languagePhrases];

    if (req.query.language) {
      phrases = phrases.filter(
        (item) =>
          String(item.language).toLowerCase() ===
          String(req.query.language).toLowerCase()
      );
    }

    if (req.query.search) {
      const search = String(req.query.search).toLowerCase();

      phrases = phrases.filter((item) =>
        JSON.stringify(item)
          .toLowerCase()
          .includes(search)
      );
    }

    return sendSuccess(res, { phrases });
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
       
