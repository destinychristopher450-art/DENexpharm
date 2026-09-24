"use strict";

/* ============================================================
   DENexpharm
   FULL-STACK PHARMACY LEARNING, GPA, COMPETITION
   & STUDENT PLATFORM

   Version: 3.2.0
   Content Year: 2026
   Node.js: >=18
   Express: 5.x

   COMPLETE BACKEND
   ------------------------------------------------------------
   1. Configuration
   2. Subjects
   3. Database Structure
   4. Time / ID Utilities
   5. Validation / Normalization
   6. Pagination
   7. Response Helpers
   8. Database Management
   9. Password Security
   10. Rate Limiter
   11. User Helpers
   12. Rewards / Wallet Engine
   13. Achievements
   14. Subscriptions
   15. Authentication
   16. Audit Logs
   17. Question Engine
   18. Express Middleware
   19. Health / Configuration / Stats
   20. Authentication Routes
   21. Profile Routes
   22. Search
   23. Questions
   24. Timed Quiz
   25. Battle Engine
   26. Daily Challenge
   27. Leaderboards
   28. Achievements Routes
   29. Wallet
   30. Referrals
   31. Subscriptions
   32. Pharmacopoeia Hub
   33. Pharmacy Language Assistant
   34. Bookmarks
   35. Analytics
   36. Notifications
   37. Feedback
   38. GPA
   39. Admin Questions
   40. Admin Users
   41. Admin Language
   42. Admin Audit Logs
   43. Seed Content
   44. Database Migration
   45. Static Frontend
   46. 404
   47. Global Error Handler
   48. Startup
   49. Export
   ============================================================ */

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

/* ============================================================
   1. APP CONFIGURATION
   ============================================================ */

const app = express();

app.disable("x-powered-by");

const PORT =
  Number(process.env.PORT) || 3000;

const CONFIG = {
  appName: "DENexpharm",
  version: "3.2.0",
  contentYear: "2026",
  nodeVersion: ">=18",
  environment:
    process.env.NODE_ENV || "development",

  databaseVersion: 2,

  sessionDays: 30,

  battle: {
    questionCount: 5,
    durationMinutes: 5
  },

  quiz: {
    defaultCount: 10,
    defaultDurationMinutes: 10,
    maxQuestions: 50
  },

  security: {
    passwordMinLength: 6,
    passwordMaxLength: 200,
    bodyLimit: "2mb"
  },

  pagination: {
    maxPageSize: 100,
    defaultPageSize: 20
  }
};

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "*";

const DATA_DIR =
  path.join(__dirname, "data");

const DB_FILE =
  path.join(
    DATA_DIR,
    "database.json"
  );

const PUBLIC_DIR =
  path.join(
    __dirname,
    "public"
  );

/* ============================================================
   2. SUBJECTS
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
  "Toxicology",
  "Pathophysiology",
  "Pharmacotherapy",
  "Hospital Pharmacy",
  "Community Pharmacy",
  "Industrial Pharmacy",
  "Regulatory Pharmacy",
  "Biopharmaceutics",
  "Pharmacokinetics",
  "Pharmaceutical Calculations"
];

/* ============================================================
   3. DATABASE STRUCTURE
   ============================================================ */

/*
   JSON DATABASE DESIGN

   We deliberately keep the database collections simple.

   There is NO separate:
     - battleScores collection
     - battleParticipants collection
     - battleStatuses collection

   Battle-specific information lives inside each battle.

   This is appropriate for the current MVP architecture.

   Database versioning allows future migrations without
   destroying existing data.
*/

const EMPTY_DATABASE = {
  meta: {
    databaseVersion:
      CONFIG.databaseVersion,
    createdAt:
      null,
    updatedAt:
      null
  },

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
   4. TIME & ID UTILITIES
   ============================================================ */

function nowISO() {
  return new Date().toISOString();
}

function addDays(
  date,
  days
) {
  const result =
    new Date(date);

  result.setDate(
    result.getDate() +
      Number(days || 0)
  );

  return result.toISOString();
}

function addMinutes(
  date,
  minutes
) {
  const result =
    new Date(date);

  result.setMinutes(
    result.getMinutes() +
      Number(minutes || 0)
  );

  return result.toISOString();
}

function todayKey() {
  return new Date()
    .toISOString()
    .slice(0, 10);
}

function generateId(
  prefix = "id"
) {
  return (
    prefix +
    "_" +
    Date.now().toString(36) +
    "_" +
    crypto
      .randomBytes(6)
      .toString("hex")
  );
}

function generateSecureToken() {
  return crypto
    .randomBytes(48)
    .toString("hex");
}

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

/* ============================================================
   5. VALIDATION / NORMALIZATION
   ============================================================ */

function normalizeEmail(
  email
) {
  return String(email || "")
    .trim()
    .toLowerCase();
}

function safeText(
  value,
  maxLength = 500
) {
  return String(value ?? "")
    .trim()
    .slice(0, maxLength);
}

function isValidEmail(
  email
) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function isValidPassword(
  password
) {
  return (
    typeof password ===
      "string" &&
    password.length >=
      CONFIG.security
        .passwordMinLength &&
    password.length <=
      CONFIG.security
        .passwordMaxLength
  );
}

function isValidUsername(
  username
) {
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
  const number =
    Number(value);

  if (
    !Number.isFinite(number)
  ) {
    return fallback;
  }

  return Math.min(
    max,
    Math.max(min, number)
  );
}

/* ============================================================
   6. PAGINATION
   ============================================================ */

function paginate(
  items,
  page = 1,
  limit =
    CONFIG.pagination
      .defaultPageSize
) {
  page = Math.max(
    1,
    Number(page) || 1
  );

  limit = Math.min(
    CONFIG.pagination
      .maxPageSize,
    Math.max(
      1,
      Number(limit) ||
        CONFIG.pagination
          .defaultPageSize
    )
  );

  const total =
    items.length;

  const totalPages =
    Math.max(
      1,
      Math.ceil(
        total / limit
      )
    );

  const start =
    (page - 1) *
    limit;

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
   7. RESPONSE HELPERS
   ============================================================ */

function sendSuccess(
  res,
  data = {},
  message = "Success.",
  status = 200
) {
  return res
    .status(status)
    .json({
      success: true,
      message,
      data
    });
}

function sendError(
  res,
  status = 400,
  message = "Request failed.",
  details
) {
  const payload = {
    success: false,
    message
  };

  if (
    details !== undefined
  ) {
    payload.details =
      details;
  }

  return res
    .status(status)
    .json(payload);
}

/* ============================================================
   8. DATABASE MANAGEMENT
   ============================================================ */

function ensureDatabase() {
  if (
    !fs.existsSync(DATA_DIR)
  ) {
    fs.mkdirSync(
      DATA_DIR,
      {
        recursive: true
      }
    );
  }

  if (
    !fs.existsSync(DB_FILE)
  ) {
    const database = {
      ...EMPTY_DATABASE,
      meta: {
        databaseVersion:
          CONFIG.databaseVersion,
        createdAt:
          nowISO(),
        updatedAt:
          nowISO()
      }
    };

    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(
        database,
        null,
        2
      ),
      "utf8"
    );
  }
}

function normalizeDatabase(
  db
) {
  const normalized = {
    ...EMPTY_DATABASE,
    ...(db || {})
  };

  normalized.meta = {
    ...EMPTY_DATABASE.meta,
    ...(db?.meta || {})
  };

  for (
    const key of Object.keys(
      EMPTY_DATABASE
    )
  ) {
    if (
      key === "meta"
    ) {
      continue;
    }

    if (
      !Array.isArray(
        normalized[key]
      )
    ) {
      normalized[key] = [];
    }
  }

  normalized.meta.databaseVersion =
    Number(
      normalized.meta
        .databaseVersion
    ) ||
    1;

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
      "[DATABASE] Read error:",
      error
    );

    return normalizeDatabase(
      {}
    );
  }
}

function writeDatabase(
  db
) {
  ensureDatabase();

  const normalized =
    normalizeDatabase(db);

  normalized.meta.updatedAt =
    nowISO();

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

function updateDatabase(
  callback
) {
  const db =
    readDatabase();

  const result =
    callback(db);

  writeDatabase(db);

  return result;
}

/* ============================================================
   9. PASSWORD SECURITY
   ============================================================ */

const PBKDF2_ITERATIONS =
  210000;

const PBKDF2_KEY_LENGTH =
  64;

const PBKDF2_DIGEST =
  "sha512";

function hashPassword(
  password
) {
  const salt =
    crypto.randomBytes(
      32
    );

  const derivedKey =
    crypto.pbkdf2Sync(
      password,
      salt,
      PBKDF2_ITERATIONS,
      PBKDF2_KEY_LENGTH,
      PBKDF2_DIGEST
    );

  return {
    algorithm:
      "pbkdf2-sha512",

    salt:
      salt.toString(
        "hex"
      ),

    hash:
      derivedKey.toString(
        "hex"
      ),

    iterations:
      PBKDF2_ITERATIONS,

    keyLength:
      PBKDF2_KEY_LENGTH
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

  try {
    const derivedKey =
      crypto.pbkdf2Sync(
        password,
        Buffer.from(
          stored.salt,
          "hex"
        ),
        stored.iterations ||
          PBKDF2_ITERATIONS,
        stored.keyLength ||
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
  } catch {
    return false;
  }
}

/* ============================================================
   10. RATE LIMITER
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

  return (
    req,
    res,
    next
  ) => {
    const ip =
      req.ip ||
      req.socket
        ?.remoteAddress ||
      "unknown";

    const key =
      `${ip}:${req.path}`;

    const current =
      Date.now();

    let record =
      rateLimitStore.get(
        key
      );

    if (
      !record ||
      current -
        record.start >
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

    if (
      record.count > max
    ) {
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
   11. USER HELPERS
   ============================================================ */

function getUserById(
  db,
  userId
) {
  return db.users.find(
    user =>
      user.id === userId
  );
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

  user.lastStreakDate =
    user.lastStreakDate ||
    null;

  user.referralCode =
    user.referralCode ||
    `DEN-${String(
      user.username ||
        "USER"
    )
      .toUpperCase()
      .slice(0, 6)}-${crypto
      .randomBytes(2)
      .toString("hex")
      .toUpperCase()}`;
}

function getPublicUser(
  user
) {
  if (!user) {
    return null;
  }

  ensureUserDefaults(
    user
  );

  return {
    id: user.id,

    username:
      user.username,

    displayName:
      user.displayName,

    email:
      user.email,

    country:
      user.country,

    institution:
      user.institution,

    curriculum:
      user.curriculum,

    yearLevel:
      user.yearLevel,

    semester:
      user.semester,

    role:
      user.role ||
      "student",

    xp:
      user.xp,

    coins:
      user.coins,

    level:
      user.level,

    streak:
      user.streak,

    questionsAnswered:
      user.questionsAnswered,

    correctAnswers:
      user.correctAnswers,

    quizzesCompleted:
      user.quizzesCompleted,

    battlesWon:
      user.battlesWon,

    battlesPlayed:
      user.battlesPlayed,

    createdAt:
      user.createdAt,

    lastActiveAt:
      user.lastActiveAt
  };
}

function calculateLevel(
  xp
) {
  return Math.max(
    1,
    Math.floor(
      Math.sqrt(
        Math.max(
          0,
          xp
        ) / 100
      )
    ) + 1
  );
}

/* ============================================================
   12. STREAK ENGINE
   ============================================================ */

function updateUserStreak(
  user
) {
  if (!user) {
    return;
  }

  ensureUserDefaults(
    user
  );

  const today =
    todayKey();

  if (
    user.lastStreakDate ===
    today
  ) {
    return;
  }

  if (
    !user.lastStreakDate
  ) {
    user.streak = 1;
    user.lastStreakDate =
      today;

    return;
  }

  const previous =
    new Date(
      `${user.lastStreakDate}T00:00:00Z`
    );

  const current =
    new Date(
      `${today}T00:00:00Z`
    );

  const difference =
    Math.round(
      (
        current.getTime() -
        previous.getTime()
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

  user.lastStreakDate =
    today;
}

/* ============================================================
   13. WALLET / REWARD ENGINE
   ============================================================ */

function getOrCreateWalletInDatabase(
  db,
  userId
) {
  let wallet =
    db.wallets.find(
      item =>
        item.userId ===
        userId
    );

  const user =
    getUserById(
      db,
      userId
    );

  if (!wallet) {
    wallet = {
      id:
        generateId(
          "wallet"
        ),

      userId,

      balance:
        Number(
          user?.coins
        ) || 0,

      lifetimeEarned: 0,

      lifetimeSpent: 0,

      createdAt:
        nowISO(),

      updatedAt:
        nowISO()
    };

    db.wallets.push(
      wallet
    );
  }

  return wallet;
}

function awardRewardsInDatabase(
  db,
  userId,
  xp = 0,
  coins = 0,
  reason = "Reward"
) {
  const user =
    getUserById(
      db,
      userId
    );

  if (!user) {
    return null;
  }

  ensureUserDefaults(
    user
  );

  const xpAmount =
    Math.max(
      0,
      Number(xp) || 0
    );

  const coinAmount =
    Math.max(
      0,
      Number(coins) || 0
    );

  const oldLevel =
    user.level;

  user.xp += xpAmount;

  user.coins +=
    coinAmount;

  user.level =
    calculateLevel(
      user.xp
    );

  const wallet =
    getOrCreateWalletInDatabase(
      db,
      userId
    );

  wallet.balance =
    user.coins;

  wallet.lifetimeEarned =
    Number(
      wallet.lifetimeEarned
    ) + coinAmount;

  wallet.updatedAt =
    nowISO();

  if (
    coinAmount > 0
  ) {
    db.walletTransactions.push({
      id:
        generateId(
          "wallet_tx"
        ),

      userId,

      type:
        "credit",

      amount:
        coinAmount,

      reason,

      createdAt:
        nowISO()
    });
  }

  if (
    user.level >
    oldLevel
  ) {
    db.notifications.push({
      id:
        generateId(
          "notification"
        ),

      userId,

      type:
        "level_up",

      title:
        "Level Up!",

      message:
        `Congratulations! You reached level ${user.level}.`,

      read: false,

      createdAt:
        nowISO()
    });
  }

  return user;
}

/* ============================================================
   14. ACHIEVEMENTS
   ============================================================ */

function evaluateAchievementsInDatabase(
  db,
  userId
) {
  const user =
    getUserById(
      db,
      userId
    );

  if (!user) {
    return;
  }

  ensureUserDefaults(
    user
  );

  const unlocked =
    new Set(
      db.userAchievements
        .filter(
          item =>
            item.userId ===
            userId
        )
        .map(
          item =>
            item.achievementId
        )
    );

  const conditions = [
    {
      id:
        "first_quiz",

      condition:
        user.quizzesCompleted >=
        1
    },

    {
      id:
        "questions_10",

      condition:
        user.questionsAnswered >=
        10
    },

    {
      id:
        "questions_100",

      condition:
        user.questionsAnswered >=
        100
    },

    {
      id:
        "battle_win",

      condition:
        user.battlesWon >=
        1
    },

    {
      id:
        "streak_7",

      condition:
        user.streak >=
        7
    }
  ];

  for (
    const condition of
    conditions
  ) {
    if (
      !condition.condition ||
      unlocked.has(
        condition.id
      )
    ) {
      continue;
    }

    const definition =
      db.achievements.find(
        achievement =>
          achievement.id ===
          condition.id
      );

    const rewardXP =
      Number(
        definition?.rewardXP
      ) || 50;

    const rewardCoins =
      Number(
        definition?.rewardCoins
      ) || 20;

    db.userAchievements.push({
      id:
        generateId(
          "userachievement"
        ),

      userId,

      achievementId:
        condition.id,

      unlockedAt:
        nowISO()
    });

    db.notifications.push({
      id:
        generateId(
          "notification"
        ),

      userId,

      type:
        "achievement",

      title:
        "Achievement Unlocked!",

      message:
        `You unlocked achievement: ${condition.id}`,

      read: false,

      createdAt:
        nowISO()
    });

    awardRewardsInDatabase(
      db,
      userId,
      rewardXP,
      rewardCoins,
      `Achievement: ${condition.id}`
    );
  }
}

/* ============================================================
   15. SUBSCRIPTIONS
   ============================================================ */

function getActiveSubscription(
  userId
) {
  const db =
    readDatabase();

  const now =
    new Date();

  return (
    db.subscriptions.find(
      item =>
        item.userId ===
          userId &&
        item.status ===
          "active" &&
        item.expiresAt &&
        new Date(
          item.expiresAt
        ) > now
    ) || null
  );
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
   16. AUTHENTICATION
   ============================================================ */

function createSession(
  userId
) {
  const db =
    readDatabase();

  const rawToken =
    generateSecureToken();

  const tokenHash =
    sha256(rawToken);

  db.sessions.push({
    id:
      generateId(
        "session"
      ),

    userId,

    tokenHash,

    createdAt:
      nowISO(),

    expiresAt:
      addDays(
        new Date(),
        CONFIG.sessionDays
      )
  });

  writeDatabase(db);

  return rawToken;
}

function getBearerToken(
  req
) {
  const header =
    req.headers
      .authorization ||
    "";

  if (
    !header.startsWith(
      "Bearer "
    )
  ) {
    return null;
  }

  return header
    .slice(7)
    .trim();
}

function authRequired(
  req,
  res,
  next
) {
  const token =
    getBearerToken(req);

  if (!token) {
    return sendError(
      res,
      401,
      "Authentication required."
    );
  }

  const db =
    readDatabase();

  const tokenHash =
    sha256(token);

  const session =
    db.sessions.find(
      item =>
        item.tokenHash ===
          tokenHash &&
        item.expiresAt &&
        new Date(
          item.expiresAt
        ) > new Date()
    );

  if (!session) {
    return sendError(
      res,
      401,
      "Invalid or expired session."
    );
  }

  const user =
    getUserById(
      db,
      session.userId
    );

  if (!user) {
    return sendError(
      res,
      401,
      "User not found."
    );
  }

  ensureUserDefaults(
    user
  );

  user.lastActiveAt =
    nowISO();

  req.user =
    user;

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
   17. AUDIT LOGS
   ============================================================ */

function createAuditLog(
  userId,
  action,
  details = {}
) {
  updateDatabase(
    db => {
      db.auditLogs.push({
        id:
          generateId(
            "audit"
          ),

        userId:
          userId || null,

        action,

        details,

        createdAt:
          nowISO()
      });
    }
  );
}

/* ============================================================
   18. QUESTION ENGINE
   ============================================================ */

function sanitizeQuestion(
  question
) {
  if (!question) {
    return null;
  }

  return {
    id:
      question.id,

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

    learningPoints:
      question.learningPoints ||
      []
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
    const subject =
      String(
        options.subject
      )
        .toLowerCase()
        .trim();

    questions =
      questions.filter(
        question =>
          String(
            question.subject ||
              ""
          )
            .toLowerCase()
            .trim() ===
          subject
      );
  }

  if (
    options.difficulty
  ) {
    const difficulty =
      String(
        options.difficulty
      )
        .toLowerCase()
        .trim();

    questions =
      questions.filter(
        question =>
          String(
            question.difficulty ||
              ""
          )
            .toLowerCase()
            .trim() ===
          difficulty
      );
  }

  for (
    let i =
      questions.length -
      1;
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

function calculateQuizScore(
  questions,
  answers
) {
  let correct = 0;

  questions.forEach(
    (
      question,
      index
    ) => {
      const submitted =
        answers?.[index];

      if (
        String(
          submitted ?? ""
        )
          .trim()
          .toLowerCase() ===
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
            (correct /
              total) *
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

/* ============================================================
   19. EXPRESS MIDDLEWARE
   ============================================================ */

app.set(
  "trust proxy",
  1
);

app.use(
  cors({
    origin:
      FRONTEND_ORIGIN ===
      "*"
        ? true
        : FRONTEND_ORIGIN
            .split(",")
            .map(
              item =>
                item.trim()
            )
            .filter(Boolean),

    credentials:
      true
  })
);

app.use(
  express.json({
    limit:
      CONFIG.security
        .bodyLimit
  })
);

app.use(
  express.urlencoded({
    extended: true,

    limit:
      CONFIG.security
        .bodyLimit
  })
);

app.use(
  rateLimit()
);

/* ============================================================
   20. HEALTH / CONFIG / PUBLIC STATS
   ============================================================ */

app.get(
  "/health",
  (req, res) => {
    return sendSuccess(
      res,
      {
        app:
          CONFIG.appName,

        status:
          "healthy",

        timestamp:
          nowISO()
      }
    );
  }
);

app.get(
  "/api/health",
  (req, res) => {
    return sendSuccess(
      res,
      {
        app:
          CONFIG.appName,

        status:
          "healthy",

        version:
          CONFIG.version,

        databaseVersion:
          CONFIG.databaseVersion,

        timestamp:
          nowISO()
      }
    );
  }
);

app.get(
  "/api/config",
  (req, res) => {
    return sendSuccess(
      res,
      {
        appName:
          CONFIG.appName,

        version:
          CONFIG.version,

        contentYear:
          CONFIG.contentYear,

        subjects:
          SUBJECTS,

        battle:
          CONFIG.battle,

        quiz:
          CONFIG.quiz
      }
    );
  }
);

app.get(
  "/api/stats",
  (req, res) => {
    const db =
      readDatabase();

    return sendSuccess(
      res,
      {
        totalUsers:
          db.users.length,

        totalQuestions:
          db.questions.length,

        totalQuizzesCompleted:
          db.quizAttempts.filter(
            item =>
              item.status ===
              "completed"
          ).length,

        totalBattlesPlayed:
          db.battles.filter(
            battle =>
              battle.status ===
                "completed" ||
              battle.status ===
                "draw" ||
              battle.status ===
                "expired"
          ).length
      }
    );
  }
);

/* ============================================================
   21. AUTH ROUTES
   ============================================================ */

app.post(
  "/api/auth/register",
  (req, res) => {
    const email =
      normalizeEmail(
        req.body.email
      );

    const username =
      safeText(
        req.body.username,
        30
      );

    const password =
      req.body.password;

    const displayName =
      safeText(
        req.body.displayName,
        100
      ) || username;

    const referralCodeUsed =
      safeText(
        req.body.referralCode,
        50
      );

    if (
      !isValidEmail(
        email
      )
    ) {
      return sendError(
        res,
        400,
        "Invalid email address."
      );
    }

    if (
      !isValidUsername(
        username
      )
    ) {
      return sendError(
        res,
        400,
        "Invalid username."
      );
    }

    if (
      !isValidPassword(
        password
      )
    ) {
      return sendError(
        res,
        400,
        "Password must be 6-200 characters."
      );
    }

    const result =
      updateDatabase(
        db => {
          if (
            db.users.some(
              user =>
                normalizeEmail(
                  user.email
                ) ===
                email
            )
          ) {
            return {
              error:
                "Email already exists."
            };
          }

          if (
            db.users.some(
              user =>
                String(
                  user.username
                )
                  .toLowerCase() ===
                username.toLowerCase()
            )
          ) {
            return {
              error:
                "Username already taken."
            };
          }

          const user = {
            id:
              generateId(
                "user"
              ),

            email,

            username,

            displayName,

            role:
              "student",

            password:
              hashPassword(
                password
              ),

            xp: 0,

            coins: 0,

            level: 1,

            streak: 0,

            lastStreakDate:
              null,

            questionsAnswered:
              0,

            correctAnswers:
              0,

            quizzesCompleted:
              0,

            battlesWon:
              0,

            battlesPlayed:
              0,

            createdAt:
              nowISO(),

            lastActiveAt:
              nowISO()
          };

          ensureUserDefaults(
            user
          );

          db.users.push(
            user
          );

          db.wallets.push({
            id:
              generateId(
                "wallet"
              ),

            userId:
              user.id,

            balance: 0,

            lifetimeEarned:
              0,

            lifetimeSpent:
              0,

            createdAt:
              nowISO(),

            updatedAt:
              nowISO()
          });

          if (
            referralCodeUsed
          ) {
            const referrer =
              db.users.find(
                existingUser =>
                  existingUser.referralCode ===
                  referralCodeUsed
              );

            if (
              referrer &&
              referrer.id !==
                user.id
            ) {
              db.referrals.push({
                id:
                  generateId(
                    "ref"
                  ),

                referrerId:
                  referrer.id,

                referredUserId:
                  user.id,

                status:
                  "registered",

                createdAt:
                  nowISO()
              });
            }
          }

          return {
            user
          };
        }
      );

    if (
      result.error
    ) {
      return sendError(
        res,
        409,
        result.error
      );
    }

    const token =
      createSession(
        result.user.id
      );

    createAuditLog(
      result.user.id,
      "register"
    );

    return sendSuccess(
      res,
      {
        token,

        user:
          getPublicUser(
            result.user
          )
      },
      "Account created successfully.",
      201
    );
  }
);

app.post(
  "/api/auth/login",
  (req, res) => {
    const email =
      normalizeEmail(
        req.body.email
      );

    const password =
      req.body.password;

    const db =
      readDatabase();

    const user =
      db.users.find(
        item =>
          normalizeEmail(
            item.email
          ) ===
          email
      );

    if (
      !user ||
      !verifyPassword(
        password,
        user.password
      )
    ) {
      return sendError(
        res,
        401,
        "Invalid email or password."
      );
    }

    ensureUserDefaults(
      user
    );

    const token =
      createSession(
        user.id
      );

    updateDatabase(
      database => {
        const currentUser =
          getUserById(
            database,
            user.id
          );

        if (
          currentUser
        ) {
          currentUser.lastActiveAt =
            nowISO();
        }
      }
    );

    createAuditLog(
      user.id,
      "login"
    );

    return sendSuccess(
      res,
      {
        token,

        user:
          getPublicUser(
            user
          )
      },
      "Login successful."
    );
  }
);

app.post(
  "/api/auth/logout",
  authRequired,
  (req, res) => {
    const token =
      getBearerToken(req);

    updateDatabase(
      db => {
        const hash =
          sha256(token);

        db.sessions =
          db.sessions.filter(
            session =>
              session.tokenHash !==
              hash
          );
      }
    );

    createAuditLog(
      req.user.id,
      "logout"
    );

    return sendSuccess(
      res,
      {},
      "Logged out successfully."
    );
  }
);

app.get(
  "/api/auth/me",
  authRequired,
  (req, res) => {
    return sendSuccess(
      res,
      {
        user:
          getPublicUser(
            req.user
          ),

        premium:
          isPremiumUser(
            req.user.id
          )
      }
    );
  }
);

/* ============================================================
   22. PROFILE
   ============================================================ */

app.get(
  "/api/profile",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const user =
      getUserById(
        db,
        req.user.id
      );

    return sendSuccess(
      res,
      {
        user:
          getPublicUser(
            user
          ),

        premium:
          isPremiumUser(
            user.id
          )
      }
    );
  }
);

app.patch(
  "/api/profile",
  authRequired,
  (req, res) => {
    const allowed = [
      "displayName",
      "country",
      "institution",
      "curriculum",
      "yearLevel",
      "semester"
    ];

    updateDatabase(
      db => {
        const user =
          getUserById(
            db,
            req.user.id
          );

        if (!user) {
          return;
        }

        allowed.forEach(
          field => {
            if (
              req.body[field] !==
              undefined
            ) {
              user[field] =
                safeText(
                  req.body[field],
                  150
                );
            }
          }
        );

        user.lastActiveAt =
          nowISO();
      }
    );

    createAuditLog(
      req.user.id,
      "profile_update"
    );

    const db =
      readDatabase();

    return sendSuccess(
      res,
      {
        user:
          getPublicUser(
            getUserById(
              db,
              req.user.id
            )
          )
      },
      "Profile updated successfully."
    );
  }
);

/* ============================================================
   23. SEARCH
   ============================================================ */

app.get(
  "/api/search",
  authRequired,
  (req, res) => {
    const query =
      String(
        req.query.q || ""
      )
        .toLowerCase()
        .trim();

    if (!query) {
      return sendSuccess(
        res,
        {
          questions: [],
          library: [],
          pharmacopoeia: []
        }
      );
    }

    const db =
      readDatabase();

    const questions =
      db.questions
        .filter(
          question =>
            String(
              question.question ||
                ""
            )
              .toLowerCase()
              .includes(
                query
              ) ||
            String(
              question.subject ||
                ""
            )
              .toLowerCase()
              .includes(
                query
              ) ||
            String(
              question.topic ||
                ""
            )
              .toLowerCase()
              .includes(
                query
              )
        )
        .slice(0, 10)
        .map(
          sanitizeQuestion
        );

    const library =
      db.library
        .filter(
          item =>
            String(
              item.title || ""
            )
              .toLowerCase()
              .includes(
                query
              )
        )
        .slice(0, 10);

    const pharmacopoeia =
      db.pharmacopoeia
        .filter(
          item =>
            String(
              item.name || ""
            )
              .toLowerCase()
              .includes(
                query
              ) ||
            String(
              item.category || ""
            )
              .toLowerCase()
              .includes(
                query
              )
            )
        )
        .slice(0, 10);

    return sendSuccess(
      res,
      {
        questions,
        library,
        pharmacopoeia
      }
    );
  }
);

/* ============================================================
   24. QUESTIONS
   ============================================================ */

app.get(
  "/api/questions",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const {
      subject,
      difficulty,
      page,
      limit
    } = req.query;

    const filtered =
      selectQuestions(
        db,
        {
          subject,
          difficulty
        }
      );

    return sendSuccess(
      res,
      paginate(
        filtered.map(
          sanitizeQuestion
        ),
        page,
        limit
      )
    );
  }
);

/* ============================================================
   25. TIMED QUIZ
   ============================================================ */

app.post(
  "/api/quiz/start",
  authRequired,
  (req, res) => {
    const {
      subject,
      difficulty
    } = req.body;

    const count =
      clampNumber(
        req.body.count,
        1,
        CONFIG.quiz.maxQuestions,
        CONFIG.quiz.defaultCount
      );

    const durationMinutes =
      clampNumber(
        req.body.durationMinutes,
        1,
        180,
        CONFIG.quiz.defaultDurationMinutes
      );

    const db =
      readDatabase();

    const selected =
      selectQuestions(
        db,
        {
          subject,
          difficulty
        }
      ).slice(
        0,
        count
      );

    if (
      selected.length ===
      0
    ) {
      return sendError(
        res,
        404,
        "No questions found matching criteria."
      );
    }

    const startedAt =
      nowISO();

    const endsAt =
      addMinutes(
        new Date(),
        durationMinutes
      );

    const quizAttempt = {
      id:
        generateId(
          "quiz"
        ),

      userId:
        req.user.id,

      questionIds:
        selected.map(
          question =>
            question.id
        ),

      status:
        "active",

      startedAt,

      durationMinutes,

      endsAt,

      answers:
        [],

      score:
        null,

      createdAt:
        nowISO()
    };

    db.quizAttempts.push(
      quizAttempt
    );

    writeDatabase(db);

    return sendSuccess(
      res,
      {
        quizId:
          quizAttempt.id,

        startedAt,

        durationMinutes,

        endsAt,

        questions:
          selected.map(
            sanitizeQuestion
          ),

        total:
          selected.length
      }
    );
  }
);

app.post(
  "/api/quiz/submit",
  authRequired,
  (req, res) => {
    const {
      quizId,
      answers = []
    } = req.body;

    if (
      !Array.isArray(
        answers
      )
    ) {
      return sendError(
        res,
        400,
        "Answers must be an array."
      );
    }

    const db =
      readDatabase();

    const attempt =
      db.quizAttempts.find(
        item =>
          item.id ===
            quizId &&
          item.userId ===
            req.user.id
      );

    if (!attempt) {
      return sendError(
        res,
        404,
        "Quiz attempt not found."
      );
    }

    if (
      attempt.status ===
      "completed"
    ) {
      return sendError(
        res,
        400,
        "Quiz already submitted."
      );
    }

    if (
      attempt.status !==
      "active"
    ) {
      return sendError(
        res,
        400,
        "Quiz is no longer active."
      );
    }

    const questions =
      attempt.questionIds
        .map(
          id =>
            db.questions.find(
              question =>
                question.id ===
                id
            )
        )
        .filter(Boolean);

    const score =
      calculateQuizScore(
        questions,
        answers
      );

    const expired =
      attempt.endsAt &&
      new Date() >
        new Date(
          attempt.endsAt
        );

    attempt.status =
      "completed";

    attempt.answers =
      answers;

    attempt.score =
      score.percentage;

    attempt.completedAt =
      nowISO();

    attempt.expired =
      Boolean(expired);

    const xpEarned =
      score.correct * 10;

    const coinsEarned =
      score.correct * 2;

    const user =
      getUserById(
        db,
        req.user.id
      );

    ensureUserDefaults(
      user
    );

    user.questionsAnswered +=
      score.total;

    user.correctAnswers +=
      score.correct;

    user.quizzesCompleted +=
      1;

    updateUserStreak(
      user
    );

    db.quizResults.push({
      id:
        generateId(
          "result"
        ),

      userId:
        user.id,

      quizId,

      score:
        score.percentage,

      correctCount:
        score.correct,

      totalQuestions:
        score.total,

      createdAt:
        nowISO()
    });

    awardRewardsInDatabase(
      db,
      user.id,
      xpEarned,
      coinsEarned,
      "Quiz Completion Reward"
    );

    evaluateAchievementsInDatabase(
      db,
      user.id
    );

    writeDatabase(db);

    const detailedReview =
      questions.map(
        (
          question,
          index
        ) => ({
          ...sanitizeQuestionWithAnswer(
            question
          ),

          userAnswer:
            answers[index] ??
            null,

          isCorrect:
            String(
              answers[index] ??
                ""
            )
              .trim()
              .toLowerCase() ===
            String(
              question.answer
            )
              .trim()
              .toLowerCase()
        })
      );

    return sendSuccess(
      res,
      {
        score:
          score.percentage,

        correctCount:
          score.correct,

        totalQuestions:
          score.total,

        xpEarned,

        coinsEarned,

        expired:

          Boolean(expired),

        detailedReview
      },
      expired
        ? "Quiz submitted after the timer reached its limit; answers were scored."
        : "Quiz submitted successfully."
    );
  }
);

/* ============================================================
   26. BATTLE ENGINE
   ============================================================ */

/*
   ============================================================
   CANONICAL BATTLE DATA MODEL
   ============================================================

   {
     id,

     creatorId,
     opponentId,

     questionIds,

     status:
       "waiting"
       "active"
       "completed"
       "expired"
       "cancelled"
       "draw"

     creatorScore,
     opponentScore,

     submissions: {
       [userId]: {
         submitted,
         correct,
         total,
         answers,
         submittedAt
       }
     },

     winnerId,

     resultProcessed,

     startedAt,
     endsAt,
     completedAt,

     createdAt
   }

   IMPORTANT:
   - creatorId is ALWAYS derived from req.user.id.
   - The client cannot choose creatorId.
   - No hostId is used.
   - No creatorScore/opponentScore is accepted
     from the client.
   ============================================================
*/

/* ------------------------------------------------------------
   Battle helper
   ------------------------------------------------------------ */

function getBattleParticipantIds(
  battle
) {
  return [
    battle.creatorId,
    battle.opponentId
  ].filter(Boolean);
}

function isBattleParticipant(
  battle,
  userId
) {
  return (
    battle.creatorId ===
      userId ||
    battle.opponentId ===
      userId
  );
}

function getBattleScoreForUser(
  battle,
  userId
) {
  if (
    battle.creatorId ===
    userId
  ) {
    return Number(
      battle.creatorScore
    ) || 0;
  }

  if (
    battle.opponentId ===
    userId
  ) {
    return Number(
      battle.opponentScore
    ) || 0;
  }

  return null;
}

/* ------------------------------------------------------------
   Create Battle
   ------------------------------------------------------------ */

app.post(
  "/api/battles/create",
  authRequired,
  (req, res) => {
    const subject =
      safeText(
        req.body.subject,
        100
      );

    const db =
      readDatabase();

    const selected =
      selectQuestions(
        db,
        {
          subject:
            subject ||
            undefined
        }
      ).slice(
        0,
        CONFIG.battle
          .questionCount
      );

    if (
      selected.length <
      CONFIG.battle
        .questionCount
    ) {
      return sendError(
        res,
        400,
        `Battle requires at least ${CONFIG.battle.questionCount} questions.`
      );
    }

    /*
       creatorId comes directly from
       authenticated session.

       It is NEVER taken from req.body.
    */

    const battle = {
      id:
        generateId(
          "battle"
        ),

      creatorId:
        req.user.id,

      opponentId:
        null,

      questionIds:
        selected.map(
          question =>
            question.id
        ),

      status:
        "waiting",

      creatorScore:
        null,

      opponentScore:
        null,

      submissions:
        {},

      winnerId:
        null,

      resultProcessed:
        false,

      startedAt:
        null,

      endsAt:
        null,

      completedAt:
        null,

      createdAt:
        nowISO()
    };

    db.battles.push(
      battle
    );

    writeDatabase(db);

    return sendSuccess(
      res,
      {
        battleId:
          battle.id,

        creatorId:
          battle.creatorId,

        status:
          battle.status,

        questionCount:
          battle.questionIds
            .length
      },
      "Battle created. Waiting for opponent.",
      201
    );
  }
);

/* ------------------------------------------------------------
   Join Battle
   ------------------------------------------------------------ */

app.post(
  "/api/battles/join",
  authRequired,
  (req, res) => {
    const battleId =
      safeText(
        req.body.battleId,
        100
      );

    if (!battleId) {
      return sendError(
        res,
        400,
        "Battle ID is required."
      );
    }

    const db =
      readDatabase();

    const battle =
      db.battles.find(
        item =>
          item.id ===
          battleId
      );

    if (!battle) {
      return sendError(
        res,
        404,
        "Battle not found."
      );
    }

    if (
      battle.status !==
      "waiting"
    ) {
      return sendError(
        res,
        400,
        "Battle is no longer available."
      );
    }

    if (
      battle.creatorId ===
      req.user.id
    ) {
      return sendError(
        res,
        400,
        "You cannot join your own battle."
      );
    }

    if (
      battle.opponentId
    ) {
      return sendError(
        res,
        400,
        "Battle already has an opponent."
      );
    }

    battle.opponentId =
      req.user.id;

    battle.status =
      "active";

    battle.startedAt =
      nowISO();

    battle.endsAt =
      addMinutes(
        new Date(),
        CONFIG.battle
          .durationMinutes
      );

    battle.creatorScore =
      null;

    battle.opponentScore =
      null;

    battle.submissions = {
      [battle.creatorId]: {
        submitted: false,
        correct: 0,
        total:
          battle.questionIds
            .length,
        answers: [],
        submittedAt: null
      },

      [battle.opponentId]: {
        submitted: false,
        correct: 0,
        total:
          battle.questionIds
            .length,
        answers: [],
        submittedAt: null
      }
    };

    writeDatabase(db);

    const questions =
      battle.questionIds
        .map(
          id =>
            sanitizeQuestion(
              db.questions.find(
                question =>
                  question.id ===
                  id
              )
            )
        )
        .filter(Boolean);

    return sendSuccess(
      res,
      {
        battleId:
          battle.id,

        creatorId:
          battle.creatorId,

        opponentId:
          battle.opponentId,

        status:
          battle.status,

        startedAt:
          battle.startedAt,

        endsAt:
          battle.endsAt,

        questions
      },
      "Joined battle successfully."
    );
  }
);

/* ------------------------------------------------------------
   Process Battle Result
   ------------------------------------------------------------ */

function processBattleResult(
  db,
  battle
) {
  if (
    battle.resultProcessed
  ) {
    return;
  }

  /*
     Normalize potentially old records.
  */

  if (
    !battle.creatorId &&
    battle.hostId
  ) {
    battle.creatorId =
      battle.hostId;
  }

  if (
    !battle.creatorId
  ) {
    return;
  }

  battle.submissions =
    battle.submissions ||
    battle.participants ||
    {};

  const creatorId =
    battle.creatorId;

  const opponentId =
    battle.opponentId;

  const participants =
    getBattleParticipantIds(
      battle
    );

  /*
     A waiting battle cannot be
     scored as a completed battle.
  */

  if (
    battle.status ===
    "waiting"
  ) {
    return;
  }

  const creatorData =
    battle.submissions[
      creatorId
    ];

  const opponentData =
    opponentId
      ? battle.submissions[
          opponentId
        ]
      : null;

  const creatorSubmitted =
    Boolean(
      creatorData?.submitted
    );

  const opponentSubmitted =
    Boolean(
      opponentData?.submitted
    );

  /*
     No opponent.
  */

  if (!opponentId) {
    if (
      battle.endsAt &&
      new Date() >
        new Date(
          battle.endsAt
        )
    ) {
      battle.status =
        "expired";

      battle.completedAt =
        nowISO();

      battle.resultProcessed =
        true;
    }

    return;
  }

  /*
     Nobody submitted before
     timeout.
  */

  if (
    !creatorSubmitted &&
    !opponentSubmitted
  ) {
    battle.status =
      "expired";

    battle.creatorScore =
      0;

    battle.opponentScore =
      0;

    battle.winnerId =
      null;

    battle.completedAt =
      nowISO();

    battle.resultProcessed =
      true;

    return;
  }

  /*
     Save actual scores.
  */

  battle.creatorScore =
    Number(
      creatorData?.correct
    ) || 0;

  battle.opponentScore =
    Number(
      opponentData?.correct
    ) || 0;

  /*
     Both submitted:
     compare actual scores.
  */

  if (
    creatorSubmitted &&
    opponentSubmitted
  ) {
    if (
      battle.creatorScore >
      battle.opponentScore
    ) {
      battle.winnerId =
        creatorId;

      battle.status =
        "completed";
    } else if (
      battle.opponentScore >
      battle.creatorScore
    ) {
      battle.winnerId =
        opponentId;

      battle.status =
        "completed";
    } else {
      battle.winnerId =
        null;

      battle.status =
        "draw";
    }
  }

  /*
     Only creator submitted:
     creator wins when result
     is resolved.
  */

  else if (
    creatorSubmitted &&
    !opponentSubmitted
  ) {
    battle.winnerId =
      creatorId;

    battle.status =
      "completed";
  }

  /*
     Only opponent submitted:
     opponent wins.
  */

  else if (
    !creatorSubmitted &&
    opponentSubmitted
  ) {
    battle.winnerId =
      opponentId;

    battle.status =
      "completed";
  }

  battle.completedAt =
    nowISO();

  battle.resultProcessed =
    true;

  /*
     Participation statistics.
  */

  participants.forEach(
    userId => {
      const user =
        getUserById(
          db,
          userId
        );

      if (!user) {
        return;
      }

      ensureUserDefaults(
        user
      );

      user.battlesPlayed +=
        1;

      updateUserStreak(
        user
      );
    }
  );

  /*
     Winner reward.
  */

  if (
    battle.winnerId
  ) {
    const winner =
      getUserById(
        db,
        battle.winnerId
      );

    if (winner) {
      ensureUserDefaults(
        winner
      );

      winner.battlesWon +=
        1;

      awardRewardsInDatabase(
        db,
        winner.id,
        100,
        50,
        "Battle Victory Reward"
      );
    }
  }

  /*
     Draw reward.
  */

  if (
    battle.status ===
    "draw"
  ) {
    participants.forEach(
      userId => {
        awardRewardsInDatabase(
          db,
          userId,
          25,
          10,
          "Battle Draw Reward"
        );
      }
    );
  }

  /*
     Achievement checks.
  */

  participants.forEach(
    userId => {
      evaluateAchievementsInDatabase(
        db,
        userId
      );
    }
  );
}

/* ------------------------------------------------------------
   Battle Status
   ------------------------------------------------------------ */

app.get(
  "/api/battles/:id/status",
  authRequired,
  (req, res) => {
    const battleId =
      safeText(
        req.params.id,
        100
      );

    const db =
      readDatabase();

    const battle =
      db.battles.find(
        item =>
          item.id ===
          battleId
      );

    if (!battle) {
      return sendError(
        res,
        404,
        "Battle not found."
      );
    }

    /*
       Migrate legacy hostId
       if encountered.
    */

    if (
      !battle.creatorId &&
      battle.hostId
    ) {
      battle.creatorId =
        battle.hostId;

      delete battle.hostId;
    }

    /*
       Migrate legacy participants
       to submissions.
    */

    if (
      !battle.submissions &&
      battle.participants
    ) {
      battle.submissions =
        battle.participants;

      delete battle.participants;
    }

    if (
      !isBattleParticipant(
        battle,
        req.user.id
      )
    ) {
      return sendError(
        res,
        403,
        "You are not a participant of this battle."
      );
    }

    /*
       Automatically resolve an active
       battle after timer expiration.
    */

    if (
      battle.status ===
        "active" &&
      battle.endsAt &&
      new Date() >
        new Date(
          battle.endsAt
        )
    ) {
      processBattleResult(
        db,
        battle
      );

      writeDatabase(db);
    }

    const questions =
      battle.questionIds
        .map(
          id =>
            sanitizeQuestion(
              db.questions.find(
                question =>
                  question.id ===
                  id
              )
            )
        )
        .filter(Boolean);

    const myScore =
      getBattleScoreForUser(
        battle,
        req.user.id
      );

    return sendSuccess(
      res,
      {
        battleId:
          battle.id,

        status:
          battle.status,

        creatorId:
          battle.creatorId,

        opponentId:
          battle.opponentId,

        creatorScore:
          battle.creatorScore,

        opponentScore:
          battle.opponentScore,

        myScore,

        winnerId:
          battle.winnerId,

        resultProcessed:
          Boolean(
            battle.resultProcessed
          ),

        submissions:
          battle.submissions ||
          {},

        startedAt:
          battle.startedAt,

        endsAt:
          battle.endsAt,

        completedAt:
          battle.completedAt,

        questions:
          [
            "active",
            "completed",
            "draw"
          ].includes(
            battle.status
          )
            ? questions
            : []
      }
    );
  }
);

/* ------------------------------------------------------------
   Submit Battle
   ------------------------------------------------------------ */

app.post(
  "/api/battles/submit",
  authRequired,
  (req, res) => {
    const {
      battleId,
      answers = []
    } = req.body;

    if (
      !battleId
    ) {
      return sendError(
        res,
        400,
        "Battle ID is required."
      );
    }

    if (
      !Array.isArray(
        answers
      )
    ) {
      return sendError(
        res,
        400,
        "Answers must be an array."
      );
    }

    const db =
      readDatabase();

    const battle =
      db.battles.find(
        item =>
          item.id ===
          battleId
      );

    if (!battle) {
      return sendError(
        res,
        404,
        "Battle not found."
      );
    }

    /*
       Legacy migration.
    */

    if (
      !battle.creatorId &&
      battle.hostId
    ) {
      battle.creatorId =
        battle.hostId;

      delete battle.hostId;
    }

    if (
      !isBattleParticipant(
        battle,
        req.user.id
      )
    ) {
      return sendError(
        res,
        403,
        "You are not a participant of this battle."
      );
    }

    if (
      battle.status !==
      "active"
    ) {
      return sendError(
        res,
        400,
        "Battle is not active."
      );
    }

    /*
       If timer has expired,
       resolve before accepting
       another submission.
    */

    if (
      battle.endsAt &&
      new Date() >
        new Date(
          battle.endsAt
        )
    ) {
      processBattleResult(
        db,
        battle
      );

      writeDatabase(db);

      return sendError(
        res,
        400,
        "Battle time has expired."
      );
    }

    battle.submissions =
      battle.submissions ||
      {};

    const existing =
      battle.submissions[
        req.user.id
      ];

    if (
      existing?.submitted
    ) {
      return sendError(
        res,
        400,
        "You have already submitted this battle."
      );
    }

    const questions =
      battle.questionIds
        .map(
          id =>
            db.questions.find(
              question =>
                question.id ===
                id
            )
        )
        .filter(Boolean);

    if (
      questions.length ===
      0
    ) {
      return sendError(
        res,
        400,
        "Battle questions are unavailable."
      );
    }

    /*
       Do not trust a client-provided
       score. Calculate it from the
       stored questions.
    */

    const score =
      calculateQuizScore(
        questions,
        answers
      );

    battle.submissions[
      req.user.id
    ] = {
      submitted: true,

      correct:
        score.correct,

      total:
        score.total,

      answers:
        answers.slice(
          0,
          questions.length
        ),

      submittedAt:
        nowISO()
    };

    /*
       Store the user's current score
       in the canonical score field.
    */

    if (
      battle.creatorId ===
      req.user.id
    ) {
      battle.creatorScore =
        score.correct;
    }

    if (
      battle.opponentId ===
      req.user.id
    ) {
      battle.opponentScore =
        score.correct;
    }

    const creatorSubmitted =
      Boolean(
        battle.submissions[
          battle.creatorId
        ]?.submitted
      );

    const opponentSubmitted =
      Boolean(
        battle.submissions[
          battle.opponentId
        ]?.submitted
      );

    /*
       Both players submitted:
       resolve immediately.
    */

    if (
      battle.opponentId &&
      creatorSubmitted &&
      opponentSubmitted
    ) {
      processBattleResult(
        db,
        battle
      );
    }

    writeDatabase(db);

    return sendSuccess(
      res,
      {
        battleId:
          battle.id,

        score,

        creatorScore:
          battle.creatorScore,

        opponentScore:
          battle.opponentScore,

        status:
          battle.status,

        submitted:
          true,

        waitingForOpponent:
          battle.status ===
          "active",

        winnerId:
          battle.winnerId,

        resultProcessed:
          Boolean(
            battle.resultProcessed
          )
      },
      "Battle answer submitted successfully."
    );
  }
);

/* ------------------------------------------------------------
   Cancel Waiting Battle
   ------------------------------------------------------------ */

app.post(
  "/api/battles/:id/cancel",
  authRequired,
  (req, res) => {
    const battleId =
      safeText(
        req.params.id,
        100
      );

    const db =
      readDatabase();

    const battle =
      db.battles.find(
        item =>
          item.id ===
          battleId
      );

    if (!battle) {
      return sendError(
        res,
        404,
        "Battle not found."
      );
    }

    if (
      battle.creatorId !==
      req.user.id
    ) {
      return sendError(
        res,
        403,
        "Only the battle creator can cancel this battle."
      );
    }

    if (
      battle.status !==
      "waiting"
    ) {
      return sendError(
        res,
        400,
        "Only a waiting battle can be cancelled."
      );
    }

    battle.status =
      "cancelled";

    battle.completedAt =
      nowISO();

    battle.resultProcessed =
      true;

    writeDatabase(db);

    return sendSuccess(
      res,
      {
        battleId:
          battle.id,

        status:
          battle.status
      },
      "Battle cancelled successfully."
    );
  }
);

/* ============================================================
   27. DAILY CHALLENGE
   ============================================================ */

app.get(
  "/api/daily-challenge",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const key =
      todayKey();

    let challenge =
      db.dailyChallenges.find(
        item =>
          item.date ===
          key
      );

    if (!challenge) {
      const questions =
        selectQuestions(
          db
        ).slice(0, 5);

      if (
        questions.length ===
        0
      ) {
        return sendError(
          res,
          404,
          "No questions are available for today's challenge."
        );
      }

      challenge = {
        id:
          generateId(
            "daily"
          ),

        date:
          key,

        questionIds:
          questions.map(
            question =>
              question.id
          ),

        rewardXP:
          100,

        rewardCoins:
          25,

        createdAt:
          nowISO()
      };

      db.dailyChallenges.push(
        challenge
      );

      writeDatabase(db);
    }

    const completed =
      db.quizAttempts.some(
        item =>
          item.userId ===
            req.user.id &&
          item.dailyChallengeId ===
            challenge.id &&
          item.status ===
            "completed"
      );

    const questions =
      challenge.questionIds
        .map(
          id =>
            sanitizeQuestion(
              db.questions.find(
                question =>
                  question.id ===
                  id
              )
            )
        )
        .filter(Boolean);

    return sendSuccess(
      res,
      {
        challengeId:
          challenge.id,

        date:
          challenge.date,

        completed,

        questions,

        rewardXP:
          challenge.rewardXP,

        rewardCoins:
          challenge.rewardCoins
      }
    );
  }
);

app.post(
  "/api/daily-challenge/submit",
  authRequired,
  (req, res) => {
    const {
      challengeId,
      answers = []
    } = req.body;

    if (
      !challengeId
    ) {
      return sendError(
        res,
        400,
        "Challenge ID is required."
      );
    }

    if (
      !Array.isArray(
        answers
      )
    ) {
      return sendError(
        res,
        400,
        "Answers must be an array."
      );
    }

    const db =
      readDatabase();

    const challenge =
      db.dailyChallenges.find(
        item =>
          item.id ===
          challengeId
      );

    if (!challenge) {
      return sendError(
        res,
        404,
        "Daily challenge not found."
      );
    }

    const alreadyCompleted =
      db.quizAttempts.some(
        item =>
          item.userId ===
            req.user.id &&
          item.dailyChallengeId ===
            challengeId &&
          item.status ===
            "completed"
      );

    if (
      alreadyCompleted
    ) {
      return sendError(
        res,
        400,
        "Daily challenge already completed."
      );
    }

    const questions =
      challenge.questionIds
        .map(
          id =>
            db.questions.find(
              question =>
                question.id ===
                id
            )
        )
        .filter(Boolean);

    if (
      questions.length ===
      0
    ) {
      return sendError(
        res,
        400,
        "Daily challenge questions are unavailable."
      );
    }

    const score =
      calculateQuizScore(
        questions,
        answers
      );

    db.quizAttempts.push({
      id:
        generateId(
          "quiz_daily"
        ),

      userId:
        req.user.id,

      dailyChallengeId:
        challengeId,

      questionIds:
        challenge.questionIds,

      answers:
        answers.slice(
          0,
          questions.length
        ),

      status:
        "completed",

      score:
        score.percentage,

      correctCount:
        score.correct,

      totalQuestions:
        score.total,

      createdAt:
        nowISO()
    });

    const user =
      getUserById(
        db,
        req.user.id
      );

    ensureUserDefaults(
      user
    );

    user.questionsAnswered +=
      score.total;

    user.correctAnswers +=
      score.correct;

    updateUserStreak(
      user
    );

    awardRewardsInDatabase(
      db,
      req.user.id,
      Number(
        challenge.rewardXP
      ) || 0,
      Number(
        challenge.rewardCoins
      ) || 0,
      "Daily Challenge Reward"
    );

    evaluateAchievementsInDatabase(
      db,
      req.user.id
    );

    writeDatabase(db);

    return sendSuccess(
      res,
      {
        score,

        rewardXP:
          challenge.rewardXP,

        rewardCoins:
          challenge.rewardCoins
      },
      "Daily challenge submitted successfully."
    );
  }
);

/* ============================================================
   28. LEADERBOARD
   ============================================================ */

app.get(
  "/api/leaderboard",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const type =
      String(
        req.query.type ||
          "xp"
      ).toLowerCase();

    const users =
      db.users.map(
        getPublicUser
      );

    if (
      type ===
      "coins"
    ) {
      users.sort(
        (a, b) =>
          b.coins -
          a.coins
      );
    } else if (
      type ===
      "quiz"
    ) {
      users.sort(
        (a, b) =>
          b.quizzesCompleted -
          a.quizzesCompleted
      );
    } else if (
      type ===
      "battle"
    ) {
      users.sort(
        (a, b) =>
          b.battlesWon -
          a.battlesWon
      );
    } else {
      users.sort(
        (a, b) =>
          b.xp -
          a.xp
      );
    }

    return sendSuccess(
      res,
      {
        type,

        leaderboard:
          users.slice(
            0,
            50
          )
      }
    );
  }
);

/* ============================================================
   29. ACHIEVEMENTS
   ============================================================ */

app.get(
  "/api/achievements",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const unlockedMap =
      new Map(
        db.userAchievements
          .filter(
            item =>
              item.userId ===
              req.user.id
          )
          .map(
            item => [
              item.achievementId,
              item.unlockedAt
            ]
          )
      );

    const achievements =
      db.achievements.map(
        item => ({
          ...item,

          unlocked:
            unlockedMap.has(
              item.id
            ),

          unlockedAt:
            unlockedMap.get(
              item.id
            ) || null
        })
      );

    return sendSuccess(
      res,
      {
        achievements
      }
    );
  }
);

/* ============================================================
   30. WALLET
   ============================================================ */

app.get(
  "/api/wallet",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const wallet =
      getOrCreateWalletInDatabase(
        db,
        req.user.id
      );

    const user =
      getUserById(
        db,
        req.user.id
      );

    ensureUserDefaults(
      user
    );

    /*
       Keep wallet balance synchronized
       with the user's coin balance.
    */

    wallet.balance =
      user.coins;

    wallet.updatedAt =
      nowISO();

    writeDatabase(db);

    const transactions =
      db.walletTransactions
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    const subscription =
      getActiveSubscription(
        req.user.id
      );

    return sendSuccess(
      res,
      {
        wallet,

        transactions,

        referralCode:
          user.referralCode,

        subscription:
          subscription
            ? {
                active:
                  true,

                expiresAt:
                  subscription.expiresAt,

                plan:
                  subscription.plan
              }
            : {
                active:
                  false
              }
      }
    );
  }
);

/* ============================================================
   31. REFERRALS
   ============================================================ */

app.get(
  "/api/referrals",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const referrals =
      db.referrals.filter(
        item =>
          item.referrerId ===
          req.user.id
      );

    return sendSuccess(
      res,
      {
        referralCode:
          req.user.referralCode,

        totalReferred:
          referrals.length,

        referrals
      }
    );
  }
);

/* ============================================================
   32. SUBSCRIPTIONS
   ============================================================ */

app.post(
  "/api/subscriptions/verify",
  authRequired,
  (req, res) => {
    const reference =
      safeText(
        req.body.reference,
        200
      );

    const plan =
      req.body.plan ===
      "premium_yearly"
        ? "premium_yearly"
        : "premium_monthly";

    if (!reference) {
      return sendError(
        res,
        400,
        "Payment reference is required."
      );
    }

    /*
       SECURITY NOTE:

       This endpoint is intentionally NOT pretending
       to be a real payment gateway verification.

       For production:
         frontend -> payment provider
         backend  -> payment provider verification API
         backend  -> activate subscription only after
                     provider confirms payment

       A client should never be allowed to turn
       itself premium merely by sending a reference.
    */

    const providerVerified =
      req.body.providerVerified ===
      true;

    if (
      !providerVerified &&
      CONFIG.environment ===
        "production"
    ) {
      return sendError(
        res,
        400,
        "Payment must be verified by the payment provider before subscription activation."
      );
    }

    const durationDays =
      plan ===
      "premium_yearly"
        ? 365
        : 30;

    const expiresAt =
      addDays(
        new Date(),
        durationDays
      );

    const result =
      updateDatabase(
        db => {
          const existingPayment =
            db.payments.find(
              item =>
                item.reference ===
                reference
            );

          if (
            existingPayment
          ) {
            return {
              error:
                "Payment reference has already been processed."
            };
          }

          db.subscriptions.push({
            id:
              generateId(
                "sub"
              ),

            userId:
              req.user.id,

            plan,

            reference,

            status:
              "active",

            expiresAt,

            createdAt:
              nowISO()
          });

          db.payments.push({
            id:
              generateId(
                "pay"
              ),

            userId:
              req.user.id,

            reference,

            plan,

            status:
              "success",

            providerVerified:
              providerVerified,

            createdAt:
              nowISO()
          });

          return {
            success:
              true
          };
        }
      );

    if (
      result.error
    ) {
      return sendError(
        res,
        409,
        result.error
      );
    }

    createAuditLog(
      req.user.id,
      "subscription_activated",
      {
        plan,
        reference
      }
    );

    return sendSuccess(
      res,
      {
        active:
          true,

        expiresAt,

        plan
      },
      "Subscription activated successfully."
    );
  }
);

/* ============================================================
   33. PHARMACOPOEIA HUB
   ============================================================ */

app.get(
  "/api/pharmacopoeia",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const query =
      String(
        req.query.q || ""
      )
        .toLowerCase()
        .trim();

    let items =
      db.pharmacopoeia ||
      [];

    if (query) {
      items =
        items.filter(
          item =>
            String(
              item.name || ""
            )
              .toLowerCase()
              .includes(
                query
              ) ||
            String(
              item.category ||
                ""
            )
              .toLowerCase()
              .includes(
                query
              )
        );
    }

    return sendSuccess(
      res,
      {
        items
      }
    );
  }
);

/* ============================================================
   34. PHARMACY LANGUAGE ASSISTANT
   ============================================================ */

app.get(
  "/api/languages",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    return sendSuccess(
      res,
      {
        languages:
          db.languages ||
          [],

        phrases:
          db.languagePhrases ||
          []
      }
    );
  }
);

/* ============================================================
   35. BOOKMARKS
   ============================================================ */

app.post(
  "/api/bookmarks",
  authRequired,
  (req, res) => {
    const {
      questionId
    } = req.body;

    if (!questionId) {
      return sendError(
        res,
        400,
        "Question ID required."
      );
    }

    const result =
      updateDatabase(
        db => {
          const question =
            db.questions.find(
              item =>
                item.id ===
                questionId
            );

          if (!question) {
            return {
              error:
                "Question not found."
            };
          }

          const exists =
            db.bookmarks.some(
              bookmark =>
                bookmark.userId ===
                  req.user.id &&
                bookmark.questionId ===
                  questionId
            );

          if (exists) {
            return {
              alreadyExists:
                true
            };
          }

          db.bookmarks.push({
            id:
              generateId(
                "bm"
              ),

            userId:
              req.user.id,

            questionId,

            createdAt:
              nowISO()
          });

          return {
            added:
              true
          };
        }
      );

    if (
      result.error
    ) {
      return sendError(
        res,
        404,
        result.error
      );
    }

    return sendSuccess(
      res,
      {
        added:
          Boolean(
            result.added
          ),

        alreadyExists:
          Boolean(
            result.alreadyExists
          )
      },
      result.alreadyExists
        ? "Question is already bookmarked."
        : "Bookmark added."
    );
  }
);

app.get(
  "/api/bookmarks",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const bookmarks =
      db.bookmarks.filter(
        item =>
          item.userId ===
          req.user.id
      );

    const questions =
      bookmarks
        .map(
          bookmark =>
            sanitizeQuestionWithAnswer(
              db.questions.find(
                question =>
                  question.id ===
                  bookmark.questionId
              )
            )
        )
        .filter(Boolean);

    return sendSuccess(
      res,
      {
        bookmarks:
          questions
      }
    );
  }
);

app.delete(
  "/api/bookmarks/:questionId",
  authRequired,
  (req, res) => {
    const questionId =
      safeText(
        req.params.questionId,
        100
      );

    const result =
      updateDatabase(
        db => {
          const before =
            db.bookmarks.length;

          db.bookmarks =
            db.bookmarks.filter(
              bookmark =>
                !(
                  bookmark.userId ===
                    req.user.id &&
                  bookmark.questionId ===
                    questionId
                )
            );

          return {
            removed:
              db.bookmarks
                .length <
              before
          };
        }
      );

    return sendSuccess(
      res,
      result,
      result.removed
        ? "Bookmark removed."
        : "Bookmark was not found."
    );
  }
);

/* ============================================================
   36. ANALYTICS / WEAK TOPICS
   ============================================================ */

app.get(
  "/api/analytics",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const results =
      db.quizResults.filter(
        item =>
          item.userId ===
          req.user.id
      );

    const topicStats = {};

    results.forEach(
      result => {
        const attempt =
          db.quizAttempts.find(
            item =>
              item.id ===
              result.quizId
          );

        if (
          !attempt ||
          !Array.isArray(
            attempt.questionIds
          )
        ) {
          return;
        }

        attempt.questionIds.forEach(
          (
            questionId,
            index
          ) => {
            const question =
              db.questions.find(
                item =>
                  item.id ===
                  questionId
              );

            if (!question) {
              return;
            }

            const topic =
              question.topic ||
              question.subject ||
              "Unknown";

            if (
              !topicStats[
                topic
              ]
            ) {
              topicStats[
                topic
              ] = {
                total: 0,
                correct: 0
              };
            }

            topicStats[
              topic
            ].total += 1;

            const submitted =
              attempt.answers?.[
                index
              ];

            if (
              String(
                submitted ?? ""
              )
                .trim()
                .toLowerCase() ===
              String(
                question.answer
              )
                .trim()
                .toLowerCase()
            ) {
              topicStats[
                topic
              ].correct +=
                1;
            }
          }
        );
      }
    );

    const weakTopics =
      Object.entries(
        topicStats
      )
        .map(
          (
            [topic, stats]
          ) => ({
            topic,

            total:
              stats.total,

            correct:
              stats.correct,

            accuracy:
              stats.total > 0
                ? Math.round(
                    (
                      stats.correct /
                      stats.total
                    ) *
                      100
                  )
                : 0
          })
        )
        .sort(
          (a, b) =>
            a.accuracy -
            b.accuracy
        );

    return sendSuccess(
      res,
      {
        totalQuizzesCompleted:
          results.length,

        weakTopics
      }
    );
  }
);

/* ============================================================
   37. NOTIFICATIONS
   ============================================================ */

app.get(
  "/api/notifications",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const notifications =
      db.notifications
        .filter(
          item =>
            item.userId ===
            req.user.id
        )
        .sort(
          (a, b) =>
            new Date(
              b.createdAt
            ) -
            new Date(
              a.createdAt
            )
        );

    return sendSuccess(
      res,
      {
        notifications
      }
    );
  }
);

app.patch(
  "/api/notifications/:id/read",
  authRequired,
  (req, res) => {
    const notificationId =
      safeText(
        req.params.id,
        100
      );

    const result =
      updateDatabase(
        db => {
          const notification =
            db.notifications.find(
              item =>
                item.id ===
                  notificationId &&
                item.userId ===
                  req.user.id
            );

          if (
            !notification
          ) {
            return {
              error:
                "Notification not found."
            };
          }

          notification.read =
            true;

          notification.readAt =
            nowISO();

          return {
            notification
          };
        }
      );

    if (
      result.error
    ) {
      return sendError(
        res,
        404,
        result.error
      );
    }

    return sendSuccess(
      res,
      {
        notification:
          result.notification
      },
      "Notification marked as read."
    );
  }
);

/* ============================================================
   38. FEEDBACK
   ============================================================ */

app.post(
  "/api/feedback",
  authRequired,
  (req, res) => {
    const message =
      safeText(
        req.body.message,
        1000
      );

    if (!message) {
      return sendError(
        res,
        400,
        "Feedback message required."
      );
    }

    updateDatabase(
      db => {
        db.feedback.push({
          id:
            generateId(
              "fb"
            ),

          userId:
            req.user.id,

          message,

          status:
            "new",

          createdAt:
            nowISO()
        });
      }
    );

    return sendSuccess(
      res,
      {},
      "Feedback submitted successfully."
    );
  }
);

/* ============================================================
   39. GPA CALCULATOR
   ============================================================ */

app.post(
  "/api/gpa/calculate",
  authRequired,
  (req, res) => {
    const {
      courses = []
    } = req.body;

    if (
      !Array.isArray(
        courses
      ) ||
      courses.length ===
        0
    ) {
      return sendError(
        res,
        400,
        "Provide valid courses with units and grades."
      );
    }

    const gradeMap = {
      A: 5,
      B: 4,
      C: 3,
      D: 2,
      E: 1,
      F: 0
    };

    let totalUnits = 0;
    let totalPoints = 0;

    for (
      const course of
      courses
    ) {
      const units =
        Number(
          course.units
        );

      const grade =
        String(
          course.grade || ""
        ).toUpperCase();

      if (
        !Number.isFinite(
          units
        ) ||
        units <= 0 ||
        gradeMap[
          grade
        ] === undefined
      ) {
        return sendError(
          res,
          400,
          "Invalid course units or grade."
        );
      }

      totalUnits +=
        units;

      totalPoints +=
        units *
        gradeMap[
          grade
        ];
    }

    const gpa =
      totalUnits > 0
        ? Number(
            (
              totalPoints /
              totalUnits
            ).toFixed(2)
          )
        : 0;

    const record = {
      id:
        generateId(
          "gpa"
        ),

      userId:
        req.user.id,

      semester:
        safeText(
          req.body.semester,
          50
        ) || "Current",

      totalUnits,

      totalPoints,

      gpa,

      courses:
        courses.map(
          course => ({
            course:
              safeText(
                course.course,
                150
              ),

            units:
              Number(
                course.units
              ),

            grade:
              String(
                course.grade
              ).toUpperCase()
          })
        ),

      createdAt:
        nowISO()
    };

    updateDatabase(
      db => {
        db.gpaRecords.push(
          record
        );
      }
    );

    createAuditLog(
      req.user.id,
      "gpa_calculated",
      {
        gpa,
        totalUnits
      }
    );

    return sendSuccess(
      res,
      {
        gpa,

        totalUnits,

        totalPoints,

        recordId:
          record.id
      }
    );
  }
);

app.get(
  "/api/gpa/records",
  authRequired,
  (req, res) => {
    const db =
      readDatabase();

    const records =
      db.gpaRecords.filter(
        item =>
          item.userId ===
          req.user.id
      );

    return sendSuccess(
      res,
      {
        records
      }
    );
  }
);

/* ============================================================
   40. ADMIN - QUESTIONS
   ============================================================ */

app.post(
  "/api/admin/questions",
  authRequired,
  adminRequired,
  (req, res) => {
    const {
      question,
      options,
      answer,
      explanation,
      subject,
      topic,
      difficulty
    } = req.body;

    if (
      !question ||
      !Array.isArray(
        options
      ) ||
      options.length < 2 ||
      !answer ||
      !subject
    ) {
      return sendError(
        res,
        400,
        "Provide valid question payload."
      );
    }

    const cleanOptions =
      options
        .map(
          option =>
            safeText(
              option,
              300
            )
        )
        .filter(Boolean);

    if (
      cleanOptions.length <
      2
    ) {
      return sendError(
        res,
        400,
        "At least two valid options are required."
      );
    }

    const cleanAnswer =
      safeText(
        answer,
        300
      );

    if (
      !cleanOptions.some(
        option =>
          option.toLowerCase() ===
          cleanAnswer.toLowerCase()
      )
    ) {
      return sendError(
        res,
        400,
        "Answer must match one of the question options."
      );
    }

    const newQuestion = {
      id:
        generateId(
          "question"
        ),

      question:
        safeText(
          question,
          1000
        ),

      options:
        cleanOptions,

      answer:
        cleanAnswer,

      explanation:
        safeText(
          explanation,
          2000
        ),

      learningPoints:
        Array.isArray(
          req.body.learningPoints
        )
          ? req.body.learningPoints
              .map(
                point =>
                  safeText(
                    point,
                    500
                  )
              )
              .filter(Boolean)
          : [],

      subject:
        safeText(
          subject,
          100
        ),

      topic:
        safeText(
          topic,
          100
        ),

      difficulty:
        safeText(
          difficulty,
          20
        ) || "medium",

      curriculum:
        safeText(
          req.body.curriculum,
          100
        ) || "International",

      yearLevel:
        safeText(
          req.body.yearLevel,
          50
        ) || "Any",

      semester:
        safeText(
          req.body.semester,
          50
        ) || "Any",

      tags:
        Array.isArray(
          req.body.tags
        )
          ? req.body.tags
              .map(
                tag =>
                  safeText(
                    tag,
                    50
                  )
              )
              .filter(Boolean)
          : [],

      createdAt:
        nowISO()
    };

    updateDatabase(
      db => {
        db.questions.push(
          newQuestion
        );
      }
    );

    createAuditLog(
      req.user.id,
      "admin_create_question",
      {
        questionId:
          newQuestion.id
      }
    );

    return sendSuccess(
      res,
      {
        question:
          sanitizeQuestionWithAnswer(
            newQuestion
          )
      },
      "Question created.",
      201
    );
  }
);

/* ============================================================
   41. ADMIN - USERS
   ============================================================ */

app.get(
  "/api/admin/users",
  authRequired,
  adminRequired,
  (req, res) => {
    const db =
      readDatabase();

    return sendSuccess(
      res,
      {
        users:
          db.users.map(
            getPublicUser
          )
      }
    );
  }
);

/* ============================================================
   42. ADMIN - LANGUAGE
   ============================================================ */

app.post(
  "/api/admin/language",
  authRequired,
  adminRequired,
  (req, res) => {
    const {
      english,
      localPidgin,
      igbo
    } = req.body;

    if (!english) {
      return sendError(
        res,
        400,
        "English phrase required."
      );
    }

    const phrase = {
      id:
        generateId(
          "phrase"
        ),

      english:
        safeText(
          english,
          500
        ),

      localPidgin:
        safeText(
          localPidgin,
          500
        ),

      igbo:
        safeText(
          igbo,
          500
        ),

      createdAt:
        nowISO()
    };

    /*
       IMPORTANT:
       db is explicitly loaded inside
       this route. This fixes the
       previous undefined-db problem.
    */

    const db =
      readDatabase();

    db.languagePhrases.push(
      phrase
    );

    writeDatabase(db);

    createAuditLog(
      req.user.id,
      "admin_add_language_phrase",
      {
        phraseId:
          phrase.id
      }
    );

    return sendSuccess(
      res,
      {
        phrase
      },
      "Language phrase added successfully.",
      201
    );
  }
);

/* ============================================================
   43. ADMIN - AUDIT LOGS
   ============================================================ */

app.get(
  "/api/admin/audit-logs",
  authRequired,
  adminRequired,
  (req, res) => {
    const db =
      readDatabase();

    return sendSuccess(
      res,
      {
        auditLogs:
          (
            db.auditLogs ||
            []
          )
            .slice(-100)
            .reverse()
      }
    );
  }
);

/* ============================================================
   44. DATABASE MIGRATION
   ============================================================ */

/*
   This migration protects the project if the user already
   has a database.json created by an earlier DENexpharm version.

   Important legacy changes:

   OLD:
     hostId

   NEW:
     creatorId

   OLD:
     participants

   NEW:
     submissions

   OLD/INCOMPLETE:
     no creatorScore/opponentScore

   NEW:
     creatorScore
     opponentScore

   The migration does NOT delete user/question/content data.
*/

function migrateDatabase(
  db
) {
  let changed = false;

  if (
    !db.meta ||
    typeof db.meta !==
      "object"
  ) {
    db.meta = {
      databaseVersion: 1,
      createdAt:
        nowISO(),
      updatedAt:
        nowISO()
    };

    changed = true;
  }

  if (
    !db.meta.createdAt
  ) {
    db.meta.createdAt =
      nowISO();

    changed = true;
  }

  /*
     Ensure arrays exist.
  */

  for (
    const key of Object.keys(
      EMPTY_DATABASE
    )
  ) {
    if (
      key === "meta"
    ) {
      continue;
    }

    if (
      !Array.isArray(
        db[key]
      )
    ) {
      db[key] = [];

      changed = true;
    }
  }

  /*
     User migration.
  */

  db.users.forEach(
    user => {
      const before =
        JSON.stringify({
          xp: user.xp,
          coins: user.coins,
          level: user.level,
          streak: user.streak
        });

      ensureUserDefaults(
        user
      );

      const after =
        JSON.stringify({
          xp: user.xp,
          coins: user.coins,
          level: user.level,
          streak: user.streak
        });

      if (
        before !== after
      ) {
        changed = true;
      }
    }
  );

  /*
     Battle migration.
  */

  db.battles.forEach(
    battle => {
      /*
         hostId -> creatorId
      */

      if (
        !battle.creatorId &&
        battle.hostId
      ) {
        battle.creatorId =
          battle.hostId;

        delete battle.hostId;

        changed = true;
      }

      /*
         participants -> submissions
      */

      if (
        !battle.submissions &&
        battle.participants
      ) {
        battle.submissions =
          battle.participants;

        delete battle.participants;

        changed = true;
      }

      if (
        !battle.submissions
      ) {
        battle.submissions =
          {};

        changed = true;
      }

      if (
        battle.creatorScore ===
        undefined
      ) {
        const creatorSubmission =
          battle.submissions[
            battle.creatorId
          ];

        battle.creatorScore =
          creatorSubmission
            ?.correct ??
          null;

        changed = true;
      }

      if (
        battle.opponentScore ===
        undefined
      ) {
        const opponentSubmission =
          battle.submissions[
            battle.opponentId
          ];

        battle.opponentScore =
          opponentSubmission
            ?.correct ??
          null;

        changed = true;
      }

      if (
        battle.resultProcessed ===
        undefined
      ) {
        battle.resultProcessed =
          [
            "completed",
            "draw",
            "expired",
            "cancelled"
          ].includes(
            battle.status
          );

        changed = true;
      }

      if (
        battle.winnerId ===
        undefined
      ) {
        battle.winnerId =
          null;

        changed = true;
      }

      if (
        battle.startedAt ===
        undefined
      ) {
        battle.startedAt =
          null;

        changed = true;
      }

      if (
        battle.endsAt ===
        undefined
      ) {
        battle.endsAt =
          null;

        changed = true;
      }

      if (
        battle.completedAt ===
        undefined
      ) {
        battle.completedAt =
          null;

        changed = true;
      }
    }
  );

  /*
     Wallet migration.
  */

  db.users.forEach(
    user => {
      const walletExists =
        db.wallets.some(
          wallet =>
            wallet.userId ===
            user.id
        );

      if (
        !walletExists
      ) {
        db.wallets.push({
          id:
            generateId(
              "wallet"
            ),

          userId:
            user.id,

          balance:
            Number(
              user.coins
            ) || 0,

          lifetimeEarned:
            0,

          lifetimeSpent:
            0,

          createdAt:
            nowISO(),

          updatedAt:
            nowISO()
        });

        changed = true;
      }
    }
  );

  /*
     Upgrade database version.
  */

  if (
    Number(
      db.meta.databaseVersion
    ) <
    CONFIG.databaseVersion
  ) {
    db.meta.databaseVersion =
      CONFIG.databaseVersion;

    changed = true;
  }

  return changed;
}

/* ============================================================
   45. SEED CONTENT
   ============================================================ */

function seedContent() {
  const db =
    readDatabase();

  let changed =
    false;

  /*
     Default question.
  */

  if (
    db.questions.length ===
    0
  ) {
    db.questions.push({
      id:
        generateId(
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
        "Muscarinic receptors are G-protein-coupled cholinergic receptors mediating many parasympathetic actions.",

      learningPoints: [
        "Muscarinic receptors are cholinergic receptors.",
        "They are G-protein-coupled receptors."
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
        "muscarinic"
      ],

      createdAt:
        nowISO()
    });

    changed = true;
  }

  /*
     Achievements.
  */

  const achievementDefinitions = [
    {
      id:
        "first_quiz",

      name:
        "First Quiz",

      description:
        "Complete your first quiz.",

      rewardXP:
        25,

      rewardCoins:
        10
    },

    {
      id:
        "questions_10",

      name:
        "Getting Started",

      description:
        "Answer 10 questions.",

      rewardXP:
        50,

      rewardCoins:
        20
    },

    {
      id:
        "questions_100",

      name:
        "Century Scholar",

      description:
        "Answer 100 questions.",

      rewardXP:
        250,

      rewardCoins:
        100
    },

    {
      id:
        "battle_win",

      name:
        "Gladiator",

      description:
        "Win your first quick battle.",

      rewardXP:
        100,

      rewardCoins:
        50
    },

    {
      id:
        "streak_7",

      name:
        "7-Day Streak",

      description:
        "Maintain a 7-day streak.",

      rewardXP:
        150,

      rewardCoins:
        75
    }
  ];

  achievementDefinitions.forEach(
    definition => {
      const exists =
        db.achievements.some(
          item =>
            item.id ===
            definition.id
        );

      if (!exists) {
        db.achievements.push(
          definition
        );

        changed = true;
      }
    }
  );

  /*
     Pharmacopoeia seed content.

     This remains student-friendly and does not attempt
     to reproduce copyrighted pharmacopoeial monographs.
  */

  if (
    db.pharmacopoeia.length ===
    0
  ) {
    db.pharmacopoeia.push({
      id:
        generateId(
          "drug"
        ),

      name:
        "Paracetamol (Acetaminophen)",

      category:
        "Analgesic / Antipyretic",

      indications:
        "Mild to moderate pain and fever reduction.",

      mechanism:
        "Produces analgesic and antipyretic effects primarily through central mechanisms.",

      dosage:
        "Use according to applicable product information and clinical guidance.",

      sideEffects:
        "Hepatotoxicity can occur with overdose.",

      references: [
        "BP concepts",
        "USP-NF concepts",
        "Ph. Eur. concepts"
      ],

      createdAt:
        nowISO()
    });

    changed = true;
  }

  /*
     Language seed content.
  */

  if (
    db.languagePhrases.length ===
    0
  ) {
    db.languagePhrases.push({
      id:
        generateId(
          "phrase"
        ),

      english:
        "Take this medication twice daily after meals.",

      localPidgin:
        "Take am two times every day after chop food.",

      igbo:
        "Were ogwu a ugboro abuo n'ubochi mgbe i risichara nri.",

      createdAt:
        nowISO()
    });

    changed = true;
  }

  if (
    db.languages.length ===
    0
  ) {
    db.languages.push(
      {
        id:
          "en",

        name:
          "English",

        nativeName:
          "English"
      },

      {
        id:
          "ig",

        name:
          "Igbo",

        nativeName:
          "Igbo"
      },

      {
        id:
          "pcm",

        name:
          "Nigerian Pidgin",

        nativeName:
          "Naijá Pidgin"
      }
    );

    changed = true;
  }

  if (changed) {
    writeDatabase(db);
  }
}

/* ============================================================
   46. STATIC FRONTEND
   ============================================================ */

if (
  fs.existsSync(
    PUBLIC_DIR
  )
) {
  app.use(
    express.static(
      PUBLIC_DIR
    )
  );

  /*
     Express 5 wildcard syntax:
       /{*splat}

     instead of:
       *
  */

  app.get(
    "/{*splat}",
    (req, res, next) => {
      if (
        req.path.startsWith(
          "/api/"
        )
      ) {
        return next();
      }

      const indexFile =
        path.join(
          PUBLIC_DIR,
          "index.html"
        );

      if (
        fs.existsSync(
          indexFile
        )
      ) {
        return res.sendFile(
          indexFile
        );
      }

      return next();
    }
  );
}

/* ============================================================
   47. 404 HANDLER
   ============================================================ */

app.use(
  (req, res) => {
    return sendError(
      res,
      404,
      "Endpoint not found."
    );
  }
);

/* ============================================================
   48. GLOBAL ERROR HANDLER
   ============================================================ */

app.use(
  (
    error,
    req,
    res,
    next
  ) => {
    console.error(
      "[SERVER ERROR]",
      error
    );

    if (
      res.headersSent
    ) {
      return next(
        error
      );
    }

    return sendError(
      res,
      500,
      "Internal server error."
    );
  }
);

/* ============================================================
   49. STARTUP
   ============================================================ */

function startServer() {
  try {
    ensureDatabase();

    const db =
      readDatabase();

    const migrated =
      migrateDatabase(
        db
      );

    if (migrated) {
      writeDatabase(db);

      console.log(
        "[DATABASE] Migration completed."
      );
    }

    seedContent();

    app.listen(
      PORT,
      () => {
        console.log(
          "============================================================"
        );

        console.log(
          `[${CONFIG.appName}]`
        );

        console.log(
          `Version: ${CONFIG.version}`
        );

        console.log(
          `Environment: ${CONFIG.environment}`
        );

        console.log(
          `Node requirement: ${CONFIG.nodeVersion}`
        );

        console.log(
          `Database version: ${CONFIG.databaseVersion}`
        );

        console.log(
          `Server running on port ${PORT}`
        );

        console.log(
          "Battle architecture: creatorId + opponentId"
        );

        console.log(
          "Battle scoring: creatorScore + opponentScore"
        );

        console.log(
          "Battle submissions: submissions"
        );

        console.log(
          "============================================================"
        );
      }
    );
  } catch (error) {
    console.error(
      "[STARTUP ERROR]",
      error
    );

    process.exit(1);
  }
}

startServer();

/* ============================================================
   EXPORT
   ============================================================ */

module.exports = app;
