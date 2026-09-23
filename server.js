"use strict";

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "3.0.1";
const CONTENT_YEAR = process.env.CONTENT_YEAR || "2026";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");
const PUBLIC_DIR = path.join(__dirname, "public");


// ============================================================
// DATABASE
// ============================================================

const DEFAULT_DB = {
  users: [],
  questions: [],
  scores: [],
  battles: [],
  referrals: [],
  subscriptions: [],
  dailyChallenges: [],
  achievements: [],
  sessions: []
};


function ensureDatabase() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(
      DB_FILE,
      JSON.stringify(DEFAULT_DB, null, 2),
      "utf8"
    );
  }
}


function loadDB() {
  ensureDatabase();

  try {
    const raw = fs.readFileSync(DB_FILE, "utf8");

    const db = JSON.parse(raw);

    for (const key of Object.keys(DEFAULT_DB)) {
      if (!Array.isArray(db[key])) {
        db[key] = [];
      }
    }

    return db;

  } catch (error) {

    console.error("Database read error:", error);

    return JSON.parse(JSON.stringify(DEFAULT_DB));
  }
}


function saveDB(db) {
  ensureDatabase();

  fs.writeFileSync(
    DB_FILE,
    JSON.stringify(db, null, 2),
    "utf8"
  );
}


ensureDatabase();


// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors({
  origin: process.env.CLIENT_ORIGIN || "*"
}));

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
  res.setHeader("X-DENexpharm-Version", APP_VERSION);
  res.setHeader("X-DENexpharm-Content-Year", CONTENT_YEAR);
  next();
});

if (fs.existsSync(PUBLIC_DIR)) {
  app.use(express.static(PUBLIC_DIR));
}


// ============================================================
// HELPERS
// ============================================================

function id(prefix = "id") {
  return `${prefix}_${crypto.randomBytes(8).toString("hex")}`;
}


function now() {
  return new Date().toISOString();
}


function cleanEmail(email) {
  return String(email || "").trim().toLowerCase();
}


function cleanText(value, max = 500) {
  return String(value || "")
    .trim()
    .slice(0, max);
}


function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(String(password))
    .digest("hex");
}


function makeToken(userId) {
  const secret =
    process.env.AUTH_SECRET ||
    "denexpharm-development-secret-change-in-production";

  const payload = Buffer.from(
    JSON.stringify({
      userId,
      iat: Date.now()
    })
  ).toString("base64url");

  const signature = crypto
    .createHmac("sha256", secret)
    .update(payload)
    .digest("base64url");

  return `${payload}.${signature}`;
}


function verifyToken(token) {
  try {

    if (!token || !token.includes(".")) {
      return null;
    }

    const [payload, signature] = token.split(".");

    const secret =
      process.env.AUTH_SECRET ||
      "denexpharm-development-secret-change-in-production";

    const expected = crypto
      .createHmac("sha256", secret)
      .update(payload)
      .digest("base64url");

    if (signature.length !== expected.length) {
      return null;
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(signature),
        Buffer.from(expected)
      )
    ) {
      return null;
    }

    const decoded = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    return decoded.userId || null;

  } catch (error) {
    return null;
  }
}


function authUser(req) {

  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.substring(7);

  const userId = verifyToken(token);

  if (!userId) {
    return null;
  }

  const db = loadDB();

  return db.users.find(
    user => user.id === userId
  ) || null;
}


function requireAuth(req, res, next) {

  const user = authUser(req);

  if (!user) {
    return res.status(401).json({
      success: false,
      error: "Authentication required"
    });
  }

  req.user = user;

  next();
}


function publicUser(user) {

  if (!user) {
    return null;
  }

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    country: user.country || "",
    school: user.school || "",
    level: user.level || "",
    referralCode: user.referralCode,
    xp: user.xp || 0,
    coins: user.coins || 0,
    createdAt: user.createdAt
  };
}


function generateReferralCode(name) {

  const base =
    String(name || "DEN")
      .replace(/[^a-zA-Z0-9]/g, "")
      .toUpperCase()
      .slice(0, 6) || "DEN";

  return `${base}${crypto.randomBytes(3)
    .toString("hex")
    .toUpperCase()}`;
}


function shuffle(array) {

  const result = [...array];

  for (let i = result.length - 1; i > 0; i--) {

    const j =
      Math.floor(Math.random() * (i + 1));

    [result[i], result[j]] =
      [result[j], result[i]];
  }

  return result;
}


function safeQuestion(question) {

  return {
    id: question.id,
    subject: question.subject,
    topic: question.topic,
    question: question.question,
    options: question.options,
    difficulty: question.difficulty || "medium",
    marks: question.marks || 1
  };
}


// ============================================================
// STARTER QUESTION BANK
// ============================================================

function createStarterQuestions() {

  const db = loadDB();

  if (db.questions.length > 0) {
    return;
  }

  const questions = [

    {
      subject: "Pharmacology",
      topic: "General Pharmacology",
      question: "Which route of administration gives complete systemic bioavailability in a typical clinical setting?",
      options: [
        "Oral",
        "Intravenous",
        "Subcutaneous",
        "Rectal"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Pharmacokinetics",
      topic: "Absorption",
      question: "Bioavailability refers to:",
      options: [
        "The rate of renal excretion",
        "The fraction of an administered dose reaching systemic circulation unchanged",
        "The amount of drug bound to plasma proteins",
        "The volume of distribution"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Dispensing",
      topic: "Prescription",
      question: "Which information is essential on a properly prepared prescription?",
      options: [
        "Only the patient's first name",
        "Drug name, strength, dosage form and directions",
        "Only the price of the medicine",
        "Only the pharmacist's telephone number"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Pharmaceutics",
      topic: "Solutions",
      question: "A pharmaceutical solution is best described as:",
      options: [
        "A heterogeneous mixture",
        "A homogeneous mixture",
        "A suspension of insoluble particles",
        "A mixture containing only solids"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Pharmaceutics",
      topic: "Particle Size Reduction",
      question: "Which law relates energy requirement to the new surface area produced during size reduction?",
      options: [
        "Hooke's law",
        "Rittinger's law",
        "Boyle's law",
        "Raoult's law"
      ],
      answer: 1,
      difficulty: "medium"
    },

    {
      subject: "Pharmacognosy",
      topic: "Crude Drugs",
      question: "Pharmacognosy is primarily concerned with:",
      options: [
        "The study of crude drugs from natural sources",
        "Only synthetic polymers",
        "Only hospital administration",
        "Only surgical procedures"
      ],
      answer: 0,
      difficulty: "easy"
    },

    {
      subject: "Pharmaceutical Microbiology",
      topic: "Sterilization",
      question: "Which method is commonly used for sterilizing culture media?",
      options: [
        "Autoclaving",
        "Freezing",
        "Filtration through ordinary paper",
        "Sun drying"
      ],
      answer: 0,
      difficulty: "easy"
    },

    {
      subject: "Biochemistry",
      topic: "Enzymes",
      question: "Most enzymes are:",
      options: [
        "Proteins",
        "Lipids",
        "Minerals",
        "Nucleic acid salts"
      ],
      answer: 0,
      difficulty: "easy"
    },

    {
      subject: "Physiology",
      topic: "Blood",
      question: "Which blood cells are primarily responsible for oxygen transport?",
      options: [
        "Platelets",
        "Erythrocytes",
        "Neutrophils",
        "Lymphocytes"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Anatomy",
      topic: "Thorax",
      question: "The heart is located primarily in the:",
      options: [
        "Abdominal cavity",
        "Mediastinum",
        "Pelvic cavity",
        "Cranial cavity"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Clinical Pharmacy",
      topic: "Patient Care",
      question: "The primary purpose of medication counselling is to:",
      options: [
        "Increase medicine cost",
        "Help the patient use medicines safely and effectively",
        "Replace diagnosis",
        "Eliminate the need for monitoring"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Pharmacy Practice",
      topic: "Patient Counselling",
      question: "Which approach is most appropriate when counselling a patient?",
      options: [
        "Use understandable language and confirm understanding",
        "Use only technical terminology",
        "Avoid discussing directions",
        "Give instructions without allowing questions"
      ],
      answer: 0,
      difficulty: "easy"
    },

    {
      subject: "Pharmaceutical Physical Chemistry",
      topic: "pH",
      question: "At 25°C, a neutral aqueous solution has a pH of approximately:",
      options: [
        "1",
        "5",
        "7",
        "14"
      ],
      answer: 2,
      difficulty: "easy"
    },

    {
      subject: "Pharmaceutical Entrepreneurship",
      topic: "Business",
      question: "A business plan primarily helps an entrepreneur to:",
      options: [
        "Avoid identifying customers",
        "Structure goals, strategies and financial expectations",
        "Guarantee profit",
        "Eliminate competition"
      ],
      answer: 1,
      difficulty: "easy"
    },

    {
      subject: "Pharmacology",
      topic: "Adverse Drug Reactions",
      question: "An adverse drug reaction is best described as:",
      options: [
        "A beneficial therapeutic effect",
        "A harmful and unintended response to a medicine at normal doses",
        "A medicine's packaging",
        "A patient's diagnosis"
      ],
      answer: 1,
      difficulty: "medium"
    },

    {
      subject: "Pharmacokinetics",
      topic: "Half-life",
      question: "Drug half-life is the time required for:",
      options: [
        "The drug to become completely inactive",
        "The plasma concentration to decrease by approximately 50%",
        "The drug to be absorbed completely",
        "The patient to recover"
      ],
      answer: 1,
      difficulty: "easy"
    }

  ];


  const records = questions.map(q => ({
    id: id("q"),
    ...q,
    marks: 1,
    createdAt: now(),
    updatedAt: now()
  }));

  db.questions.push(...records);

  saveDB(db);

  console.log(
    `Starter question bank created: ${records.length} questions`
  );
}


createStarterQuestions();


// ============================================================
// HEALTH
// ============================================================

app.get("/api/v1/health", (req, res) => {

  res.json({
    success: true,
    status: "healthy",
    service: "DENexpharm",
    version: APP_VERSION,
    contentYear: CONTENT_YEAR,
    time: now()
  });

});


// ============================================================
// CONFIG
// ============================================================

app.get("/api/v1/config", (req, res) => {

  res.json({
    success: true,
    appName: "DENexpharm",
    version: APP_VERSION,
    contentYear: CONTENT_YEAR,
    features: {
      quiz: true,
      pharmacokinetics: true,
      dispensing: true,
      gpaCalculator: true,
      leaderboard: true,
      dailyChallenge: true,
      timedBattle: true,
      pharmacopoeiaHub: true,
      languageAssistant: true,
      referrals: true,
      achievements: true,
      subscriptions: true
    }
  });

});


// ============================================================
// SUBJECTS
// ============================================================

app.get("/api/v1/subjects", (req, res) => {

  const db = loadDB();

  const names = [
    "Pharmacology",
    "Pharmacokinetics",
    "Dispensing",
    "Pharmaceutics",
    "Pharmacognosy",
    "Pharmaceutical Microbiology",
    "Pharmacy Practice",
    "Pharmaceutical Physical Chemistry",
    "Biochemistry",
    "Physiology",
    "Anatomy",
    "Clinical Pharmacy",
    "Pharmaceutical Entrepreneurship"
  ];

  const subjects = names.map(name => {

    const count =
      db.questions.filter(
        q => q.subject === name
      ).length;

    return {
      code: name
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_|_$/g, ""),

      name,
      questionCount: count
    };

  });

  res.json({
    success: true,
    subjects
  });

});


// ============================================================
// AUTH — REGISTER
// ============================================================

app.post("/api/v1/auth/register", (req, res) => {

  const db = loadDB();

  const name =
    cleanText(req.body.name, 100);

  const email =
    cleanEmail(req.body.email);

  const password =
    String(req.body.password || "");

  const country =
    cleanText(req.body.country, 80);

  const school =
    cleanText(req.body.school, 150);

  const level =
    cleanText(req.body.level, 50);

  if (!name || !email || !password) {

    return res.status(400).json({
      success: false,
      error: "Name, email and password are required"
    });

  }

  if (password.length < 6) {

    return res.status(400).json({
      success: false,
      error: "Password must contain at least 6 characters"
    });

  }

  if (
    db.users.some(
      user => user.email === email
    )
  ) {

    return res.status(409).json({
      success: false,
      error: "An account with this email already exists"
    });

  }

  const referralCode =
    generateReferralCode(name);

  const user = {

    id: id("user"),

    name,
    email,

    passwordHash:
      hashPassword(password),

    country,
    school,
    level,

    referralCode,

    xp: 0,
    coins: 0,

    createdAt: now(),
    updatedAt: now()

  };

  db.users.push(user);

  const suppliedReferral =
    cleanText(
      req.body.referralCode,
      50
    ).toUpperCase();

  if (suppliedReferral) {

    const referrer =
      db.users.find(
        u =>
          String(u.referralCode)
            .toUpperCase() === suppliedReferral
      );

    if (referrer && referrer.id !== user.id) {

      db.referrals.push({
        id: id("ref"),
        referrerId: referrer.id,
        referredUserId: user.id,
        code: suppliedReferral,
        createdAt: now()
      });

      referrer.coins =
        (referrer.coins || 0) + 50;

      referrer.xp =
        (referrer.xp || 0) + 25;

      user.coins = 25;
      user.xp = 10;
    }
  }

  saveDB(db);

  const token =
    makeToken(user.id);

  res.status(201).json({
    success: true,
    token,
    user: publicUser(user)
  });

});


// ============================================================
// AUTH — LOGIN
// ============================================================

app.post("/api/v1/auth/login", (req, res) => {

  const db = loadDB();

  const email =
    cleanEmail(req.body.email);

  const password =
    String(req.body.password || "");

  const user =
    db.users.find(
      u => u.email === email
    );

  if (
    !user ||
    user.passwordHash !== hashPassword(password)
  ) {

    return res.status(401).json({
      success: false,
      error: "Invalid email or password"
    });

  }

  const token =
    makeToken(user.id);

  res.json({
    success: true,
    token,
    user: publicUser(user)
  });

});


// ============================================================
// AUTH — ME
// ============================================================

app.get(
  "/api/v1/auth/me",
  requireAuth,
  (req, res) => {

    res.json({
      success: true,
      user: publicUser(req.user)
    });

  }
);


// ============================================================
// PROFILE
// ============================================================

app.get(
  "/api/v1/profile",
  requireAuth,
  (req, res) => {

    res.json({
      success: true,
      user: publicUser(req.user)
    });

  }
);


app.put(
  "/api/v1/profile",
  requireAuth,
  (req, res) => {

    const db = loadDB();

    const user =
      db.users.find(
        u => u.id === req.user.id
      );

    if (!user) {

      return res.status(404).json({
        success: false,
        error: "User not found"
      });

    }

    if (req.body.name !== undefined) {
      user.name =
        cleanText(req.body.name, 100);
    }

    if (req.body.country !== undefined) {
      user.country =
        cleanText(req.body.country, 80);
    }

    if (req.body.school !== undefined) {
      user.school =
        cleanText(req.body.school, 150);
    }

    if (req.body.level !== undefined) {
      user.level =
        cleanText(req.body.level, 50);
    }

    user.updatedAt = now();

    saveDB(db);

    res.json({
      success: true,
      user: publicUser(user)
    });

  }
);


// ============================================================
// QUIZ — QUESTIONS
// ============================================================

app.get("/api/v1/quiz/questions", (req, res) => {

  const db = loadDB();

  const subject =
    cleanText(req.query.subject, 150);

  let limit =
    Number(req.query.limit || 10);

  if (!Number.isFinite(limit)) {
    limit = 10;
  }

  limit =
    Math.max(1, Math.min(50, limit));

  let questions =
    [...db.questions];

  if (subject) {

    const normalized =
      subject.toLowerCase();

    questions =
      questions.filter(
        q =>
          q.subject.toLowerCase() ===
          normalized ||
          q.subject
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, "_") ===
          normalized
      );

  }

  questions =
    shuffle(questions)
      .slice(0, limit)
      .map(safeQuestion);

  res.json({
    success: true,
    questions
  });

});


// ============================================================
// QUIZ — SUBMIT
// ============================================================

app.post("/api/v1/quiz/submit", (req, res) => {

  const db = loadDB();

  const answers =
    Array.isArray(req.body.answers)
      ? req.body.answers
      : [];

  if (!answers.length) {

    return res.status(400).json({
      success: false,
      error: "No answers submitted"
    });

  }

  let correct = 0;

  const details = [];

  for (const item of answers) {

    const question =
      db.questions.find(
        q => q.id === item.questionId
      );

    if (!question) {
      continue;
    }

    const answerIndex =
      Number(item.answerIndex);

    const isCorrect =
      answerIndex === question.answer;

    if (isCorrect) {
      correct++;
    }

    details.push({
      questionId: question.id,
      correct: isCorrect
    });

  }

  const total =
    details.length;

  const score =
    total
      ? Math.round((correct / total) * 100)
      : 0;

  const user =
    authUser(req);

  const scoreRecord = {

    id: id("score"),

    userId:
      user ? user.id : null,

    correct,
    total,
    score,

    createdAt: now()

  };

  db.scores.push(scoreRecord);

  if (user) {

    const dbUser =
      db.users.find(
        u => u.id === user.id
      );

    if (dbUser) {

      dbUser.xp =
        (dbUser.xp || 0) +
        correct * 10;

      dbUser.coins =
        (dbUser.coins || 0) +
        correct * 2;
    }
  }

  saveDB(db);

  res.json({
    success: true,
    score,
    correct,
    total,
    details
  });

});


// ============================================================
// SCORE HISTORY
// ============================================================

app.get(
  "/api/v1/scores/me",
  requireAuth,
  (req, res) => {

    const db = loadDB();

    const scores =
      db.scores
        .filter(
          score =>
            score.userId === req.user.id
        )
        .sort(
          (a, b) =>
            new Date(b.createdAt) -
            new Date(a.createdAt)
        );

    res.json({
      success: true,
      scores
    });

  }
);


// ============================================================
// LEADERBOARD
// ============================================================

app.get("/api/v1/leaderboard", (req, res) => {

  const db = loadDB();

  const limit =
    Math.max(
      1,
      Math.min(
        100,
        Number(req.query.limit || 20)
      )
    );

  const totals = {};

  for (const score of db.scores) {

    if (!score.userId) {
      continue;
    }

    if (!totals[score.userId]) {

      totals[score.userId] = {
        totalScore: 0,
        quizzes: 0
      };

    }

    totals[score.userId].totalScore +=
      Number(score.score || 0);

    totals[score.userId].quizzes++;
  }

  const leaderboard =
    Object.entries(totals)
      .map(([userId, stats]) => {

        const user =
          db.users.find(
            u => u.id === userId
          );

        if (!user) {
          return null;
        }

        return {
          userId,
          name: user.name,
          score: stats.totalScore,
          quizzes: stats.quizzes,
          xp: user.xp || 0
        };

      })
      .filter(Boolean)
      .sort(
        (a, b) =>
          b.score - a.score ||
          b.xp - a.xp
      )
      .slice(0, limit);

  res.json({
    success: true,
    leaderboard
  });

});


// ============================================================
// GPA CALCULATOR
// ============================================================

app.post("/api/v1/gpa/calculate", (req, res) => {

  const courses =
    Array.isArray(req.body.courses)
      ? req.body.courses
      : [];

  if (!courses.length) {

    return res.status(400).json({
      success: false,
      error: "At least one course is required"
    });

  }

  const gradePoints = {
    A: 5,
    B: 4,
    C: 3,
    D: 2,
    E: 1,
    F: 0
  };

  let totalCreditUnits = 0;
  let totalQualityPoints = 0;

  for (const course of courses) {

    const units =
      Number(
        course.creditUnits ??
        course.units ??
        0
      );

    const grade =
      String(
        course.grade || ""
      ).toUpperCase();

    if (
      !Number.isFinite(units) ||
      units <= 0 ||
      gradePoints[grade] === undefined
    ) {
      continue;
    }

    totalCreditUnits += units;

    totalQualityPoints +=
      units * gradePoints[grade];

  }

  const gpa =
    totalCreditUnits
      ? totalQualityPoints / totalCreditUnits
      : 0;

  res.json({
    success: true,
    gpa: Number(gpa.toFixed(2)),
    totalCreditUnits,
    totalQualityPoints
  });

});


// ============================================================
// PHARMACOPOEIA HUB
// ============================================================

const pharmacopoeiaData = [

  {
    code: "BP",
    name: "British Pharmacopoeia",
    region: "United Kingdom",
    description:
      "A major pharmacopoeial reference containing standards and requirements for medicines and pharmaceutical substances."
  },

  {
    code: "USP",
    name: "United States Pharmacopeia",
    region: "United States",
    description:
      "A major standards-setting reference for medicines, dosage forms, ingredients and related quality requirements."
  },

  {
    code: "PH_EUR",
    name: "European Pharmacopoeia",
    region: "Europe",
    description:
      "A regional pharmacopoeial reference establishing quality standards for medicines and pharmaceutical substances."
  },

  {
    code: "WHO",
    name: "WHO Pharmacopoeial Concepts",
    region: "International",
    description:
      "Internationally relevant concepts concerning medicine quality, standards and pharmaceutical quality assurance."
  }

];


app.get("/api/v1/pharmacopoeia", (req, res) => {

  res.json({
    success: true,
    pharmacopoeia: pharmacopoeiaData
  });

});


app.get(
  "/api/v1/pharmacopoeia/:code",
  (req, res) => {

    const code =
      String(req.params.code)
        .toUpperCase();

    const item =
      pharmacopoeiaData.find(
        p =>
          p.code === code
      );

    if (!item) {

      return res.status(404).json({
        success: false,
        error: "Pharmacopoeia entry not found"
      });

    }

    res.json({
      success: true,
      item
    });

  }
);


// ============================================================
// PHARMACY LANGUAGE ASSISTANT
// ============================================================

const languageData = [

  {
    code: "en",
    name: "English"
  },

  {
    code: "fr",
    name: "French"
  },

  {
    code: "es",
    name: "Spanish"
  },

  {
    code: "de",
    name: "German"
  },

  {
    code: "pt",
    name: "Portuguese"
  },

  {
    code: "sw",
    name: "Swahili"
  },

  {
    code: "ha",
    name: "Hausa"
  },

  {
    code: "yo",
    name: "Yoruba"
  },

  {
    code: "ig",
    name: "Igbo"
  }

];


const languagePhrases = [

  {
    language: "English",
    category: "Counselling",
    phrase: "Take this medicine exactly as directed."
  },

  {
    language: "French",
    category: "Counselling",
    phrase: "Prenez ce médicament exactement comme indiqué."
  },

  {
    language: "Spanish",
    category: "Counselling",
    phrase: "Tome este medicamento exactamente como se le indicó."
  },

  {
    language: "Igbo",
    category: "Counselling",
    phrase: "Were ọgwụ a dịka e nyere gị ntụziaka."
  },

  {
    language: "Yoruba",
    category: "Counselling",
    phrase: "Lo oogun yii gẹgẹ bi a ti sọ fun ọ."
  },

  {
    language: "Hausa",
    category: "Counselling",
    phrase: "Yi amfani da wannan magani kamar yadda aka umarce ka."
  }

];


app.get("/api/v1/language", (req, res) => {

  res.json({
    success: true,
    languages: languageData,
    phrases: languagePhrases
  });

});


app.get("/api/v1/language/phrase", (req, res) => {

  const language =
    cleanText(req.query.language, 50);

  let phrases =
    [...languagePhrases];

  if (language) {

    phrases =
      phrases.filter(
        p =>
          p.language.toLowerCase() ===
          language.toLowerCase()
      );

  }

  res.json({
    success: true,
    phrases
  });

});


// ============================================================
// DAILY CHALLENGE
// ============================================================

function getTodayKey() {

  return new Date()
    .toISOString()
    .slice(0, 10);

}


app.get(
  "/api/v1/daily-challenge",
  (req, res) => {

    const db = loadDB();

    const today =
      getTodayKey();

    let challenge =
      db.dailyChallenges.find(
        item =>
          item.date === today
      );

    if (!challenge) {

      if (!db.questions.length) {

        return res.status(404).json({
          success: false,
          error: "No questions available"
        });

      }

      const question =
        db.questions[
          Math.floor(
            Math.random() *
            db.questions.length
          )
        ];

      challenge = {

        id: id("daily"),

        date: today,

        questionId:
          question.id,

        createdAt: now()

      };

      db.dailyChallenges.push(challenge);

      saveDB(db);

    }

    const question =
      db.questions.find(
        q =>
          q.id === challenge.questionId
      );

    if (!question) {

      return res.status(404).json({
        success: false,
        error: "Daily question unavailable"
      });

    }

    res.json({
      success: true,
      date: today,
      challengeId: challenge.id,
      question: safeQuestion(question)
    });

  }
);


// ============================================================
// DAILY CHALLENGE SUBMIT
// ============================================================

app.post(
  "/api/v1/daily-challenge/submit",
  (req, res) => {

    const db = loadDB();

    const today =
      getTodayKey();

    const challenge =
      db.dailyChallenges.find(
        item =>
          item.date === today
      );

    if (!challenge) {

      return res.status(404).json({
        success: false,
        error: "Today's challenge has not been created"
      });

    }

    const question =
      db.questions.find(
        q =>
          q.id === challenge.questionId
      );

    if (!question) {

      return res.status(404).json({
        success: false,
        error: "Challenge question unavailable"
      });

    }

    const answerIndex =
      Number(req.body.answerIndex);

    const correct =
      answerIndex === question.answer;

    const user =
      authUser(req);

    if (user && correct) {

      const dbUser =
        db.users.find(
          u =>
            u.id === user.id
        );

      if (dbUser) {

        dbUser.xp =
          (dbUser.xp || 0) + 25;

        dbUser.coins =
          (dbUser.coins || 0) + 5;

      }

    }

    saveDB(db);

    res.json({
      success: true,
      correct,
      reward: correct
        ? {
            xp: 25,
            coins: 5
          }
        : {
            xp: 0,
            coins: 0
          }
    });

  }
);


// ============================================================
// TIMED BATTLE — CREATE
// ============================================================

app.post(
  "/api/v1/battle/create",
  requireAuth,
  (req, res) => {

    const db = loadDB();

    const questionCount =
      Math.max(
        1,
        Math.min(
          20,
          Number(
            req.body.questionCount || 10
          )
        )
      );

    const questions =
      shuffle(db.questions)
        .slice(0, questionCount);

    const battle = {

      id: id("battle"),

      hostId:
        req.user.id,

      opponentId: null,

      status: "waiting",

      questionIds:
        questions.map(
          q => q.id
        ),

      hostAnswers: [],

      opponentAnswers: [],

      createdAt: now(),

      startedAt: null,

      finishedAt: null

    };

    db.battles.push(battle);

    saveDB(db);

    res.status(201).json({
      success: true,
      battle: {
        id: battle.id,
        status: battle.status,
        questionCount:
          battle.questionIds.length
      }
    });

  }
);


// ============================================================
// TIMED BATTLE — JOIN
// ============================================================

app.post(
  "/api/v1/battle/:battleId/join",
  requireAuth,
  (req, res) => {

    const db = loadDB();

    const battle =
      db.battles.find(
        b =>
          b.id === req.params.battleId
      );

    if (!battle) {

      return res.status(404).json({
        success: false,
        error: "Battle not found"
      });

    }

    if (
      battle.hostId === req.user.id
    ) {

      return res.json({
        success: true,
        battle: {
          id: battle.id,
          status: battle.status
        }
      });

    }

    if (battle.opponentId) {

      return res.status(409).json({
        success: false,
        error: "Battle already has an opponent"
      });

    }

    battle.opponentId =
      req.user.id;

    battle.status = "active";
    battle.startedAt = now();

    saveDB(db);

    res.json({
      success: true,
      battle: {
        id: battle.id,
        status: battle.status,
        questionCount:
          battle.questionIds.length
      }
    });

  }
);


// ============================================================
// TIMED BATTLE — GET
// ============================================================

app.get(
  "/api/v1/battle/:battleId",
  requireAuth,
  (req, res) => {

    const db = loadDB();

    const battle =
      db.battles.find(
        b =>
          b.id === req.params.battleId
      );

    if (!battle) {

      return res.status(404).json({
        success: false,
        error: "Battle not found"
      });

    }

    const isParticipant =
      battle.hostId === req.user.id ||
      battle.opponentId === req.user.id;

    if (!isParticipant) {

      return res.status(403).json({
        success: false,
        error: "You are not a participant in this battle"
      });

    }

    const questions =
      battle.questionIds
        .map(
          questionId =>
            db.questions.find(
              q =>
                q.id === questionId
            )
        )
        .filter(Boolean)
        .map(safeQuestion);

    res.json({
      success: true,
      battle: {
        id: battle.id,
        status: battle.status,
        questionCount:
          questions.length,
        questions
      }
    });

  }
);


// ============================================================
// TIMED BATTLE — SUBMIT
// ============================================================

app.post(
  "/api/v1/battle/:battleId/submit",
  requireAuth,
  (req, res) => {

    const db = loadDB();

    const battle =
      db.battles.find(
        b =>
          b.id === req.params.battleId
      );

    if (!battle) {

      return res.status(404).json({
        success: false,
        error: "Battle not found"
      });

    }

    const isHost =
      battle.hostId === req.user.id;

    const isOpponent =
      battle.opponentId === req.user.id;

    if (!isHost && !isOpponent) {

      return res.status(403).json({
        success: false,
        error: "You are not part of this battle"
      });

    }

    const answers =
      Array.isArray(req.body.answers)
        ? req.body.answers
        : [];

    let correct = 0;

    for (const item of answers) {

      const question =
        db.questions.find(
          q =>
            q.id === item.questionId
        );

      if (!question) {
        continue;
      }

      if (
        Number(item.answerIndex) ===
        question.answer
      ) {
        correct++;
      }

    }

    if (isHost) {
      battle.hostAnswers = answers;
      battle.hostScore = correct;
    }

    if (isOpponent) {
      battle.opponentAnswers = answers;
      battle.opponentScore = correct;
    }

    if (
      battle.hostAnswers.length > 0 &&
      battle.opponentAnswers.length > 0
    ) {

      battle.status = "finished";
      battle.finishedAt = now();

    }

    saveDB(db);

    res.json({
      success: true,
      correct,
      total: answers.length,
      score: correct,
      battleStatus: battle.status
    });

  }
);


// ============================================================
// REFERRALS
// ============================================================

app.get(
  "/api/v1/referrals/me",
  requireAuth,
  (req
