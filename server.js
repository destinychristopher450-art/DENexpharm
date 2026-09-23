/*
===========================================================
 DENexpharm - Full Stack Pharmacy Learning & Competition
 Phase 1 + Phase 2 + Phase 3 (Complete Backend)
===========================================================
*/

"use strict";

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "3.0.0";
const CONTENT_YEAR = process.env.CONTENT_YEAR || "2026";

const DATA_DIR = path.join(__dirname, "data");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_FILE = path.join(DATA_DIR, "database.json");

const DEFAULT_DB = {
    users: [],
    questions: [],
    scores: [],
    battles: [],
    referrals: [],
    subscriptions: [],
    dailyChallenges: [],
    achievements: []
};

function loadDB() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            fs.writeFileSync(
                DB_FILE,
                JSON.stringify(DEFAULT_DB, null, 2)
            );
            return JSON.parse(JSON.stringify(DEFAULT_DB));
        }

        const content = fs.readFileSync(DB_FILE, "utf8");

        if (!content.trim()) {
            return JSON.parse(JSON.stringify(DEFAULT_DB));
        }

        return {
            ...DEFAULT_DB,
            ...JSON.parse(content)
        };
    } catch (error) {
        console.error("Database read error:", error);
        return JSON.parse(JSON.stringify(DEFAULT_DB));
    }
}

let db = loadDB();

function saveDB() {
    fs.writeFileSync(
        DB_FILE,
        JSON.stringify(db, null, 2)
    );
}

function id(prefix = "") {
    return (
        prefix +
        crypto.randomBytes(8).toString("hex")
    );
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(password)
        .digest("hex");
}

function createToken(userId) {
    const payload = {
        userId,
        createdAt: Date.now()
    };

    const encoded = Buffer
        .from(JSON.stringify(payload))
        .toString("base64url");

    const signature = crypto
        .createHmac(
            "sha256",
            process.env.JWT_SECRET || "CHANGE_THIS_SECRET"
        )
        .update(encoded)
        .digest("base64url");

    return `${encoded}.${signature}`;
}

function verifyToken(token) {
    try {
        if (!token) return null;

        const parts = token.split(".");

        if (parts.length !== 2) {
            return null;
        }

        const [encoded, signature] = parts;

        const expected = crypto
            .createHmac(
                "sha256",
                process.env.JWT_SECRET || "CHANGE_THIS_SECRET"
            )
            .update(encoded)
            .digest("base64url");

        if (signature !== expected) {
            return null;
        }

        const payload = JSON.parse(
            Buffer.from(encoded, "base64url").toString()
        );

        return payload;
    } catch {
        return null;
    }
}

function auth(req, res, next) {
    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
        ? header.substring(7)
        : null;

    const payload = verifyToken(token);

    if (!payload) {
        return res.status(401).json({
            success: false,
            message: "Authentication required."
        });
    }

    const user = db.users.find(
        u => u.id === payload.userId
    );

    if (!user) {
        return res.status(401).json({
            success: false,
            message: "User account not found."
        });
    }

    req.user = user;

    next();
}

function adminOnly(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({
            success: false,
            message: "Administrator access required."
        });
    }

    next();
}

function sanitizeUser(user) {
    if (!user) return null;

    return {
        id: user.id,
        name: user.name,
        email: user.email,
        university: user.university,
        country: user.country,
        level: user.level,
        xp: user.xp || 0,
        coins: user.coins || 0,
        quizzesCompleted: user.quizzesCompleted || 0,
        correctAnswers: user.correctAnswers || 0,
        createdAt: user.createdAt,
        appVersion: user.appVersion
    };
}

/* ---------------------------------------------------------
   MIDDLEWARE
--------------------------------------------------------- */

app.use(
    cors({
        origin: process.env.CLIENT_ORIGIN || "*"
    })
);

app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    res.setHeader(
        "X-DENexpharm-Version",
        APP_VERSION
    );

    next();
});

app.use(express.static(path.join(__dirname, "public")));

/* ---------------------------------------------------------
   HEALTH / SYSTEM
--------------------------------------------------------- */

app.get("/api/v1/health", (req, res) => {
    res.json({
        success: true,
        app: "DENexpharm",
        version: APP_VERSION,
        contentYear: CONTENT_YEAR,
        status: "online",
        serverTime: new Date().toISOString()
    });
});

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
            pharmacopoeiaHub: true,
            languageAssistant: true,
            leaderboard: true,
            dailyChallenge: true,
            timedBattle: true,
            authentication: true,
            referrals: true,
            subscriptions: true,
            achievements: true
        }
    });
});

/* ---------------------------------------------------------
   QUESTIONS SEED DATA
--------------------------------------------------------- */

const starterQuestions = [
    {
        id: "q001",
        subject: "Pharmacokinetics",
        question: "Which pharmacokinetic process describes movement of a drug from the site of administration into systemic circulation?",
        options: ["Absorption", "Distribution", "Metabolism", "Excretion"],
        answer: 0,
        explanation: "Absorption is the movement of a drug from its site of administration into systemic circulation.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },
    {
        id: "q002",
        subject: "Pharmacokinetics",
        question: "Which parameter describes the theoretical volume required to contain the total amount of drug at the same concentration found in plasma?",
        options: ["Clearance", "Volume of distribution", "Half-life", "Bioavailability"],
        answer: 1,
        explanation: "Volume of distribution relates the amount of drug in the body to its plasma concentration.",
        difficulty: "medium",
        year: CONTENT_YEAR,
        active: true
    },
    {
        id: "q003",
        subject: "Dispensing",
        question: "Which information should be clearly included on a dispensed medicine label?",
        options: ["Patient directions", "The pharmacist's favourite colour", "A random identification number", "The weather forecast"],
        answer: 0,
        explanation: "A dispensing label should provide appropriate directions for safe use, together with relevant identification information.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },
    {
        id: "q004",
        subject: "Pharmaceutics",
        question: "Which dosage form is designed to be swallowed and release the drug in the gastrointestinal tract?",
        options: ["Tablet", "Eye drop", "Ointment", "Transdermal patch"],
        answer: 0,
        explanation: "Tablets are solid oral dosage forms intended for administration through the mouth.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },
    {
        id: "q005",
        subject: "Pharmacology",
        question: "Pharmacodynamics primarily describes:",
        options: ["What the drug does to the body", "What the body does to the drug", "How drugs are manufactured", "How prescriptions are printed"],
        answer: 0,
        explanation: "Pharmacodynamics concerns the effects of drugs on biological systems and their mechanisms of action.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    }
];

if (db.questions.length === 0) {
    db.questions = starterQuestions;
    saveDB();
}

/* ---------------------------------------------------------
   AUTHENTICATION
--------------------------------------------------------- */

app.post("/api/v1/auth/register", (req, res) => {
    const { name, email, password, university = "", country = "", level = "" } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ success: false, message: "Name, email and password are required." });
    }

    if (password.length < 6) {
        return res.status(400).json({ success: false, message: "Password must contain at least 6 characters." });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = db.users.find(u => u.email === normalizedEmail);

    if (existing) {
        return res.status(409).json({ success: false, message: "An account with this email already exists." });
    }

    const user = {
        id: id("usr_"),
        name: String(name).trim(),
        email: normalizedEmail,
        passwordHash: hashPassword(password),
        university,
        country,
        level,
        role: "student",
        xp: 0,
        coins: 100,
        quizzesCompleted: 0,
        correctAnswers: 0,
        createdAt: new Date().toISOString(),
        appVersion: APP_VERSION
    };

    db.users.push(user);
    saveDB();

    const token = createToken(user.id);
    res.status(201).json({ success: true, token, user: sanitizeUser(user) });
});

app.post("/api/v1/auth/login", (req, res) => {
    const { email, password } = req.body;
    const normalizedEmail = String(email || "").trim().toLowerCase();
    const user = db.users.find(u => u.email === normalizedEmail);

    if (!user || user.passwordHash !== hashPassword(password || "")) {
        return res.status(401).json({ success: false, message: "Invalid email or password." });
    }

    const token = createToken(user.id);
    res.json({ success: true, token, user: sanitizeUser(user) });
});

app.get("/api/v1/auth/me", auth, (req, res) => {
    res.json({ success: true, user: sanitizeUser(req.user) });
});

/* ---------------------------------------------------------
   PROFILE
--------------------------------------------------------- */

app.put("/api/v1/profile", auth, (req, res) => {
    const allowed = ["name", "university", "country", "level"];
    allowed.forEach(field => {
        if (req.body[field] !== undefined) {
            req.user[field] = req.body[field];
        }
    });

    req.user.appVersion = APP_VERSION;
    saveDB();

    res.json({ success: true, user: sanitizeUser(req.user) });
});

/* ---------------------------------------------------------
   SUBJECTS
--------------------------------------------------------- */

app.get("/api/v1/subjects", (req, res) => {
    const subjects = [
        "Pharmacology", "Pharmacokinetics", "Pharmaceutics", "Dispensing",
        "Pharmacognosy", "Pharmaceutical Microbiology", "Pharmacy Practice",
        "Pharmaceutical Physical Chemistry", "Biochemistry", "Physiology",
        "Anatomy", "Pharmaceutical Entrepreneurship", "Clinical Pharmacy"
    ];
    res.json({ success: true, subjects });
});

/* ---------------------------------------------------------
   QUIZ & SUBMISSION
--------------------------------------------------------- */

app.get("/api/v1/quiz/questions", auth, (req, res) => {
    const { subject, limit = 10, difficulty } = req.query;
    let questions = db.questions.filter(q => q.active !== false);

    if (subject) {
        questions = questions.filter(q => q.subject.toLowerCase() === String(subject).toLowerCase());
    }
    if (difficulty) {
        questions = questions.filter(q => q.difficulty === difficulty);
    }

    questions = questions.sort(() => Math.random() - 0.5).slice(0, Math.min(Number(limit), 50));

    const safeQuestions = questions.map(q => ({
        id: q.id,
        subject: q.subject,
        question: q.question,
        options: q.options,
        difficulty: q.difficulty
    }));

    res.json({ success: true, questions: safeQuestions, contentYear: CONTENT_YEAR });
});

app.post("/api/v1/quiz/submit", auth, (req, res) => {
    const { answers, startedAt, mode = "practice" } = req.body;

    if (!Array.isArray(answers)) {
        return res.status(400).json({ success: false, message: "Answers must be an array." });
    }

    if (startedAt && (Date.now() - new Date(startedAt).getTime() < 3000)) {
        return res.status(400).json({ success: false, message: "Quiz submitted too quickly." });
    }

    let correct = 0;
    let total = answers.length;
    let xp = 0;
    const results = [];

    answers.forEach(item => {
        const question = db.questions.find(q => q.id === item.questionId);
        if (!question) return;

        const selected = Number(item.answer);
        const isCorrect = selected === question.answer;

        if (isCorrect) {
            correct++;
            xp += question.difficulty === "hard" ? 30 : question.difficulty === "medium" ? 20 : 10;
        }

        results.push({
            questionId: question.id,
            correct: isCorrect,
            correctAnswer: question.answer,
            explanation: question.explanation
        });
    });

    const score = total > 0 ? Math.round((correct / total) * 100) : 0;

    req.user.xp = (req.user.xp || 0) + xp;
    req.user.coins = (req.user.coins || 0) + Math.floor(xp / 5);
    req.user.quizzesCompleted = (req.user.quizzesCompleted || 0) + 1;
    req.user.correctAnswers = (req.user.correctAnswers || 0) + correct;

    db.scores.push({
        id: id("score_"),
        userId: req.user.id,
        userName: req.user.name,
        university: req.user.university,
        country: req.user.country,
        mode,
        score,
        correct,
        total,
        xp,
        createdAt: new Date().toISOString()
    });

    checkAchievements(req.user);
    saveDB();

    res.json({ success: true, score, correct, total, xpEarned: xp, results, user: sanitizeUser(req.user) });
});

/* ---------------------------------------------------------
   LEADERBOARD, GPA, & SUBSCRIPTIONS
--------------------------------------------------------- */

app.get("/api/v1/leaderboard", (req, res) => {
    let users = [...db.users];
    users.sort((a, b) => (b.xp || 0) - (a.xp || 0));

    const leaderboard = users.slice(0, 50).map((u, index) => ({
        rank: index + 1,
        name: u.name,
        university: u.university,
        country: u.country,
        xp: u.xp || 0,
        quizzesCompleted: u.quizzesCompleted || 0
    }));

    res.json({ success: true, leaderboard });
});

app.post("/api/v1/gpa/calculate", (req, res) => {
    const courses = req.body.courses;
    if (!Array.isArray(courses)) {
        return res.status(400).json({ success: false, message: "Courses must be an array." });
    }

    let totalUnits = 0;
    let totalPoints = 0;

    courses.forEach(c => {
        const unit = Number(c.unit);
        const gradePoint = Number(c.gradePoint);
        if (Number.isFinite(unit) && Number.isFinite(gradePoint)) {
            totalUnits += unit;
            totalPoints += unit * gradePoint;
        }
    });

    const gpa = totalUnits > 0 ? totalPoints / totalUnits : 0;
    res.json({ success: true, totalUnits, totalPoints, gpa: Number(gpa.toFixed(2)), scale: 5 });
});

app.post("/api/v1/subscriptions/create", auth, (req, res) => {
    const { plan = "premium" } = req.body;
    const subscription = {
        id: id("sub_"),
        userId: req.user.id,
        plan,
        status: "pending_payment",
        createdAt: new Date().toISOString()
    };

    db.subscriptions.push(subscription);
    saveDB();

    res.json({
        success: true,
        message: "Subscription created. Connect a payment provider to complete payment.",
        subscription
    });
});

app.get("/api/v1/subscriptions/me", auth, (req, res) => {
    const subscriptions = db.subscriptions.filter(sub => sub.userId === req.user.id);
    res.json({ success: true, subscriptions });
});

/* ---------------------------------------------------------
   ACHIEVEMENTS HELPER
--------------------------------------------------------- */

function checkAchievements(user) {
    const achievements = [];
    if ((user.quizzesCompleted || 0) >= 1) achievements.push("First Quiz");
    if ((user.correctAnswers || 0) >= 50) achievements.push("50 Correct Answers");
    if ((user.xp || 0) >= 1000) achievements.push("1000 XP");

    achievements.forEach(name => {
        const exists = db.achievements.some(a => a.userId === user.id && a.name === name);
        if (!exists) {
            db.achievements.push({
                id: id("ach_"),
                userId: user.id,
                name,
                createdAt: new Date().toISOString()
            });
        }
    });
}

app.get("/api/v1/achievements", auth, (req, res) => {
    res.json({
        success: true,
        achievements: db.achievements.filter(a => a.userId === req.user.id)
    });
});

/* ---------------------------------------------------------
   SERVER STARTUP
--------------------------------------------------------- */

app.listen(PORT, () => {
    console.log("===========================================================");
    console.log(`🚀 DENexpharm API Server Running on Port ${PORT}`);
    console.log(`📂 Database Connected: JSON Persistence (${DB_FILE})`);
    console.log("===========================================================");
});
