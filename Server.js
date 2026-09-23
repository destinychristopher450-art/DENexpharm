/*
===========================================================
 DENexpharm
 Full Stack Pharmacy Learning & Competition Platform
 Phase 1 + Phase 2 + Phase 3
 COMPLETE BACKEND
===========================================================
*/

"use strict";

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

/* =========================================================
   APP CONFIGURATION
========================================================= */

const PORT = process.env.PORT || 3000;
const APP_VERSION = process.env.APP_VERSION || "3.0.0";
const CONTENT_YEAR = process.env.CONTENT_YEAR || "2026";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");

if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}

/* =========================================================
   DATABASE
========================================================= */

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

function cloneDefaultDB() {
    return JSON.parse(JSON.stringify(DEFAULT_DB));
}

function loadDB() {
    try {
        if (!fs.existsSync(DB_FILE)) {
            const fresh = cloneDefaultDB();

            fs.writeFileSync(
                DB_FILE,
                JSON.stringify(fresh, null, 2)
            );

            return fresh;
        }

        const content = fs.readFileSync(DB_FILE, "utf8");

        if (!content.trim()) {
            return cloneDefaultDB();
        }

        const parsed = JSON.parse(content);

        return {
            ...cloneDefaultDB(),
            ...parsed
        };
    } catch (error) {
        console.error("Database loading error:", error);
        return cloneDefaultDB();
    }
}

let db = loadDB();

function saveDB() {
    try {
        const tempFile = `${DB_FILE}.tmp`;

        fs.writeFileSync(
            tempFile,
            JSON.stringify(db, null, 2),
            "utf8"
        );

        fs.renameSync(tempFile, DB_FILE);
    } catch (error) {
        console.error("Database save error:", error);
    }
}

/* =========================================================
   UTILITIES
========================================================= */

function createId(prefix = "") {
    return (
        prefix +
        crypto.randomBytes(12).toString("hex")
    );
}

function hashPassword(password) {
    return crypto
        .createHash("sha256")
        .update(String(password))
        .digest("hex");
}

function normalizeEmail(email) {
    return String(email || "")
        .trim()
        .toLowerCase();
}

function safeNumber(value, fallback = 0) {
    const number = Number(value);
    return Number.isFinite(number) ? number : fallback;
}

function todayString() {
    return new Date().toISOString().slice(0, 10);
}

/* =========================================================
   TOKEN SYSTEM
========================================================= */

function createToken(userId) {
    const payload = {
        userId,
        createdAt: Date.now()
    };

    const encoded = Buffer
        .from(JSON.stringify(payload))
        .toString("base64url");

    const secret =
        process.env.JWT_SECRET ||
        "DENEXPHARM_CHANGE_THIS_SECRET";

    const signature = crypto
        .createHmac("sha256", secret)
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

        const encoded = parts[0];
        const signature = parts[1];

        const secret =
            process.env.JWT_SECRET ||
            "DENEXPHARM_CHANGE_THIS_SECRET";

        const expected = crypto
            .createHmac("sha256", secret)
            .update(encoded)
            .digest("base64url");

        if (
            !crypto.timingSafeEqual(
                Buffer.from(signature),
                Buffer.from(expected)
            )
        ) {
            return null;
        }

        return JSON.parse(
            Buffer.from(encoded, "base64url").toString("utf8")
        );
    } catch {
        return null;
    }
}

/* =========================================================
   USER SANITIZATION
========================================================= */

function sanitizeUser(user) {
    if (!user) return null;

    return {
        id: user.id,
        name: user.name,
        email: user.email,
        university: user.university,
        country: user.country,
        level: user.level,
        role: user.role,
        xp: user.xp || 0,
        coins: user.coins || 0,
        quizzesCompleted: user.quizzesCompleted || 0,
        correctAnswers: user.correctAnswers || 0,
        battleWins: user.battleWins || 0,
        battleLosses: user.battleLosses || 0,
        referralCount: user.referralCount || 0,
        premium: user.premium === true,
        createdAt: user.createdAt,
        appVersion: user.appVersion
    };
}

/* =========================================================
   MIDDLEWARE
========================================================= */

app.use(
    cors({
        origin: process.env.CLIENT_ORIGIN || "*"
    })
);

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

app.use((req, res, next) => {
    res.setHeader(
        "X-DENexpharm-Version",
        APP_VERSION
    );

    next();
});

app.use(
    express.static(
        path.join(__dirname, "public")
    )
);

/* =========================================================
   AUTH MIDDLEWARE
========================================================= */

function auth(req, res, next) {
    const header =
        req.headers.authorization || "";

    const token =
        header.startsWith("Bearer ")
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
    if (
        !req.user ||
        req.user.role !== "admin"
    ) {
        return res.status(403).json({
            success: false,
            message: "Administrator access required."
        });
    }

    next();
}

/* =========================================================
   HEALTH / CONFIGURATION
========================================================= */

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
            authentication: true,
            quiz: true,
            pharmacology: true,
            pharmacokinetics: true,
            dispensing: true,
            pharmaceutics: true,
            pharmacognosy: true,
            pharmaceuticalMicrobiology: true,
            pharmacyPractice: true,
            clinicalPharmacy: true,
            biochemistry: true,
            physiology: true,
            anatomy: true,
            physicalChemistry: true,
            entrepreneurship: true,

            gpaCalculator: true,

            pharmacopoeiaHub: true,

            languageAssistant: true,

            leaderboard: true,

            dailyChallenge: true,

            timedBattle: true,

            referrals: true,

            subscriptions: true,

            achievements: true,

            profile: true,

            adminQuestionManagement: true
        }
    });
});

/* =========================================================
   SUBJECTS
========================================================= */

const SUBJECTS = [
    "Pharmacology",
    "Pharmacokinetics",
    "Pharmaceutics",
    "Dispensing",
    "Pharmacognosy",
    "Pharmaceutical Microbiology",
    "Pharmacy Practice",
    "Pharmaceutical Physical Chemistry",
    "Biochemistry",
    "Physiology",
    "Anatomy",
    "Pharmaceutical Entrepreneurship",
    "Clinical Pharmacy"
];

app.get("/api/v1/subjects", (req, res) => {
    res.json({
        success: true,
        subjects: SUBJECTS
    });
});

/* =========================================================
   QUESTION BANK
========================================================= */

const starterQuestions = [
    {
        id: "q001",
        subject: "Pharmacokinetics",
        question:
            "Which pharmacokinetic process describes movement of a drug from the site of administration into systemic circulation?",
        options: [
            "Absorption",
            "Distribution",
            "Metabolism",
            "Excretion"
        ],
        answer: 0,
        explanation:
            "Absorption is the movement of a drug from its site of administration into systemic circulation.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q002",
        subject: "Pharmacokinetics",
        question:
            "Which parameter describes the theoretical volume required to contain the total amount of drug at the same concentration found in plasma?",
        options: [
            "Clearance",
            "Volume of distribution",
            "Half-life",
            "Bioavailability"
        ],
        answer: 1,
        explanation:
            "Volume of distribution relates the amount of drug in the body to its plasma concentration.",
        difficulty: "medium",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q003",
        subject: "Pharmacokinetics",
        question:
            "Which pharmacokinetic parameter represents the fraction of an administered dose that reaches systemic circulation unchanged?",
        options: [
            "Bioavailability",
            "Clearance",
            "Volume of distribution",
            "Half-life"
        ],
        answer: 0,
        explanation:
            "Bioavailability is the fraction of an administered dose that reaches systemic circulation unchanged.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q004",
        subject: "Pharmacokinetics",
        question:
            "The elimination half-life of a drug is the time required for:",
        options: [
            "The drug to reach the stomach",
            "The plasma concentration to fall by 50%",
            "The drug to become completely inactive",
            "The drug to be absorbed completely"
        ],
        answer: 1,
        explanation:
            "Half-life is the time required for the concentration or amount of drug in the body to decrease by 50%.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q005",
        subject: "Dispensing",
        question:
            "Which information should be clearly included on a dispensed medicine label?",
        options: [
            "Patient directions",
            "The pharmacist's favourite colour",
            "A random identification number",
            "The weather forecast"
        ],
        answer: 0,
        explanation:
            "A dispensing label should provide appropriate directions for safe use.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q006",
        subject: "Pharmaceutics",
        question:
            "Which dosage form is designed to be swallowed and release the drug in the gastrointestinal tract?",
        options: [
            "Tablet",
            "Eye drop",
            "Ointment",
            "Transdermal patch"
        ],
        answer: 0,
        explanation:
            "Tablets are solid oral dosage forms intended for administration by mouth.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q007",
        subject: "Pharmacology",
        question:
            "Pharmacodynamics primarily describes:",
        options: [
            "What the drug does to the body",
            "What the body does to the drug",
            "How drugs are manufactured",
            "How prescriptions are printed"
        ],
        answer: 0,
        explanation:
            "Pharmacodynamics concerns drug effects and mechanisms of action.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q008",
        subject: "Pharmacognosy",
        question:
            "Pharmacognosy is primarily concerned with:",
        options: [
            "Natural medicinal substances",
            "Computer programming",
            "Hospital architecture",
            "Accounting"
        ],
        answer: 0,
        explanation:
            "Pharmacognosy deals with medicinal substances obtained from natural sources.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q009",
        subject: "Pharmaceutical Microbiology",
        question:
            "Which process is commonly used to sterilize heat-stable materials using steam under pressure?",
        options: [
            "Autoclaving",
            "Filtration only",
            "Freezing",
            "Sedimentation"
        ],
        answer: 0,
        explanation:
            "Autoclaving uses saturated steam under pressure to achieve sterilization.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q010",
        subject: "Biochemistry",
        question:
            "Which biomolecule is primarily composed of amino acids?",
        options: [
            "Protein",
            "Lipid",
            "Carbohydrate",
            "Nucleic acid"
        ],
        answer: 0,
        explanation:
            "Proteins are polymers made from amino acids.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q011",
        subject: "Physiology",
        question:
            "Which organ is primarily responsible for pumping blood through the circulatory system?",
        options: [
            "Heart",
            "Liver",
            "Kidney",
            "Lung"
        ],
        answer: 0,
        explanation:
            "The heart pumps blood through the systemic and pulmonary circulations.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q012",
        subject: "Anatomy",
        question:
            "Which structure separates the thoracic cavity from the abdominal cavity?",
        options: [
            "Diaphragm",
            "Sternum",
            "Femur",
            "Scapula"
        ],
        answer: 0,
        explanation:
            "The diaphragm forms the muscular partition between the thorax and abdomen.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q013",
        subject: "Pharmacy Practice",
        question:
            "Patient counselling is primarily intended to:",
        options: [
            "Promote safe and effective medicine use",
            "Increase prescription length",
            "Replace every medical consultation",
            "Remove the need for medication labels"
        ],
        answer: 0,
        explanation:
            "Patient counselling helps patients understand and safely use their medicines.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q014",
        subject: "Clinical Pharmacy",
        question:
            "A medication history is useful for identifying:",
        options: [
            "Current and previous medication use",
            "The patient's favourite sport only",
            "The patient's internet speed",
            "The hospital building design"
        ],
        answer: 0,
        explanation:
            "Medication histories help identify current and previous medicines and relevant medication-related issues.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q015",
        subject: "Pharmaceutical Physical Chemistry",
        question:
            "A solution with pH below 7 at 25°C is generally described as:",
        options: [
            "Acidic",
            "Neutral",
            "Alkaline",
            "Non-aqueous"
        ],
        answer: 0,
        explanation:
            "At approximately 25°C, a pH below 7 indicates an acidic solution.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    },

    {
        id: "q016",
        subject: "Pharmaceutical Entrepreneurship",
        question:
            "A business plan is primarily used to:",
        options: [
            "Describe a business idea, strategy and operations",
            "Replace all financial records",
            "Eliminate customer research",
            "Prevent business innovation"
        ],
        answer: 0,
        explanation:
            "A business plan describes the business idea, market, strategy, operations and financial considerations.",
        difficulty: "easy",
        year: CONTENT_YEAR,
        active: true
    }
];

if (!Array.isArray(db.questions)) {
    db.questions = [];
}

if (db.questions.length === 0) {
    db.questions = starterQuestions;
    saveDB();
}

/* =========================================================
   AUTHENTICATION
========================================================= */

app.post("/api/v1/auth/register", (req, res) => {
    const {
        name,
        email,
        password,
        university = "",
        country = "",
        level = "",
        referralCode = ""
    } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message:
                "Name, email and password are required."
        });
    }

    if (String(password).length < 6) {
        return res.status(400).json({
            success: false,
            message:
                "Password must contain at least 6 characters."
        });
    }

    const normalizedEmail =
        normalizeEmail(email);

    const existing = db.users.find(
        u => u.email === normalizedEmail
    );

    if (existing) {
        return res.status(409).json({
            success: false,
            message:
                "An account with this email already exists."
        });
    }

    const user = {
        id: createId("usr_"),
        name: String(name).trim(),
        email: normalizedEmail,
        passwordHash: hashPassword(password),

        university: String(university || ""),
        country: String(country || ""),
        level: String(level || ""),

        role: "student",

        xp: 0,
        coins: 100,

        quizzesCompleted: 0,
        correctAnswers: 0,

        battleWins: 0,
        battleLosses: 0,

        referralCount: 0,

        premium: false,

        referralCode:
            "DEN" +
            crypto
                .randomBytes(4)
                .toString("hex")
                .toUpperCase(),

        createdAt:
            new Date().toISOString(),

        appVersion: APP_VERSION
    };

    db.users.push(user);

    /*
       Referral reward
    */

    if (referralCode) {
        const referrer = db.users.find(
            u =>
                u.referralCode ===
                String(referralCode).trim()
        );

        if (referrer && referrer.id !== user.id) {
            referrer.referralCount =
                (referrer.referralCount || 0) + 1;

            referrer.coins =
                (referrer.coins || 0) + 50;

            user.coins += 25;

            db.referrals.push({
                id: createId("ref_"),
                referrerId: referrer.id,
                referredUserId: user.id,
                reward: 50,
                createdAt:
                    new Date().toISOString()
            });
        }
    }

    saveDB();

    const token = createToken(user.id);

    res.status(201).json({
        success: true,
        token,
        user: sanitizeUser(user)
    });
});

app.post("/api/v1/auth/login", (req, res) => {
    const {
        email,
        password
    } = req.body;

    const normalizedEmail =
        normalizeEmail(email);

    const user = db.users.find(
        u => u.email === normalizedEmail
    );

    if (
        !user ||
        user.passwordHash !==
            hashPassword(password || "")
    ) {
        return res.status(401).json({
            success: false,
            message:
                "Invalid email or password."
        });
    }

    user.appVersion = APP_VERSION;

    saveDB();

    const token =
        createToken(user.id);

    res.json({
        success: true,
        token,
        user: sanitizeUser(user)
    });
});

app.get(
    "/api/v1/auth/me",
    auth,
    (req, res) => {
        res.json({
            success: true,
            user: sanitizeUser(req.user)
        });
    }
);

/* =========================================================
   PROFILE
========================================================= */

app.get(
    "/api/v1/profile",
    auth,
    (req, res) => {
        res.json({
            success: true,
            user: sanitizeUser(req.user)
        });
    }
);

app.put(
    "/api/v1/profile",
    auth,
    (req, res) => {
        const allowed = [
            "name",
            "university",
            "country",
            "level"
        ];

        allowed.forEach(field => {
            if (
                req.body[field] !==
                undefined
            ) {
                req.user[field] =
                    String(req.body[field]);
            }
        });

        req.user.appVersion =
            APP_VERSION;

        saveDB();

        res.json({
            success: true,
            user: sanitizeUser(req.user)
        });
    }
);

/* =========================================================
   QUIZ QUESTIONS
========================================================= */

app.get(
    "/api/v1/quiz/questions",
    auth,
    (req, res) => {
        const {
            subject,
            difficulty,
            limit = 10
        } = req.query;

        let questions =
            db.questions.filter(
                q => q.active !== false
            );

        if (subject) {
            questions =
                questions.filter(
                    q =>
                        q.subject.toLowerCase() ===
                        String(subject).toLowerCase()
                );
        }

        if (difficulty) {
            questions =
                questions.filter(
                    q =>
                        q.difficulty ===
                        difficulty
                );
        }

        questions =
            questions
                .sort(
                    () =>
                        Math.random() - 0.5
                )
                .slice(
                    0,
                    Math.min(
                        safeNumber(limit, 10),
                        50
                    )
                );

        const safeQuestions =
            questions.map(q => ({
                id: q.id,
                subject: q.subject,
                question: q.question,
                options: q.options,
                difficulty:
                    q.difficulty
            }));

        res.json({
            success: true,
            questions: safeQuestions,
            contentYear:
                CONTENT_YEAR
        });
    }
);

/* =========================================================
   QUIZ SUBMISSION
========================================================= */

app.post(
    "/api/v1/quiz/submit",
    auth,
    (req, res) => {
        const {
            answers,
            startedAt,
            mode = "practice"
        } = req.body;

        if (!Array.isArray(answers)) {
            return res.status(400).json({
                success: false,
                message:
                    "Answers must be an array."
            });
        }

        if (
            startedAt &&
            Date.now() -
                new Date(startedAt).getTime() <
                3000
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Quiz submitted too quickly."
            });
        }

        let correct = 0;
        let total = 0;
        let xp = 0;

        const results = [];

        answers.forEach(item => {
            const question =
                db.questions.find(
                    q =>
                        q.id ===
                        item.questionId
                );

            if (!question) {
                return;
            }

            total++;

            const selected =
                Number(item.answer);

            const isCorrect =
                selected ===
                question.answer;

            if (isCorrect) {
                correct++;

                if (
                    question.difficulty ===
                    "hard"
                ) {
                    xp += 30;
                } else if (
                    question.difficulty ===
                    "medium"
                ) {
                    xp += 20;
                } else {
                    xp += 10;
                }
            }

            results.push({
                questionId:
                    question.id,
                correct:
                    isCorrect,
                correctAnswer:
                    question.answer,
                explanation:
                    question.explanation
            });
        });

        const score =
            total > 0
                ? Math.round(
                      (correct / total) *
                          100
                  )
                : 0;

        req.user.xp =
            (req.user.xp || 0) +
            xp;

        req.user.coins =
            (req.user.coins || 0) +
            Math.floor(xp / 5);

        req.user.quizzesCompleted =
            (req.user.quizzesCompleted || 0) +
            1;

        req.user.correctAnswers =
            (req.user.correctAnswers || 0) +
            correct;

        db.scores.push({
            id: createId("score_"),

            userId:
                req.user.id,

            userName:
                req.user.name,

            university:
                req.user.university,

            country:
                req.user.country,

            mode,

            score,

            correct,

            total,

            xp,

            createdAt:
                new Date().toISOString()
        });

        checkAchievements(req.user);

        saveDB();

        res.json({
            success: true,
            score,
            correct,
            total,
            xpEarned: xp,
            results,
            user:
                sanitizeUser(
                    req.user
                )
        });
    }
);

/* =========================================================
   USER SCORE HISTORY
========================================================= */

app.get(
    "/api/v1/scores/me",
    auth,
    (req, res) => {
        const scores =
            db.scores
                .filter(
                    s =>
                        s.userId ===
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
                )
                .slice(0, 100);

        res.json({
            success: true,
            scores
        });
    }
);

/* =========================================================
   LEADERBOARD
========================================================= */

app.get(
    "/api/v1/leaderboard",
    (req, res) => {
        const users =
            [...db.users]
                .sort(
                    (a, b) =>
                        (b.xp || 0) -
                        (a.xp || 0)
                )
                .slice(0, 100);

        const leaderboard =
            users.map(
                (user, index) => ({
                    rank:
                        index + 1,
                    name:
                        user.name,
                    university:
                        user.university,
                    country:
                        user.country,
                    xp:
                        user.xp || 0,
                    quizzesCompleted:
                        user.quizzesCompleted ||
                        0
                })
            );

        res.json({
            success: true,
            leaderboard
        });
    }
);

/* =========================================================
   GPA CALCULATOR
========================================================= */

app.post(
    "/api/v1/gpa/calculate",
    (req, res) => {
        const courses =
            req.body.courses;

        if (!Array.isArray(courses)) {
            return res.status(400).json({
                success: false,
                message:
                    "Courses must be an array."
            });
        }

        let totalUnits = 0;
        let totalPoints = 0;

        courses.forEach(course => {
            const unit =
                Number(course.unit);

            const gradePoint =
                Number(
                    course.gradePoint
                );

            if (
                Number.isFinite(unit) &&
                Number.isFinite(
                    gradePoint
                ) &&
                unit > 0
            ) {
                totalUnits += unit;

                totalPoints +=
                    unit *
                    gradePoint;
            }
        });

        const gpa =
            totalUnits > 0
                ? totalPoints /
                  totalUnits
                : 0;

        res.json({
            success: true,
            totalUnits,
            totalPoints,
            gpa: Number(
                gpa.toFixed(2)
            ),
            scale: 5
        });
    }
);

/* =========================================================
   PHARMACOPOEIA HUB
========================================================= */

const pharmacopoeia = [
    {
        code: "BP",
        name: "British Pharmacopoeia",
        region:
            "United Kingdom",
        description:
            "Official pharmacopoeial reference framework containing standards for medicines and pharmaceutical substances."
    },

    {
        code: "USP",
        name:
            "United States Pharmacopeia",
        region:
            "United States",
        description:
            "Major pharmacopoeial standards framework for medicines, substances and quality requirements."
    },

    {
        code: "Ph. Eur.",
        name:
            "European Pharmacopoeia",
        region:
            "Europe",
        description:
            "European pharmacopoeial standards framework for quality of medicines and pharmaceutical substances."
    },

    {
        code: "WHO",
        name:
            "WHO International Pharmacopoeia",
        region:
            "International",
        description:
            "International reference framework supporting quality standards for pharmaceutical substances and dosage forms."
    }
];

app.get(
    "/api/v1/pharmacopoeia",
    (req, res) => {
        res.json({
            success: true,
            notice:
                "DENexpharm provides educational summaries and navigation concepts. It does not reproduce copyrighted monographs.",
            sources:
                pharmacopoeia
        });
    }
);

app.get(
    "/api/v1/pharmacopoeia/:code",
    (req, res) => {
        const item =
            pharmacopoeia.find(
                p =>
                    p.code.toLowerCase() ===
                    String(
                        req.params.code
                    ).toLowerCase()
            );

        if (!item) {
            return res.status(404).json({
                success: false,
                message:
                    "Pharmacopoeia reference not found."
            });
        }

        res.json({
            success: true,
            item
        });
    }
);

/* =========================================================
   PHARMACY LANGUAGE ASSISTANT
========================================================= */

const languageData = {
    English: {
        greeting:
            "Hello, how can I help you today?",
        medicine:
            "Please take your medicine exactly as directed.",
        adherence:
            "Have you been taking your medicine regularly?"
    },

    French: {
        greeting:
            "Bonjour, comment puis-je vous aider aujourd'hui ?",
        medicine:
            "Veuillez prendre votre médicament exactement comme indiqué.",
        adherence:
            "Prenez-vous régulièrement votre médicament ?"
    },

    Spanish: {
        greeting:
            "Hola, ¿cómo puedo ayudarle hoy?",
        medicine:
            "Tome su medicamento exactamente como se le indicó.",
        adherence:
            "¿Ha estado tomando su medicamento regularmente?"
    },

    Portuguese: {
        greeting:
            "Olá, como posso ajudá-lo hoje?",
        medicine:
            "Tome o seu medicamento exatamente conforme indicado.",
        adherence:
            "Tem tomado o seu medicamento regularmente?"
    },

    German: {
        greeting:
            "Hallo, wie kann ich Ihnen heute helfen?",
        medicine:
            "Bitte nehmen Sie Ihr Arzneimittel genau nach Anweisung ein.",
        adherence:
            "Nehmen Sie Ihr Arzneimittel regelmäßig ein?"
    },

    Arabic: {
        greeting:
            "مرحباً، كيف يمكنني مساعدتك اليوم؟",
        medicine:
            "يرجى تناول دوائك حسب التعليمات.",
        adherence:
            "هل تتناول دواءك بانتظام؟"
    },

    Hausa: {
        greeting:
            "Sannu, ta yaya zan iya taimaka maka yau?",
        medicine:
            "Da fatan za ka sha maganinka kamar yadda aka umurta.",
        adherence:
            "Kana shan maganinka akai-akai?"
    },

    Yoruba: {
        greeting:
            "Bawo, bawo ni mo ṣe le ran ọ lọwọ loni?",
        medicine:
            "Jọwọ mu oogun rẹ gẹgẹ bi a ti paṣẹ.",
        adherence:
            "Ṣe o n mu oogun rẹ nigbagbogbo?"
    },

    Igbo: {
        greeting:
            "Ndewo, kedu ka m ga-esi nyere gị aka taa?",
        medicine:
            "Biko were ọgwụ gị dịka e nyere gị iwu.",
        adherence:
            "Ị na-aṅụ ọgwụ gị mgbe niile?"
    }
};

app.get(
    "/api/v1/language",
    (req, res) => {
        res.json({
            success: true,
            languages:
                Object.keys(
                    languageData
                ),
            data:
                languageData
        });
    }
);

app.post(
    "/api/v1/language/phrase",
    (req, res) => {
        const {
            language,
            phrase
        } = req.body;

        const selected =
            languageData[language];

        if (!selected) {
            return res.status(404).json({
                success: false,
                message:
                    "Language not currently available."
            });
        }

        const result =
            selected[
                phrase || "greeting"
            ];

        res.json({
            success: true,
            language,
            phrase:
                phrase || "greeting",
            result:
                result || null
        });
    }
);

/* =========================================================
   DAILY CHALLENGE
========================================================= */

function getDailyChallenge() {
    const today =
        todayString();

    let challenge =
        db.dailyChallenges.find(
            c => c.date === today
        );

    if (challenge) {
        return challenge;
    }

    const activeQuestions =
        db.questions.filter(
            q => q.active !== false
        );

    if (
        activeQuestions.length === 0
    ) {
        return null;
    }

    const question =
        activeQuestions[
            Math.floor(
                Math.random() *
                    activeQuestions.length
            )
        ];

    challenge = {
        id:
            createId("daily_"),
        date: today,
        questionId:
            question.id,
        rewardXP: 50,
        rewardCoins: 10
    };

    db.dailyChallenges.push(
        challenge
    );

    saveDB();

    return challenge;
}

app.get(
    "/api/v1/daily-challenge",
    auth,
    (req, res) => {
        const challenge =
            getDailyChallenge();

        if (!challenge) {
            return res.status(404).json({
                success: false,
                message:
                    "No daily challenge available."
            });
        }

        const question =
            db.questions.find(
                q =>
                    q.id ===
                    challenge.questionId
            );

        res.json({
            success: true,

            challenge: {
                id:
                    challenge.id,
                date:
                    challenge.date,
                rewardXP:
                    challenge.rewardXP,
                rewardCoins:
                    challenge.rewardCoins,

                question: {
                    id:
                        question.id,
                    subject:
                        question.subject,
                    question:
                        question.question,
                    options:
                        question.options
                }
            }
        });
    }
);

app.post(
    "/api/v1/daily-challenge/submit",
    auth,
    (req, res) => {
        const {
            challengeId,
            answer
        } = req.body;

        const challenge =
            db.dailyChallenges.find(
                c =>
                    c.id ===
                    challengeId
            );

        if (!challenge) {
            return res.status(404).json({
                success: false,
                message:
                    "Challenge not found."
            });
        }

        const question =
            db.questions.find(
                q =>
                    q.id ===
                    challenge.questionId
            );

        if (!question) {
            return res.status(404).json({
                success: false,
                message:
                    "Challenge question not found."
            });
        }

        const already =
            db.scores.some(
                score =>
                    score.userId ===
                        req.user.id &&
                    score.mode ===
                        "daily" &&
                    score.challengeId ===
                        challenge.id
            );

        if (already) {
            return res.status(409).json({
                success: false,
                message:
                    "You have already completed today's challenge."
            });
        }

        const correct =
            Number(answer) ===
            question.answer;

        let rewardXP = 0;
        let rewardCoins = 0;

        if (correct) {
            rewardXP =
                challenge.rewardXP;

            rewardCoins =
                challenge.rewardCoins;

            req.user.xp +=
                rewardXP;

            req.user.coins +=
                rewardCoins;
        }

        db.scores.push({
            id:
                createId("score_"),
            userId:
                req.user.id,
            userName:
                req.user.name,
            university:
                req.user.university,
            country:
                req.user.country,
            mode:
                "daily",
            challengeId:
                challenge.id,
            score:
                correct ? 100 : 0,
            correct:
                correct ? 1 : 0,
            total: 1,
            xp:
                rewardXP,
            createdAt:
                new Date().toISOString()
        });

        checkAchievements(
            req.user
        );

        saveDB();

        res.json({
            success: true,
            correct,
            rewardXP,
            rewardCoins,
            user:
                sanitizeUser(
                    req.user
                )
        });
    }
);

/* =========================================================
   TIMED BATTLE
========================================================= */

app.post(
    "/api/v1/battle/create",
    auth,
    (req, res) => {
        const {
            questionCount = 10
        } = req.body;

        const count =
            Math.min(
                Math.max(
                    safeNumber(
                        questionCount,
                        10
                    ),
                    1
                ),
                30
            );

        const questions =
            db.questions
                .filter(
                    q =>
                        q.active !== false
                )
                .sort(
                    () =>
                        Math.random() -
                        0.5
                )
                .slice(0, count)
                .map(q => ({
                    id: q.id,
                    subject:
                        q.subject,
                    question:
                        q.question,
                    options:
                        q.options
                }));

        const battle = {
            id:
                createId("battle_"),

            creatorId:
                req.user.id,

            opponentId:
                null,

            status:
                "waiting",

            questionCount:
                questions.length,

            questions,

            createdAt:
                new Date().toISOString()
        };

        db.battles.push(
            battle
        );

        saveDB();

        res.status(201).json({
            success: true,
            battle
        });
    }
);

app.post(
    "/api/v1/battle/:battleId/join",
    auth,
    (req, res) => {
        const battle =
            db.battles.find(
                b =>
                    b.id ===
                    req.params.battleId
            );

        if (!battle) {
            return res.status(404).json({
                success: false,
                message:
                    "Battle not found."
            });
        }

        if (
            battle.creatorId ===
            req.user.id
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "You cannot join your own battle."
            });
        }

        if (
            battle.opponentId
        ) {
            return res.status(409).json({
                success: false,
                message:
                    "Battle already has an opponent."
            });
        }

        battle.opponentId =
            req.user.id;

        battle.status =
            "active";

        battle.startedAt =
            new Date().toISOString();

        saveDB();

        res.json({
            success: true,
            battle
        });
    }
);

app.get(
    "/api/v1/battle/:battleId",
    auth,
    (req, res) => {
        const battle =
            db.battles.find(
                b =>
                    b.id ===
                    req.params.battleId
            );

        if (!battle) {
            return res.status(404).json({
                success: false,
                message:
                    "Battle not found."
            });
        }

        res.json({
            success: true,
            battle
        });
    }
);

app.post(
    "/api/v1/battle/:battleId/submit",
    auth,
    (req, res) => {
        const {
            answers
        } = req.body;

        const battle =
            db.battles.find(
                b =>
                    b.id ===
                    req.params.battleId
            );

        if (!battle) {
            return res.status(404).json({
                success: false,
                message:
                    "Battle not found."
            });
        }

        if (
            battle.creatorId !==
                req.user.id &&
            battle.opponentId !==
                req.user.id
        ) {
            return res.status(403).json({
                success: false,
                message:
                    "You are not part of this battle."
            });
        }

        if (!Array.isArray(answers)) {
            return res.status(400).json({
                success: false,
                message:
                    "Answers must be an array."
            });
        }

        let correct = 0;

        answers.forEach(item => {
            const question =
                db.questions.find(
                    q =>
                        q.id ===
                        item.questionId
                );

            if (
                question &&
                Number(
                    item.answer
                ) ===
                    question.answer
            ) {
                correct++;
            }
        });

        const percentage =
            battle.questionCount > 0
                ? Math.round(
                      (correct /
                          battle.questionCount) *
                          100
                  )
                : 0;

        if (!battle.results) {
            battle.results = [];
        }

        battle.results.push({
            userId:
                req.user.id,
            correct,
            total:
                battle.questionCount,
            percentage,
            submittedAt:
                new Date().toISOString()
        });

        if (
            battle.results.length >=
            2
        ) {
            battle.status =
                "completed";

            const first =
                battle.results[0];

            const second =
                battle.results[1];

            if (
                first.percentage >
                second.percentage
            ) {
                awardBattleWin(first.userId);
                awardBattleLoss(second.userId);
            } else if (
                second.percentage >
                first.percentage
            ) {
                awardBattleWin(second.userId);
                awardBattleLoss(first.userId);
            }
        }

        saveDB();

        res.json({
            success: true,
            correct,
            total:
                battle.questionCount,
            percentage,
            battle
        });
    }
);

function awardBattleWin(userId) {
    const user =
        db.users.find(
            u => u.id === userId
        );

    if (!user) return;

    user.battleWins =
        (user.battleWins || 0) +
        1;

    user.xp =
        (user.xp || 0) +
        100;

    user.coins =
        (user.coins || 0) +
        20;

    checkAchievements(user);
}

function awardBattleLoss(userId) {
    const user =
        db.users.find(
            u => u.id === userId
        );

    if (!user) return;

    user.battleLosses =
        (user.battleLosses || 0) +
        1;

    user.xp =
        (user.xp || 0) +
        20;
}

/* =========================================================
   REFERRALS
========================================================= */

app.get(
    "/api/v1/referrals/me",
    auth,
    (req, res) => {
        const referrals =
            db.referrals.filter(
                r =>
                    r.referrerId ===
                    req.user.id
            );

        res.json({
            success: true,

            referralCode:
                req.user.referralCode,

            referralCount:
                req.user.referralCount ||
                0,

            referrals
        });
    }
);

/* =========================================================
   ACHIEVEMENTS
========================================================= */

function checkAchievements(user) {
    const achievements = [];

    if (
        (user.quizzesCompleted || 0) >=
        1
    ) {
        achievements.push(
            "First Quiz"
        );
    }

    if (
        (user.correctAnswers || 0) >=
        50
    ) {
        achievements.push(
            "50 Correct Answers"
        );
    }

    if (
        (user.xp || 0) >=
        1000
    ) {
        achievements.push(
            "1000 XP"
        );
    }

    if (
        (user.battleWins || 0) >=
        1
    ) {
        achievements.push(
            "First Battle Win"
        );
    }

    if (
        (user.battleWins || 0) >=
        10
    ) {
        achievements.push(
            "10 Battle Wins"
        );
    }

    achievements.forEach(name => {
        const exists =
            db.achievements.some(
                achievement =>
                    achievement.userId ===
                        user.id &&
                    achievement.name ===
                        name
            );

        if (!exists) {
            db.achievements.push({
                id:
                    createId("ach_"),
                userId:
                    user.id,
                name,
                createdAt:
                    new Date().toISOString()
            });
        }
    });
}

app.get(
    "/api/v1/achievements",
    auth,
    (req, res) => {
        const achievements =
            db.achievements.filter(
                a =>
                    a.userId ===
                    req.user.id
            );

        res.json({
            success: true,
            achievements
        });
    }
);

/* =========================================================
   SUBSCRIPTIONS
========================================================= */

app.post(
    "/api/v1/subscriptions/create",
    auth,
    (req, res) => {
        const {
            plan = "premium"
        } = req.body;

        const subscription = {
            id:
                createId("sub_"),

            userId:
                req.user.id,

            plan,

            status:
                "pending_payment",

            createdAt:
                new Date().toISOString()
        };

        db.subscriptions.push(
            subscription
        );

        saveDB();

        res.json({
            success: true,

            message:
                "Subscription created. A payment provider must be connected before real payments can be processed.",

            subscription
        });
    }
);

app.get(
    "/api/v1/subscriptions/me",
    auth,
    (req, res) => {
        const subscriptions =
            db.subscriptions.filter(
                s =>
                    s.userId ===
                    req.user.id
            );

        res.json({
            success: true,
            subscriptions
        });
    }
);

/* =========================================================
   COINS / XP
========================================================= */

app.get(
    "/api/v1/wallet",
    auth,
    (req, res) => {
        res.json({
            success: true,

            xp:
                req.user.xp || 0,

            coins:
                req.user.coins || 0
        });
    }
);

/* =========================================================
   ADMIN QUESTION MANAGEMENT
========================================================= */

app.post(
    "/api/v1/admin/questions",
    auth,
    adminOnly,
    (req, res) => {
        const {
            subject,
            question,
            options,
            answer,
            explanation = "",
            difficulty = "easy"
        } = req.body;

        if (
            !subject ||
            !question ||
            !Array.isArray(options) ||
            options.length < 2 ||
            answer === undefined
        ) {
            return res.status(400).json({
                success: false,
                message:
                    "Invalid question data."
            });
        }

        const newQuestion = {
            id:
                createId("q_"),

            subject,

            question,

            options,

            answer:
                Number(answer),

            explanation,

            difficulty,

            year:
                CONTENT_YEAR,

            active: true,

            createdAt:
                new Date().toISOString()
        };

        db.questions.push(
            newQuestion
        );

        saveDB();

        res.status(201).json({
            success: true,
            question:
                newQuestion
        });
    }
);

app.get(
    "/api/v1/admin/questions",
    auth,
    adminOnly,
    (req, res) => {
        res.json({
            success: true,
            questions:
                db.questions
        });
    }
);

app.put(
    "/api/v1/admin/questions/:id",
    auth,
    adminOnly,
    (req, res) => {
        const question =
            db.questions.find(
                q =>
                    q.id ===
                    req.params.id
            );

        if (!question) {
            return res.status(404).json({
                success: false,
                message:
                    "Question not found."
            });
        }

        const fields = [
            "subject",
            "question",
            "options",
            "answer",
            "explanation",
            "difficulty",
            "active"
        ];

        fields.forEach(field => {
            if (
                req.body[field] !==
                undefined
            ) {
                question[field] =
                    req.body[field];
            }
        });

        saveDB();

        res.json({
            success: true,
            question
        });
    }
);

app.delete(
    "/api/v1/admin/questions/:id",
    auth,
    adminOnly,
    (req, res) => {
        const index =
            db.questions.findIndex(
                q =>
                    q.id ===
                    req.params.id
            );

        if (index === -1) {
            return res.status(404).json({
                success: false,
                message:
                    "Question not found."
            });
        }

        db.questions.splice(
            index,
            1
        );

        saveDB();

        res.json({
            success: true,
            message:
                "Question removed."
        });
    }
);

/* =========================================================
   ADMIN STATISTICS
========================================================= */

app.get(
    "/api/v1/admin/stats",
    auth,
    adminOnly,
    (req, res) => {
        res.json({
            success: true,

            statistics: {
                users:
                    db.users.length,

                questions:
                    db.questions.length,

                scores:
                    db.scores.length,

                battles:
                    db.battles.length,

                referrals:
                    db.referrals.length,

                subscriptions:
                    db.subscriptions.length,

                achievements:
                    db.achievements.length
            }
        });
    }
);

/* =========================================================
   API 404 HANDLER
========================================================= */

app.use(
    "/api",
    (req, res) => {
        res.status(404).json({
            success: false,
            message:
                "DENexpharm API endpoint not found.",
            path: req.originalUrl
        });
    }
);

/* =========================================================
   FRONTEND FALLBACK
========================================================= */

app.get(
    "*",
    (req, res, next) => {
        if (
            req.path.startsWith(
                "/api/"
            )
        ) {
            return next();
        }

        const indexPath =
            path.join(
                __dirname,
                "public",
                "index.html"
            );

        if (
            fs.existsSync(indexPath)
        ) {
            return res.sendFile(
                indexPath
            );
        }

        res.status(200).send(`
            <!DOCTYPE html>
            <html>
            <head>
                <title>DENexpharm</title>
                <meta charset="UTF-8">
                <meta name="viewport"
                    content="width=device-width, initial-scale=1.0">
            </head>
            <body>
                <h1>DENexpharm</h1>
                <p>Backend is running successfully.</p>
                <p>Version: ${APP_VERSION}</p>
                <p>Content Year: ${CONTENT_YEAR}</p>
            </body>
            </html>
        `);
    }
);

/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {
        console.error(
            "Server error:",
            error
        );

        res.status(500).json({
            success: false,
            message:
                "Internal server error."
        });
    }
);

/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {
        console.log(
            "==========================================================="
        );

        console.log(
            "🚀 DENexpharm Server Started"
        );

        console.log(
            `📡 Port: ${PORT}`
        );

        console.log(
            `📦 Version: ${APP_VERSION}`
        );

        console.log(
            `📚 Content Year: ${CONTENT_YEAR}`
        );

        console.log(
            `💾 Database: ${DB_FILE}`
        );

        console.log(
            "🧪 Quiz System: ACTIVE"
        );

        console.log(
            "⚔️ Timed Battle: ACTIVE"
        );

        console.log(
            "🏆 Leaderboard: ACTIVE"
        );

        console.log(
            "📅 Daily Challenge: ACTIVE"
        );

        console.log(
            "📖 Pharmacopoeia Hub: ACTIVE"
        );

        console.log(
            "🌍 Language Assistant: ACTIVE"
        );

        console.log(
            "🎓 GPA Calculator: ACTIVE"
        );

        console.log(
            "🎁 Referral System: ACTIVE"
        );

        console.log(
            "💎 Subscription Framework: ACTIVE"
        );

        console.log(
            "🏅 Achievement System: ACTIVE"
        );

        console.log(
            "==========================================================="
        );
    }
);
