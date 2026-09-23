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
 Express: 4.x

 MVP FEATURES
 -----------------------------------------------------------
 Authentication
 Student profiles
 International curriculum support
 Pharmacy subjects
 Question bank
 Detailed explanations
 Quiz system
 Quick battle
 Timed battle architecture
 Daily challenge
 XP / Coins / Streaks
 Achievements
 Leaderboards
 GPA calculator
 Saved GPA records
 Mini library
 Pharmacopoeia Hub
 Pharmacy Language Assistant
 Bookmarks
 Analytics
 Weak-topic detection
 Referral system
 Wallet
 Premium subscriptions
 Payment architecture
 Payment verification hooks
 Feedback
 Search
 Admin question management
 Admin user management
 Audit logs
 Public statistics
 Persistent JSON database
 Security middleware
 Rate limiting
 Static frontend
 Health endpoint
 Version endpoint
============================================================
*/

const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const APP_NAME = "DENexpharm";
const APP_VERSION = "3.0.0";
const CONTENT_YEAR = "2026";

const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PRODUCTION = NODE_ENV === "production";

const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "*";
const SESSION_SECRET =
    process.env.SESSION_SECRET ||
    "CHANGE_THIS_SESSION_SECRET_IN_PRODUCTION";

const DATA_DIR = path.join(__dirname, "data");
const DB_FILE = path.join(DATA_DIR, "database.json");
const PUBLIC_DIR = path.join(__dirname, "public");

const SESSION_DAYS = 30;
const MAX_PAGE_SIZE = 100;

/*
============================================================
 DATABASE
============================================================
*/

const DEFAULT_DATABASE = {
    meta: {
        app: APP_NAME,
        version: APP_VERSION,
        contentYear: CONTENT_YEAR,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
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

function ensureDatabase() {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    if (!fs.existsSync(DB_FILE)) {
        writeDatabase(DEFAULT_DATABASE);
    }
}

function normalizeDatabase(db) {
    const result = {
        ...DEFAULT_DATABASE,
        ...(db || {})
    };

    for (const key of Object.keys(DEFAULT_DATABASE)) {
        if (!Array.isArray(DEFAULT_DATABASE[key])) {
            continue;
        }

        if (!Array.isArray(result[key])) {
            result[key] = [];
        }
    }

    if (!result.meta || typeof result.meta !== "object") {
        result.meta = {};
    }

    result.meta.app = APP_NAME;
    result.meta.version = APP_VERSION;
    result.meta.contentYear = CONTENT_YEAR;
    result.meta.updatedAt = new Date().toISOString();

    return result;
}

function readDatabase() {
    ensureDatabase();

    try {
        const raw = fs.readFileSync(DB_FILE, "utf8");
        return normalizeDatabase(JSON.parse(raw));
    } catch (error) {
        console.error("Database read error:", error.message);

        /*
         * Do not destroy an existing database automatically.
         * A corrupt database should be investigated rather than
         * silently replaced.
         */
        throw new Error("Database could not be read.");
    }
}

function writeDatabase(db) {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const normalized = normalizeDatabase(db);
    normalized.meta.updatedAt = new Date().toISOString();

    const temporaryFile =
        DB_FILE + "." + crypto.randomBytes(8).toString("hex") + ".tmp";

    fs.writeFileSync(
        temporaryFile,
        JSON.stringify(normalized, null, 2),
        "utf8"
    );

    fs.renameSync(temporaryFile, DB_FILE);
}

function updateDatabase(mutator) {
    const db = readDatabase();
    const result = mutator(db);
    writeDatabase(db);
    return result;
}

ensureDatabase();

/*
============================================================
 SECURITY / HELPERS
============================================================
*/

function sendSuccess(res, data = {}, status = 200) {
    return res.status(status).json({
        success: true,
        data
    });
}

function sendError(res, error, message, status = 400) {
    return res.status(status).json({
        success: false,
        error,
        message
    });
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

function generateSecureToken(bytes = 32) {
    return crypto.randomBytes(bytes).toString("hex");
}

function hashPassword(password, salt = null) {
    const actualSalt = salt || crypto.randomBytes(16).toString("hex");

    const hash = crypto.pbkdf2Sync(
        password,
        actualSalt,
        210000,
        64,
        "sha512"
    );

    return {
        salt: actualSalt,
        hash: hash.toString("hex")
    };
}

function verifyPassword(password, storedHash, salt) {
    const result = hashPassword(password, salt);

    return crypto.timingSafeEqual(
        Buffer.from(result.hash, "hex"),
        Buffer.from(storedHash, "hex")
    );
}

function sanitizeUser(user) {
    if (!user) return null;

    const {
        passwordHash,
        passwordSalt,
        ...safeUser
    } = user;

    return safeUser;
}

function validatePassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 8 &&
        password.length <= 200
    );
}

function validateEmail(email) {
    return (
        typeof email === "string" &&
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    );
}

function normalizeEmail(email) {
    return String(email || "").trim().toLowerCase();
}

function safeText(value, max = 1000) {
    if (value === undefined || value === null) {
        return "";
    }

    return String(value).trim().slice(0, max);
}

function parsePage(req) {
    const page = Math.max(1, Number(req.query.page) || 1);

    const requestedLimit =
        Number(req.query.limit) || 20;

    const limit = Math.min(
        MAX_PAGE_SIZE,
        Math.max(1, requestedLimit)
    );

    return {
        page,
        limit,
        offset: (page - 1) * limit
    };
}

function paginate(items, page, limit) {
    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / limit));

    return {
        items: items.slice(
            (page - 1) * limit,
            page * limit
        ),
        pagination: {
            page,
            limit,
            total,
            totalPages
        }
    };
}

function addDays(date, days) {
    const d = new Date(date);
    d.setDate(d.getDate() + days);
    return d;
}

function todayKey() {
    return new Date().toISOString().slice(0, 10);
}

function isExpired(date) {
    if (!date) return true;
    return new Date(date).getTime() <= Date.now();
}

function secureCompare(a, b) {
    const aa = Buffer.from(String(a || ""));
    const bb = Buffer.from(String(b || ""));

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(aa, bb);
}

/*
============================================================
 RATE LIMITER
============================================================
*/

const rateBuckets = new Map();

function rateLimit({
    windowMs = 15 * 60 * 1000,
    max = 100
} = {}) {
    return (req, res, next) => {
        const forwarded = req.headers["x-forwarded-for"];
        const ip =
            String(forwarded || req.ip || "unknown")
                .split(",")[0]
                .trim();

        const key = `${ip}:${req.path}`;

        const now = Date.now();
        let bucket = rateBuckets.get(key);

        if (!bucket || now - bucket.start > windowMs) {
            bucket = {
                start: now,
                count: 0
            };
        }

        bucket.count += 1;
        rateBuckets.set(key, bucket);

        if (bucket.count > max) {
            return sendError(
                res,
                "RATE_LIMITED",
                "Too many requests. Please try again later.",
                429
            );
        }

        next();
    };
}

/*
============================================================
 EXPRESS CONFIGURATION
============================================================
*/

if (FRONTEND_ORIGIN === "*") {
    app.use(cors());
} else {
    const allowedOrigins = FRONTEND_ORIGIN
        .split(",")
        .map(v => v.trim())
        .filter(Boolean);

    app.use(
        cors({
            origin(origin, callback) {
                if (!origin || allowedOrigins.includes(origin)) {
                    return callback(null, true);
                }

                return callback(
                    new Error("Origin not allowed by CORS.")
                );
            }
        })
    );
}

app.disable("x-powered-by");

app.use(
    express.json({
        limit: "1mb"
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: "1mb"
    })
);

app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 300
}));

/*
============================================================
 AUTHENTICATION
============================================================
*/

function createSession(userId) {
    const token = generateSecureToken(48);

    const session = {
        id: generateId("session"),
        userId,
        tokenHash: crypto
            .createHash("sha256")
            .update(token + SESSION_SECRET)
            .digest("hex"),
        createdAt: new Date().toISOString(),
        expiresAt: addDays(new Date(), SESSION_DAYS).toISOString()
    };

    updateDatabase(db => {
        db.sessions = db.sessions.filter(
            s => !isExpired(s.expiresAt)
        );

        db.sessions.push(session);
    });

    return {
        token,
        expiresAt: session.expiresAt
    };
}

function getSessionFromRequest(req) {
    const auth = req.headers.authorization || "";

    if (!auth.startsWith("Bearer ")) {
        return null;
    }

    const token = auth.slice(7).trim();

    if (!token) {
        return null;
    }

    const tokenHash = crypto
        .createHash("sha256")
        .update(token + SESSION_SECRET)
        .digest("hex");

    const db = readDatabase();

    const session = db.sessions.find(
        s =>
            s.tokenHash === tokenHash &&
            !isExpired(s.expiresAt)
    );

    if (!session) {
        return null;
    }

    const user = db.users.find(
        u => u.id === session.userId
    );

    if (!user) {
        return null;
    }

    return {
        session,
        user
    };
}

function requireAuth(req, res, next) {
    const auth = getSessionFromRequest(req);

    if (!auth) {
        return sendError(
            res,
            "UNAUTHORIZED",
            "Authentication required.",
            401
        );
    }

    req.user = auth.user;
    req.session = auth.session;

    next();
}

function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return sendError(
            res,
            "FORBIDDEN",
            "Administrator access required.",
            403
        );
    }

    next();
}

/*
============================================================
 AUDIT LOG
============================================================
*/

function createAuditLog({
    actorUserId = null,
    action,
    targetType = null,
    targetId = null,
    metadata = {}
}) {
    updateDatabase(db => {
        db.auditLogs.push({
            id: generateId("audit"),
            actorUserId,
            action: safeText(action, 200),
            targetType,
            targetId,
            metadata,
            createdAt: new Date().toISOString()
        });
    });
}

/*
============================================================
 DEFAULT SUBJECTS
============================================================
*/

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
    "Pharmacy Management"
];

/*
============================================================
 QUESTION SEED DATA
============================================================
*/

const STARTER_QUESTIONS = [
    {
        id: "q_pharm_001",
        subject: "Pharmacology",
        topic: "Autonomic Pharmacology",
        subtopic: "Cholinergic receptors",
        difficulty: "easy",
        questionType: "mcq",
        question:
            "Which receptor is primarily responsible for the muscarinic effects of acetylcholine?",
        options: [
            "Nicotinic receptor",
            "Muscarinic receptor",
            "Beta-1 adrenergic receptor",
            "Alpha-1 adrenergic receptor"
        ],
        correctAnswer: 1,
        explanation:
            "Acetylcholine produces muscarinic effects by activating muscarinic cholinergic receptors.",
        whyCorrect:
            "Muscarinic receptors are G-protein-coupled acetylcholine receptors involved in many parasympathetic responses.",
        optionExplanations: [
            "Nicotinic receptors are ligand-gated ion channels and mediate other cholinergic responses.",
            "Correct. Muscarinic receptors mediate the classical muscarinic actions of acetylcholine.",
            "Beta-1 receptors respond primarily to noradrenaline and adrenaline.",
            "Alpha-1 receptors are adrenergic receptors rather than cholinergic receptors."
        ],
        learningPoints: [
            "Acetylcholine acts at both muscarinic and nicotinic receptors.",
            "Muscarinic receptors are metabotropic receptors."
        ],
        references: [
            "Standard pharmacology textbooks",
            "Current pharmacology reference materials"
        ],
        curriculum: "international",
        yearLevel: "all",
        semester: "all",
        classification: "theory",
        tags: [
            "acetylcholine",
            "muscarinic",
            "autonomic"
        ],
        sourceType: "curated",
        published: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    },

    {
        id: "q_pharm_002",
        subject: "Pharmaceutics",
        topic: "Solutions",
        subtopic: "Concentration",
        difficulty: "easy",
        questionType: "mcq",
        question:
            "What does % w/v commonly express?",
        options: [
            "Grams of solute per 100 mL of solution",
            "Milligrams of solute per 1 mL of solution",
            "Moles of solute per litre",
            "Grams of solvent per 100 mL"
        ],
        correctAnswer: 0,
        explanation:
            "% w/v commonly expresses grams of solute present in 100 mL of solution.",
        whyCorrect:
            "Weight/volume percentage relates the mass of solute to the final volume of solution.",
        optionExplanations: [
            "Correct. This is the standard interpretation of % w/v.",
            "This is not the standard definition of % w/v.",
            "This describes molarity.",
            "The denominator refers to the final solution volume rather than simply solvent."
        ],
        learningPoints: [
            "% w/v = grams of solute per 100 mL of solution.",
            "Molarity is expressed as moles per litre."
        ],
        references: [
            "Standard pharmaceutics references"
        ],
        curriculum: "international",
        yearLevel: "all",
        semester: "all",
        classification: "theory",
        tags: [
            "concentration",
            "solutions",
            "percentage"
        ],
        sourceType: "curated",
        published: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    },

    {
        id: "q_micro_001",
        subject: "Pharmaceutical Microbiology",
        topic: "Sterilization",
        subtopic: "Autoclave",
        difficulty: "easy",
        questionType: "mcq",
        question:
            "Which principle is primarily used by an autoclave to sterilize materials?",
        options: [
            "Dry heat",
            "Moist heat under pressure",
            "Ultraviolet radiation",
            "Filtration only"
        ],
        correctAnswer: 1,
        explanation:
            "An autoclave uses moist heat under pressure to achieve sterilization.",
        whyCorrect:
            "Pressurized steam raises the temperature above the normal boiling point of water and facilitates microbial destruction.",
        optionExplanations: [
            "Dry heat is used in hot-air ovens rather than autoclaves.",
            "Correct. Autoclaves use saturated steam under pressure.",
            "UV radiation is a separate physical method.",
            "Filtration is a different sterilization approach used for suitable liquids or gases."
        ],
        learningPoints: [
            "Autoclaves use moist heat.",
            "Pressure permits steam temperatures above 100°C."
        ],
        references: [
            "Standard pharmaceutical microbiology references"
        ],
        curriculum: "international",
        yearLevel: "all",
        semester: "all",
        classification: "practical",
        tags: [
            "autoclave",
            "sterilization",
            "microbiology"
        ],
        sourceType: "curated",
        published: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    },

    {
        id: "q_calc_001",
        subject: "Pharmaceutical Calculations",
        topic: "Percentage Strength",
        subtopic: "% w/v",
        difficulty: "medium",
        questionType: "calculation",
        question:
            "How many grams of drug are required to prepare 200 mL of a 5% w/v solution?",
        options: [
            "5 g",
            "10 g",
            "20 g",
            "25 g"
        ],
        correctAnswer: 1,
        explanation:
            "A 5% w/v solution contains 5 g in every 100 mL. Therefore, for 200 mL: 5 × 200 / 100 = 10 g.",
        whyCorrect:
            "The required mass is proportional to the final volume.",
        optionExplanations: [
            "5 g would correspond to 100 mL at 5% w/v.",
            "Correct. 5 g/100 mL × 200 mL = 10 g.",
            "20 g would correspond to a higher concentration.",
            "25 g is also greater than the required amount."
        ],
        learningPoints: [
            "5% w/v means 5 g per 100 mL.",
            "Scale the amount proportionally for the required volume."
        ],
        references: [
            "Standard pharmaceutical calculations references"
        ],
        curriculum: "international",
        yearLevel: "all",
        semester: "all",
        classification: "practical",
        tags: [
            "calculations",
            "percentage",
            "w/v"
        ],
        sourceType: "curated",
        published: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    },

    {
        id: "q_phys_001",
        subject: "Physiology",
        topic: "Blood",
        subtopic: "Red blood cells",
        difficulty: "easy",
        questionType: "mcq",
        question:
            "What is the primary function of haemoglobin in red blood cells?",
        options: [
            "Blood clotting",
            "Oxygen transport",
            "Antibody production",
            "Bile production"
        ],
        correctAnswer: 1,
        explanation:
            "Haemoglobin binds oxygen and facilitates its transport through the circulation.",
        whyCorrect:
            "Haemoglobin is the major oxygen-carrying protein in red blood cells.",
        optionExplanations: [
            "Clotting involves platelets and coagulation proteins.",
            "Correct. Haemoglobin is central to oxygen transport.",
            "Antibodies are produced by differentiated B cells/plasma cells.",
            "Bile is produced by the liver."
        ],
        learningPoints: [
            "Haemoglobin binds oxygen reversibly.",
            "Red blood cells are specialized for gas transport."
        ],
        references: [
            "Standard physiology textbooks"
        ],
        curriculum: "international",
        yearLevel: "all",
        semester: "all",
        classification: "theory",
        tags: [
            "blood",
            "haemoglobin",
            "oxygen"
        ],
        sourceType: "curated",
        published: true,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    }
];

/*
============================================================
 ACHIEVEMENTS
============================================================
*/

const DEFAULT_ACHIEVEMENTS = [
    {
        id: "first_quiz",
        name: "First Quiz",
        description: "Complete your first quiz.",
        requirement: {
            type: "quizCount",
            value: 1
        },
        reward: {
            xp: 50,
            coins: 10
        },
        icon: "🎯"
    },
    {
        id: "questions_10",
        name: "10 Questions",
        description: "Attempt 10 questions.",
        requirement: {
            type: "questionsAttempted",
            value: 10
        },
        reward: {
            xp: 100,
            coins: 20
        },
        icon: "📚"
    },
    {
        id: "questions_100",
        name: "100 Questions",
        description: "Attempt 100 questions.",
        requirement: {
            type: "questionsAttempted",
            value: 100
        },
        reward: {
            xp: 500,
            coins: 100
        },
        icon: "🏆"
    },
    {
        id: "perfect_score",
        name: "Perfect Score",
        description: "Achieve 100% in a quiz.",
        requirement: {
            type: "perfectQuiz",
            value: 1
        },
        reward: {
            xp: 250,
            coins: 50
        },
        icon: "💯"
    },
    {
        id: "streak_7",
        name: "7-Day Streak",
        description: "Maintain a 7-day activity streak.",
        requirement: {
            type: "streak",
            value: 7
        },
        reward: {
            xp: 300,
            coins: 75
        },
        icon: "🔥"
    },
    {
        id: "streak_30",
        name: "30-Day Streak",
        description: "Maintain a 30-day activity streak.",
        requirement: {
            type: "streak",
            value: 30
        },
        reward: {
            xp: 1000,
            coins: 250
        },
        icon: "🔥"
    }
];

/*
============================================================
 PHARMACOPOEIA HUB
============================================================
*/

const PHARMACOPOEIA_CONTENT = [
    {
        id: "bp",
        name: "British Pharmacopoeia (BP)",
        shortName: "BP",
        description:
            "The British Pharmacopoeia is an important source of official quality standards for pharmaceutical substances and medicinal products.",
        concepts: [
            "Monographs",
            "General notices",
            "Identification",
            "Assay",
            "Purity tests",
            "Dissolution",
            "Disintegration",
            "Uniformity",
            "Microbiological quality",
            "Storage"
        ],
        officialResource:
            "https://www.pharmacopoeia.com/"
    },
    {
        id: "usp-nf",
        name: "United States Pharmacopeia–National Formulary",
        shortName: "USP–NF",
        description:
            "USP–NF provides standards and specifications used to support pharmaceutical quality.",
        concepts: [
            "Monographs",
            "General chapters",
            "Identity",
            "Strength",
            "Quality",
            "Purity",
            "Performance"
        ],
        officialResource:
            "https://www.usp.org/"
    },
    {
        id: "ph-eur",
        name: "European Pharmacopoeia",
        shortName: "Ph. Eur.",
        description:
            "The European Pharmacopoeia establishes common quality standards for medicines and their components in participating jurisdictions.",
        concepts: [
            "Monographs",
            "General methods",
            "Quality standards",
            "Impurity controls",
            "Dosage forms",
            "Analytical methods"
        ],
        officialResource:
            "https://www.edqm.eu/"
    },
    {
        id: "who-quality",
        name: "WHO Medicine Quality Concepts",
        shortName: "WHO",
        description:
            "Educational material concerning medicine quality, standards and quality assurance concepts.",
        concepts: [
            "Quality assurance",
            "Good manufacturing practices",
            "Medicine quality",
            "Quality control",
            "Substandard and falsified medicines"
        ],
        officialResource:
            "https://www.who.int/"
    }
];

/*
============================================================
 LANGUAGE ASSISTANT
============================================================
*/

const LANGUAGE_DATA = [
    {
        id: "en",
        name: "English",
        nativeName: "English"
    },
    {
        id: "fr",
        name: "French",
        nativeName: "Français"
    },
    {
        id: "es",
        name: "Spanish",
        nativeName: "Español"
    },
    {
        id: "pt",
        name: "Portuguese",
        nativeName: "Português"
    },
    {
        id: "ar",
        name: "Arabic",
        nativeName: "العربية"
    },
    {
        id: "ha",
        name: "Hausa",
        nativeName: "Hausa"
    },
    {
        id: "ig",
        name: "Igbo",
        nativeName: "Igbo"
    },
    {
        id: "yo",
        name: "Yoruba",
        nativeName: "Yorùbá"
    },
    {
        id: "sw",
        name: "Swahili",
        nativeName: "Kiswahili"
    },
    {
        id: "de",
        name: "German",
        nativeName: "Deutsch"
    },
    {
        id: "it",
        name: "Italian",
        nativeName: "Italiano"
    },
    {
        id: "zh",
        name: "Mandarin Chinese",
        nativeName: "中文"
    },
    {
        id: "hi",
        name: "Hindi",
        nativeName: "हिन्दी"
    },
    {
        id: "bn",
        name: "Bengali",
        nativeName: "বাংলা"
    }
];

const LANGUAGE_PHRASES = [
    {
        id: "phrase_001",
        category: "patient-counselling",
        english:
            "Take this medicine twice daily.",
        translations: {
            fr: "Prenez ce médicament deux fois par jour.",
            es: "Tome este medicamento dos veces al día.",
            pt: "Tome este medicamento duas vezes ao dia."
        },
        pronunciation: {
            fr: "Prenez ce médicament deux fois par jour."
        }
    },
    {
        id: "phrase_002",
        category: "history-taking",
        english:
            "Do you have any allergies?",
        translations: {
            fr: "Avez-vous des allergies ?",
            es: "¿Tiene alguna alergia?",
            pt: "Você tem alguma alergia?"
        }
    },
    {
        id: "phrase_003",
        category: "history-taking",
        english:
            "What symptoms are you experiencing?",
        translations: {
            fr: "Quels symptômes ressentez-vous ?",
            es: "¿Qué síntomas está experimentando?",
            pt: "Quais sintomas você está apresentando?"
        }
    },
    {
        id: "phrase_004",
        category: "history-taking",
        english:
            "When did the symptoms start?",
        translations: {
            fr: "Quand les symptômes ont-ils commencé ?",
            es: "¿Cuándo comenzaron los síntomas?",
            pt: "Quando os sintomas começaram?"
        }
    }
];

/*
============================================================
 LIBRARY CONTENT
============================================================
*/

const LIBRARY_DATA = [
    {
        id: "lib_pharm_intro",
        title: "Introduction to Pharmacology",
        subject: "Pharmacology",
        description:
            "An original student-friendly introduction to drug action, receptors and basic pharmacological concepts.",
        resourceType: "study-note",
        difficulty: "beginner",
        author: "DENexpharm",
        source: "Original educational content",
        reference:
            "Use alongside current standard pharmacology textbooks."
    },
    {
        id: "lib_pharmaceutics_calc",
        title: "Pharmaceutical Calculations Revision Guide",
        subject: "Pharmaceutics",
        description:
            "A concise guide to common pharmaceutical calculation concepts and formulas.",
        resourceType: "revision-guide",
        difficulty: "intermediate",
        author: "DENexpharm",
        source: "Original educational content",
        reference:
            "Use alongside standard pharmaceutical calculation references."
    },
    {
        id: "lib_microbiology",
        title: "Pharmaceutical Microbiology Quick Review",
        subject: "Pharmaceutical Microbiology",
        description:
            "Student-focused review of sterilization, culture media and basic microbiology.",
        resourceType: "revision-guide",
        difficulty: "beginner",
        author: "DENexpharm",
        source: "Original educational content",
        reference:
            "Use alongside standard pharmaceutical microbiology references."
    }
];

/*
============================================================
 INITIAL CONTENT
============================================================
*/

function seedContent() {
    updateDatabase(db => {
        if (db.questions.length === 0) {
            db.questions.push(...STARTER_QUESTIONS);
        }

        if (db.achievements.length === 0) {
            db.achievements.push(...DEFAULT_ACHIEVEMENTS);
        }

        if (db.pharmacopoeia.length === 0) {
            db.pharmacopoeia.push(...PHARMACOPOEIA_CONTENT);
        }

        if (db.languages.length === 0) {
            db.languages.push(...LANGUAGE_DATA);
        }

        if (db.languagePhrases.length === 0) {
            db.languagePhrases.push(...LANGUAGE_PHRASES);
        }

        if (db.library.length === 0) {
            db.library.push(...LIBRARY_DATA);
        }
    });
}

seedContent();

/*
============================================================
 USER / WALLET HELPERS
============================================================
*/

function createWalletForUser(userId) {
    updateDatabase(db => {
        if (!db.wallets.some(w => w.userId === userId)) {
            db.wallets.push({
                id: generateId("wallet"),
                userId,
                balance: 0,
                xp: 0,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            });
        }
    });
}

function getWallet(userId) {
    const db = readDatabase();

    return (
        db.wallets.find(w => w.userId === userId) || {
            id: null,
            userId,
            balance: 0,
            xp: 0
        }
    );
}

function addWalletReward(
    userId,
    {
        coins = 0,
        xp = 0,
        type = "reward",
        reference = null,
        description = ""
    }
) {
    if (coins === 0 && xp === 0) {
        return;
    }

    updateDatabase(db => {
        let wallet = db.wallets.find(
            w => w.userId === userId
        );

        if (!wallet) {
            wallet = {
                id: generateId("wallet"),
                userId,
                balance: 0,
                xp: 0,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            };

            db.wallets.push(wallet);
        }

        wallet.balance += Number(coins) || 0;
        wallet.xp += Number(xp) || 0;
        wallet.updatedAt = new Date().toISOString();

        db.walletTransactions.push({
            id: generateId("wallet_tx"),
            userId,
            type,
            coins: Number(coins) || 0,
            xp: Number(xp) || 0,
            reference,
            description: safeText(description, 500),
            createdAt: new Date().toISOString()
        });
    });
}

function calculateLevel(xp) {
    return Math.floor(Math.max(0, xp) / 500) + 1;
}

function updateUserActivity(userId) {
    updateDatabase(db => {
        const user = db.users.find(
            u => u.id === userId
        );

        if (!user) return;

        const today = todayKey();
        const last = user.lastActivityDate;

        if (last !== today) {
            const yesterday = new Date();
            yesterday.setDate(
                yesterday.getDate() - 1
            );

            const yesterdayKey =
                yesterday.toISOString().slice(0, 10);

            if (last === yesterdayKey) {
                user.streak =
                    Number(user.streak || 0) + 1;
            } else {
                user.streak = 1;
            }

            user.lastActivityDate = today;
        }

        const wallet = db.wallets.find(
            w => w.userId === userId
        );

        if (wallet) {
            user.xp = wallet.xp || 0;
            user.coins = wallet.balance || 0;
            user.level = calculateLevel(user.xp);
        }

        user.updatedAt = new Date().toISOString();
    });
}

/*
============================================================
 ACHIEVEMENTS
============================================================
*/

function checkAchievements(userId) {
    const db = readDatabase();

    const user = db.users.find(
        u => u.id === userId
    );

    if (!user) return [];

    const quizCount = db.quizResults.filter(
        q => q.userId === userId
    ).length;

    const attemptedQuestions = db.quizResults
        .filter(q => q.userId === userId)
        .reduce(
            (sum, q) => sum + Number(q.totalQuestions || 0),
            0
        );

    const perfectQuiz = db.quizResults.some(
        q =>
            q.userId === userId &&
            Number(q.percentage) === 100
    );

    const unlocked = [];

    for (const achievement of db.achievements) {
        const already = db.userAchievements.some(
            ua =>
                ua.userId === userId &&
                ua.achievementId === achievement.id
        );

        if (already) continue;

        let qualifies = false;

        switch (
            achievement.requirement &&
            achievement.requirement.type
        ) {
            case "quizCount":
                qualifies =
                    quizCount >=
                    achievement.requirement.value;
                break;

            case "questionsAttempted":
                qualifies =
                    attemptedQuestions >=
                    achievement.requirement.value;
                break;

            case "perfectQuiz":
                qualifies = perfectQuiz;
                break;

            case "streak":
                qualifies =
                    Number(user.streak || 0) >=
                    achievement.requirement.value;
                break;

            default:
                break;
        }

        if (qualifies) {
            updateDatabase(database => {
                database.userAchievements.push({
                    id: generateId("user_achievement"),
                    userId,
                    achievementId: achievement.id,
                    unlockedAt: new Date().toISOString()
                });
            });

            addWalletReward(userId, {
                coins: achievement.reward.coins,
                xp: achievement.reward.xp,
                type: "achievement",
                reference: achievement.id,
                description:
                    `Achievement unlocked: ${achievement.name}`
            });

            unlocked.push(achievement);
        }
    }

    return unlocked;
}

/*
============================================================
 QUESTIONS
============================================================
*/

function getQuestionForClient(question) {
    if (!question) return null;

    return {
        id: question.id,
        subject: question.subject,
        topic: question.topic,
        subtopic: question.subtopic,
        difficulty: question.difficulty,
        questionType: question.questionType,
        question: question.question,
        options: question.options,
        curriculum: question.curriculum,
        yearLevel: question.yearLevel,
        semester: question.semester,
        classification: question.classification,
        tags: question.tags,
        sourceType: question.sourceType
    };
}

function getQuestionExplanation(question, selectedAnswer) {
    const selected =
        Number.isInteger(selectedAnswer)
            ? selectedAnswer
            : null;

    const correct = question.correctAnswer;

    return {
        correctAnswer: correct,
        correctOption:
            question.options &&
            question.options[correct],

        selectedAnswer: selected,

        selectedOption:
            selected !== null &&
            question.options
                ? question.options[selected]
                : null,

        explanation: question.explanation,
        whyCorrect: question.whyCorrect,

        whyYourAnswerIsWrong:
            selected !== null &&
            selected !== correct &&
            question.optionExplanations
                ? question.optionExplanations[selected]
                : null,

        optionExplanations:
            question.optionExplanations || [],

        learningPoints:
            question.learningPoints || [],

        references:
            question.references || [],

        relatedTopic: question.topic,

        classification: question.classification
    };
}

function filterQuestions(db, query) {
    let questions = db.questions.filter(
        q => q.published !== false
    );

    if (query.subject) {
        questions = questions.filter(
            q =>
                String(q.subject).toLowerCase() ===
                String(query.subject).toLowerCase()
        );
    }

    if (query.topic) {
        questions = questions.filter(
            q =>
                String(q.topic).toLowerCase() ===
                String(query.topic).toLowerCase()
        );
    }

    if (query.difficulty) {
        questions = questions.filter(
            q =>
                String(q.difficulty).toLowerCase() ===
                String(query.difficulty).toLowerCase()
        );
    }

    if (query.questionType) {
        questions = questions.filter(
            q =>
                String(q.questionType).toLowerCase() ===
                String(query.questionType).toLowerCase()
        );
    }

    if (query.classification) {
        questions = questions.filter(
            q =>
                String(q.classification).toLowerCase() ===
                String(query.classification).toLowerCase()
        );
    }

    if (query.yearLevel) {
        questions = questions.filter(
            q =>
                q.yearLevel === query.yearLevel ||
                q.yearLevel === "all"
        );
    }

    if (query.semester) {
        questions = questions.filter(
            q =>
                q.semester === query.semester ||
                q.semester === "all"
        );
    }

    if (query.curriculum) {
        questions = questions.filter(
            q =>
                q.curriculum === query.curriculum ||
                q.curriculum === "international"
        );
    }

    if (query.search) {
        const term = String(query.search).toLowerCase();

        questions = questions.filter(q =>
            [
                q.question,
                q.subject,
                q.topic,
                q.subtopic,
                ...(q.tags || [])
            ]
                .join(" ")
                .toLowerCase()
                .includes(term)
        );
    }

    return questions;
}

function selectRandomQuestions(questions, count) {
    const copy = [...questions];

    for (let i = copy.length - 1; i > 0; i--) {
        const j = crypto.randomInt(i + 1);
        [copy[i], copy[j]] = [copy[j], copy[i]];
    }

    return copy.slice(0, count);
}

/*
============================================================
 API BASE
============================================================
*/

app.get("/api/v1/health", (req, res) => {
    return sendSuccess(res, {
        status: "ok",
        app: APP_NAME,
        version: APP_VERSION,
        contentYear: CONTENT_YEAR,
        environment: NODE_ENV,
        uptime: process.uptime(),
        timestamp: new Date().toISOString()
    });
});

app.get("/api/v1/version", (req, res) => {
    return sendSuccess(res, {
        app: APP_NAME,
        version: APP_VERSION,
        contentYear: CONTENT_YEAR,
        node: process.version
    });
});

app.get("/api/v1/config", (req, res) => {
    return sendSuccess(res, {
        app: APP_NAME,
        version: APP_VERSION,
        contentYear: CONTENT_YEAR,
        supportedCountries: [
            "Nigeria",
            "Ghana",
            "Kenya",
            "South Africa",
            "United Kingdom",
            "United States",
            "Canada",
            "Australia",
            "India",
            "Pakistan",
            "Bangladesh",
            "Egypt",
            "Saudi Arabia",
            "United Arab Emirates",
            "France",
            "Germany",
            "Spain",
            "Portugal",
            "Brazil"
        ],
        supportedCurrencies: [
            "NGN",
            "USD",
            "GBP",
            "EUR",
            "CAD",
            "AUD",
            "GHS",
            "KES",
            "ZAR",
            "INR"
        ],
        paymentProvider:
            process.env.PAYMENT_PROVIDER || "not-configured"
    });
});

/*
============================================================
 SUBJECTS
============================================================
*/

app.get("/api/v1/subjects", (req, res) => {
    return sendSuccess(res, {
        subjects: SUBJECTS
    });
});

/*
============================================================
 AUTH REGISTER
============================================================
*/

app.post(
    "/api/v1/auth/register",
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 20
    }),
    (req, res) => {
        const {
            email,
            password,
            username,
            displayName,
            country,
            state,
            institution,
            program,
            yearOfStudy,
            semester,
            preferredLanguage,
            currency,
            timezone,
            referralCode
        } = req.body || {};

        const normalizedEmail =
            normalizeEmail(email);

        if (!validateEmail(normalizedEmail)) {
            return sendError(
                res,
                "INVALID_EMAIL",
                "Please provide a valid email address."
            );
        }

        if (!validatePassword(password)) {
            return sendError(
                res,
                "INVALID_PASSWORD",
                "Password must contain at least 8 characters."
            );
        }

        const db = readDatabase();

        if (
            db.users.some(
                u => u.email === normalizedEmail
            )
        ) {
            return sendError(
                res,
                "EMAIL_EXISTS",
                "An account with this email already exists.",
                409
            );
        }

        const safeUsername =
            safeText(username, 50) ||
            `student_${crypto.randomBytes(4).toString("hex")}`;

        if (
            db.users.some(
                u =>
                    String(u.username).toLowerCase() ===
                    safeUsername.toLowerCase()
            )
        ) {
            return sendError(
                res,
                "USERNAME_EXISTS",
                "That username is already in use.",
                409
            );
        }

        const passwordData =
            hashPassword(password);

        const userId = generateId("user");

        const user = {
            id: userId,
            email: normalizedEmail,
            username: safeUsername,
            displayName:
                safeText(displayName, 100) ||
                safeUsername,

            country: safeText(country, 100),
            state: safeText(state, 100),
            institution: safeText(institution, 200),
            program: safeText(program, 150),
            yearOfStudy: safeText(yearOfStudy, 50),
            semester: safeText(semester, 50),
            preferredLanguage:
                safeText(preferredLanguage, 20) || "en",
            currency:
                safeText(currency, 10) || "NGN",
            timezone:
                safeText(timezone, 100) || "Africa/Lagos",

            role: "student",

            xp: 0,
            coins: 0,
            level: 1,
            streak: 0,
            lastActivityDate: null,

            subscriptionStatus: "free",

            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),

            passwordHash: passwordData.hash,
            passwordSalt: passwordData.salt
        };

        updateDatabase(database => {
            database.users.push(user);

            database.wallets.push({
                id: generateId("wallet"),
                userId,
                balance: 0,
                xp: 0,
                createdAt: new Date().toISOString(),
                updatedAt: new Date().toISOString()
            });
        });

        /*
         * Referral is processed separately so the account
         * exists before the relationship is recorded.
         */
        if (referralCode) {
            applyReferralCodeInternal(
                userId,
                safeText(referralCode, 50)
            );
        }

        const session = createSession(userId);

        return sendSuccess(
            res,
            {
                user: sanitizeUser(user),
                session
            },
            201
        );
    }
);

/*
============================================================
 AUTH LOGIN
============================================================
*/

app.post(
    "/api/v1/auth/login",
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 15
    }),
    (req, res) => {
        const email =
            normalizeEmail(req.body && req.body.email);

        const password =
            req.body && req.body.password;

        const db = readDatabase();

        const user = db.users.find(
            u => u.email === email
        );

        if (
            !user ||
            !validatePassword(password) ||
            !verifyPassword(
                password,
                user.passwordHash,
                user.passwordSalt
            )
        ) {
            return sendError(
                res,
                "INVALID_CREDENTIALS",
                "Invalid email or password.",
                401
            );
        }

        if (user.status === "suspended") {
            return sendError(
                res,
                "ACCOUNT_SUSPENDED",
                "This account has been suspended.",
                403
            );
        }

        updateUserActivity(user.id);

        const session = createSession(user.id);

        const freshDb = readDatabase();
        const freshUser = freshDb.users.find(
            u => u.id === user.id
        );

        return sendSuccess(res, {
            user: sanitizeUser(freshUser),
            session
        });
    }
);

/*
============================================================
 LOGOUT
============================================================
*/

app.post(
    "/api/v1/auth/logout",
    requireAuth,
    (req, res) => {
        updateDatabase(db => {
            db.sessions = db.sessions.filter(
                s => s.id !== req.session.id
            );
        });

        return sendSuccess(res, {
            message: "Logged out successfully."
        });
    }
);

/*
============================================================
 CURRENT USER / PROFILE
============================================================
*/

app.get(
    "/api/v1/me",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const user = db.users.find(
            u => u.id === req.user.id
        );

        const wallet = db.wallets.find(
            w => w.userId === req.user.id
        );

        const subscription = db.subscriptions
            .filter(
                s => s.userId === req.user.id
            )
            .sort(
                (a, b) =>
                    new Date(b.createdAt) -
                    new Date(a.createdAt)
            )[0] || null;

        return sendSuccess(res, {
            user: sanitizeUser(user),
            wallet,
            subscription
        });
    }
);

app.get(
    "/api/v1/profile",
    requireAuth,
    (req, res) => {
        return sendSuccess(res, {
            user: sanitizeUser(req.user)
        });
    }
);

app.put(
    "/api/v1/profile",
    requireAuth,
    (req, res) => {
        const allowed = [
            "displayName",
            "country",
            "state",
            "institution",
            "program",
            "yearOfStudy",
            "semester",
            "preferredLanguage",
            "currency",
            "timezone"
        ];

        updateDatabase(db => {
            const user = db.users.find(
                u => u.id === req.user.id
            );

            if (!user) return;

            for (const key of allowed) {
                if (
                    req.body[key] !== undefined
                ) {
                    user[key] =
                        safeText(
                            req.body[key],
                            200
                        );
                }
            }

            user.updatedAt =
                new Date().toISOString();
        });

        const db = readDatabase();

        return sendSuccess(res, {
            user: sanitizeUser(
                db.users.find(
                    u => u.id === req.user.id
                )
            )
        });
    }
);

/*
============================================================
 QUESTIONS
============================================================
*/

app.get(
    "/api/v1/questions",
    (req, res) => {
        const db = readDatabase();

        const questions = filterQuestions(
            db,
            req.query
        );

        const {
            page,
            limit
        } = parsePage(req);

        const result = paginate(
            questions.map(getQuestionForClient),
            page,
            limit
        );

        return sendSuccess(res, result);
    }
);

app.get(
    "/api/v1/questions/:id",
    (req, res) => {
        const db = readDatabase();

        const question = db.questions.find(
            q =>
                q.id === req.params.id &&
                q.published !== false
        );

        if (!question) {
            return sendError(
                res,
                "NOT_FOUND",
                "Question not found.",
                404
            );
        }

        return sendSuccess(res, {
            question: getQuestionForClient(question)
        });
    }
);

/*
============================================================
 QUIZ START
============================================================
*/

app.post(
    "/api/v1/quiz/start",
    requireAuth,
    (req, res) => {
        const {
            subject,
            topic,
            difficulty,
            questionType,
            classification,
            yearLevel,
            semester,
            curriculum,
            numberOfQuestions = 10,
            mode = "practice",
            timeLimitSeconds = null
        } = req.body || {};

        const db = readDatabase();

        let questions = filterQuestions(
            db,
            {
                subject,
                topic,
                difficulty,
                questionType,
                classification,
                yearLevel,
                semester,
                curriculum
            }
        );

        const requested =
            Math.min(
                100,
                Math.max(
                    1,
                    Number(numberOfQuestions) || 10
                )
            );

        if (questions.length < requested) {
            /*
             * For MVP usability, serve whatever is available
             * instead of inventing questions.
             */
        }

        questions =
            selectRandomQuestions(
                questions,
                requested
            );

        if (questions.length === 0) {
            return sendError(
                res,
                "NO_QUESTIONS",
                "No questions match the selected criteria.",
                404
            );
        }

        const attempt = {
            id: generateId("quiz_attempt"),
            userId: req.user.id,
            mode,
            questionIds:
                questions.map(q => q.id),
            answers: {},
            startedAt:
                new Date().toISOString(),
            timeLimitSeconds:
                Number(timeLimitSeconds) || null,
            status: "active"
        };

        updateDatabase(db2 => {
            db2.quizAttempts.push(attempt);
        });

        updateUserActivity(req.user.id);

        return sendSuccess(res, {
            attemptId: attempt.id,
            mode,
            startedAt: attempt.startedAt,
            timeLimitSeconds:
                attempt.timeLimitSeconds,
            questions:
                questions.map(
                    getQuestionForClient
                )
        });
    }
);

/*
============================================================
 QUIZ SUBMIT
============================================================
*/

app.post(
    "/api/v1/quiz/submit",
    requireAuth,
    (req, res) => {
        const {
            attemptId,
            answers
        } = req.body || {};

        if (!attemptId) {
            return sendError(
                res,
                "INVALID_REQUEST",
                "attemptId is required."
            );
        }

        if (
            !answers ||
            typeof answers !== "object"
        ) {
            return sendError(
                res,
                "INVALID_ANSWERS",
                "Answers must be provided as an object."
            );
        }

        const db = readDatabase();

        const attempt =
            db.quizAttempts.find(
                a =>
                    a.id === attemptId &&
                    a.userId === req.user.id
            );

        if (!attempt) {
            return sendError(
                res,
                "NOT_FOUND",
                "Quiz attempt not found.",
                404
            );
        }

        if (attempt.status !== "active") {
            return sendError(
                res,
                "ALREADY_SUBMITTED",
                "This quiz has already been submitted."
            );
        }

        const now = Date.now();

        if (
            attempt.timeLimitSeconds &&
            now >
                new Date(
                    attempt.startedAt
                ).getTime() +
                    attempt.timeLimitSeconds *
                        1000
        ) {
            /*
             * Submission is still processed, but marked
             * as time expired.
             */
            attempt.timeExpired = true;
        }

        let correct = 0;
        let wrong = 0;
        let unanswered = 0;
        let points = 0;

        const questionResults = [];

        for (const questionId of attempt.questionIds) {
            const question =
                db.questions.find(
                    q => q.id === questionId
                );

            if (!question) continue;

            const rawAnswer =
                answers[questionId];

            const selected =
                rawAnswer === undefined ||
                rawAnswer === null ||
                rawAnswer === ""
                    ? null
                    : Number(rawAnswer);

            if (selected === null) {
                unanswered++;

                questionResults.push({
                    questionId,
                    correct: false,
                    unanswered: true,
                    explanation:
                        getQuestionExplanation(
                            question,
                            null
                        )
                });

                continue;
            }

            const isCorrect =
                selected ===
                question.correctAnswer;

            if (isCorrect) {
                correct++;

                const difficultyPoints =
                    question.difficulty === "hard"
                        ? 3
                        : question.difficulty ===
                          "medium"
                            ? 2
                            : 1;

                points +=
                    difficultyPoints;
            } else {
                wrong++;
            }

            questionResults.push({
                questionId,
                correct: isCorrect,
                unanswered: false,
                selectedAnswer: selected,
                explanation:
                    getQuestionExplanation(
                        question,
                        selected
                    )
            });
        }

        const totalQuestions =
            attempt.questionIds.length;

        const percentage =
            totalQuestions > 0
                ? Math.round(
                      (correct /
                          totalQuestions) *
                          10000
                  ) / 100
                : 0;

        const finishedAt =
            new Date().toISOString();

        const timeUsedSeconds = Math.max(
            0,
            Math.floor(
                (new Date(finishedAt).getTime() -
                    new Date(
                        attempt.startedAt
                    ).getTime()) /
                    1000
            )
        );

        const result = {
            id: generateId("quiz_result"),
            userId: req.user.id,
            attemptId,
            mode: attempt.mode,
            totalQuestions,
            correct,
            wrong,
            unanswered,
            points,
            percentage,
            timeUsedSeconds,
            timeExpired:
                Boolean(attempt.timeExpired),
            questionResults,
            createdAt: finishedAt
        };

        updateDatabase(database => {
            const target =
                database.quizAttempts.find(
                    a => a.id === attemptId
                );

            if (target) {
                target.answers = answers;
                target.status = "submitted";
                target.finishedAt = finishedAt;
            }

            database.quizResults.push(result);

            const analytics = database.analytics;

            analytics.push({
                id: generateId("analytics"),
                userId: req.user.id,
                type: "quiz_completed",
                subject: null,
                topic: null,
                score: percentage,
                correct,
                wrong,
                unanswered,
                createdAt: finishedAt
            });
        });

        /*
         * XP reward
         */
        const xpReward =
            correct * 10 +
            Math.floor(points * 5);

        const coinReward =
            Math.floor(correct / 5);

        addWalletReward(req.user.id, {
            xp: xpReward,
            coins: coinReward,
            type: "quiz_reward",
            reference: result.id,
            description:
                "Reward for completing a quiz."
        });

        updateUserActivity(req.user.id);

        const unlocked =
            checkAchievements(
                req.user.id
            );

        /*
         * Weak topics
         */
        const weakTopics = [];

        for (const item of questionResults) {
            if (item.correct) continue;

            const question =
                db.questions.find(
                    q => q.id === item.questionId
                );

            if (question) {
                weakTopics.push({
                    subject:
                        question.subject,
                    topic:
                        question.topic
                });
            }
        }

        return sendSuccess(res, {
            result,
            rewards: {
                xp: xpReward,
                coins: coinReward
            },
            unlockedAchievements:
                unlocked,
            weakTopics
        });
    }
);

/*
============================================================
 HISTORY
============================================================
*/

app.get(
    "/api/v1/history",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const results =
            db.quizResults
                .filter(
                    r =>
                        r.userId ===
                        req.user.id
                )
                .sort(
                    (a, b) =>
                        new Date(b.createdAt) -
                        new Date(a.createdAt)
                );

        const {
            page,
            limit
        } = parsePage(req);

        return sendSuccess(
            res,
            paginate(results, page, limit)
        );
    }
);

app.get(
    "/api/v1/results/:id",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const result =
            db.quizResults.find(
                r =>
                    r.id === req.params.id &&
                    r.userId === req.user.id
            );

        if (!result) {
            return sendError(
                res,
                "NOT_FOUND",
                "Result not found.",
                404
            );
        }

        return sendSuccess(res, {
            result
        });
    }
);

/*
============================================================
 QUICK BATTLE
============================================================
*/

app.post(
    "/api/v1/quick-battle",
    requireAuth,
    (req, res) => {
        const {
            subject,
            numberOfQuestions = 10
        } = req.body || {};

        const db = readDatabase();

        const questions =
            selectRandomQuestions(
                filterQuestions(
                    db,
                    { subject }
                ),
                Math.min(
                    50,
                    Math.max(
                        1,
                        Number(
                            numberOfQuestions
                        ) || 10
                    )
                )
            );

        if (questions.length === 0) {
            return sendError(
                res,
                "NO_QUESTIONS",
                "No battle questions are available."
            );
        }

        const battle = {
            id: generateId("battle"),
            type: "quick",
            userId: req.user.id,
            questionIds:
                questions.map(q => q.id),
            startedAt:
                new Date().toISOString(),
            status: "active"
        };

        updateDatabase(database => {
            database.battles.push(battle);
        });

        return sendSuccess(res, {
            battleId: battle.id,
            type: battle.type,
            questions:
                questions.map(
                    getQuestionForClient
                )
        });
    }
);

app.post(
    "/api/v1/quick-battle/submit",
    requireAuth,
    (req, res) => {
        const {
            battleId,
            answers
        } = req.body || {};

        const db = readDatabase();

        const battle =
            db.battles.find(
                b =>
                    b.id === battleId &&
                    b.userId === req.user.id
            );

        if (!battle) {
            return sendError(
                res,
                "NOT_FOUND",
                "Battle not found.",
                404
            );
        }

        if (battle.status !== "active") {
            return sendError(
                res,
                "ALREADY_SUBMITTED",
                "Battle already submitted."
            );
        }

        let score = 0;
        const details = [];

        for (const id of battle.questionIds) {
            const question =
                db.questions.find(
                    q => q.id === id
                );

            if (!question) continue;

            const selected =
                answers &&
                answers[id] !== undefined
                    ? Number(answers[id])
                    : null;

            const correct =
                selected ===
                question.correctAnswer;

            if (correct) {
                score++;
            }

            details.push({
                questionId: id,
                correct,
                selectedAnswer:
                    selected,
                correctAnswer:
                    question.correctAnswer,
                explanation:
                    getQuestionExplanation(
                        question,
                        selected
                    )
            });
        }

        const finishedAt =
            new Date().toISOString();

        updateDatabase(database => {
            const target =
                database.battles.find(
                    b => b.id === battleId
                );

            if (target) {
                target.status = "completed";
                target.answers = answers || {};
                target.score = score;
                target.finishedAt =
                    finishedAt;
            }
        });

        const xp =
            score * 15;

        const coins =
            Math.floor(score / 3);

        addWalletReward(req.user.id, {
            xp,
            coins,
            type: "battle_reward",
            reference: battleId,
            description:
                "Quick Battle reward."
        });

        return sendSuccess(res, {
            battleId,
            score,
            total:
                battle.questionIds.length,
            rewards: {
                xp,
                coins
            },
            details
        });
    }
);

/*
============================================================
 TIMED BATTLES
============================================================
*/

app.post(
    "/api/v1/battles/create",
    requireAuth,
    (req, res) => {
        const {
            subject = null,
            numberOfQuestions = 10,
            timeLimitSeconds = 60
        } = req.body || {};

        const db = readDatabase();

        const questions =
            selectRandomQuestions(
                filterQuestions(
                    db,
                    { subject }
                ),
                Math.min(
                    50,
                    Math.max(
                        1,
                        Number(
                            numberOfQuestions
                        ) || 10
                    )
                )
            );

        if (!questions.length) {
            return sendError(
                res,
                "NO_QUESTIONS",
                "No questions available."
            );
        }

        const battle = {
            id: generateId("battle"),
            type: "timed",
            hostUserId: req.user.id,
            opponentUserId: null,
            questionIds:
                questions.map(q => q.id),
            timeLimitSeconds: Math.min(
                3600,
                Math.max(
                    10,
                    Number(
                        timeLimitSeconds
                    ) || 60
                )
            ),
            createdAt:
                new Date().toISOString(),
            startedAt: null,
            status: "waiting",
            submissions: {}
        };

        updateDatabase(database => {
            database.battles.push(battle);
        });

        return sendSuccess(res, {
            battleId: battle.id,
            status: battle.status,
            timeLimitSeconds:
                battle.timeLimitSeconds,
            questionCount:
                questions.length,
            realtime:
                "REST-based MVP. WebSocket synchronization can be added later."
        });
    }
);

app.post(
    "/api/v1/battles/join",
    requireAuth,
    (req, res) => {
        const {
            battleId
        } = req.body || {};

        updateDatabase(db => {
            const battle =
                db.battles.find(
                    b =>
                        b.id ===
                        battleId
                );

            if (!battle) return;

            if (
                battle.hostUserId ===
                req.user.id
            ) {
                return;
            }

            if (
                battle.opponentUserId
            ) {
                return;
            }

            battle.opponentUserId =
                req.user.id;

            battle.startedAt =
                new Date().toISOString();

            battle.status = "active";
        });

        const db = readDatabase();

        const battle =
            db.battles.find(
                b =>
                    b.id ===
                    battleId
            );

        if (!battle) {
            return sendError(
                res,
                "NOT_FOUND",
                "Battle not found.",
                404
            );
        }

        return sendSuccess(res, {
            battle: {
                id: battle.id,
                status: battle.status,
                timeLimitSeconds:
                    battle.timeLimitSeconds,
                questionCount:
                    battle.questionIds.length
            }
        });
    }
);

app.get(
    "/api/v1/battles/:id",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const battle =
            db.battles.find(
                b =>
                    b.id ===
                    req.params.id
            );

        if (!battle) {
            return sendError(
                res,
                "NOT_FOUND",
                "Battle not found.",
                404
            );
        }

        if (
            battle.hostUserId !==
                req.user.id &&
            battle.opponentUserId !==
                req.user.id
        ) {
            return sendError(
                res,
                "FORBIDDEN",
                "You are not a participant in this battle.",
                403
            );
        }

        return sendSuccess(res, {
            battle
        });
    }
);

app.post(
    "/api/v1/battles/:id/submit",
    requireAuth,
    (req, res) => {
        const {
            answers
        } = req.body || {};

        const db = readDatabase();

        const battle =
            db.battles.find(
                b =>
                    b.id ===
                    req.params.id
            );

        if (!battle) {
            return sendError(
                res,
                "NOT_FOUND",
                "Battle not found.",
                404
            );
        }

        if (
            battle.hostUserId !==
                req.user.id &&
            battle.opponentUserId !==
                req.user.id
        ) {
            return sendError(
                res,
                "FORBIDDEN",
                "You are not a participant.",
                403
            );
        }

        let score = 0;

        for (const id of battle.questionIds) {
            const question =
                db.questions.find(
                    q => q.id === id
                );

            if (!question) continue;

            const selected =
                answers &&
                answers[id] !== undefined
                    ? Number(answers[id])
                    : null;

            if (
                selected ===
                question.correctAnswer
            ) {
                score++;
            }
        }

        updateDatabase(database => {
            const target =
                database.battles.find(
                    b =>
                        b.id ===
                        req.params.id
                );

            if (!target.submissions) {
                target.submissions = {};
            }

            target.submissions[
                req.user.id
            ] = {
                answers: answers || {},
                score,
                submittedAt:
                    new Date().toISOString()
            };

            if (
                target.hostUserId &&
                target.opponentUserId &&
                target.submissions[
                    target.hostUserId
                ] &&
                target.submissions[
                    target.opponentUserId
                ]
            ) {
                target.status = "completed";
                target.finishedAt =
                    new Date().toISOString();
            }
        });

        addWalletReward(req.user.id, {
            xp: score * 20,
            coins: Math.floor(score / 3),
            type: "timed_battle",
            reference: req.params.id,
            description:
                "Timed battle reward."
        });

        return sendSuccess(res, {
            battleId: req.params.id,
            score,
            message:
                "Battle submission recorded."
        });
    }
);

/*
============================================================
 LEADERBOARD
============================================================
*/

app.get(
    "/api/v1/leaderboard",
    (req, res) => {
        const db = readDatabase();

        const type =
            req.query.type || "global";

        let users = db.users.filter(
            u => u.status !== "suspended"
        );

        if (type === "country" && req.query.country) {
            users = users.filter(
                u =>
                    String(u.country).toLowerCase() ===
                    String(req.query.country).toLowerCase()
            );
        }

        if (
            type === "institution" &&
            req.query.institution
        ) {
            users = users.filter(
                u =>
                    String(
                        u.institution
                    ).toLowerCase() ===
                    String(
                        req.query.institution
                    ).toLowerCase()
            );
        }

        if (
            type === "subject" &&
            req.query.subject
        ) {
            /*
             * Subject-specific ranking is derived from
             * recorded quiz performance.
             */
            const subject =
                String(
                    req.query.subject
                ).toLowerCase();

            const scoreMap = {};

            db.quizResults.forEach(
                result => {
                    if (
                        !result.userId
                    ) return;

                    for (
                        const qr of
                            result.questionResults ||
                            []
                    ) {
                        const question =
                            db.questions.find(
                                q =>
                                    q.id ===
                                    qr.questionId
                            );

                        if (
                            question &&
                            String(
                                question.subject
                            ).toLowerCase() ===
                                subject
                        ) {
                            if (
                                !scoreMap[
                                    result.userId
                                ]
                            ) {
                                scoreMap[
                                    result.userId
                                ] = {
                                    total: 0,
                                    correct: 0
                                };
                            }

                            scoreMap[
                                result.userId
                            ].total++;

                            if (
                                qr.correct
                            ) {
                                scoreMap[
                                    result.userId
                                ].correct++;
                            }
                        }
                    }
                }
            );

            users = users
                .filter(
                    u =>
                        scoreMap[
                            u.id
                        ]
                )
                .map(u => ({
                    ...u,
                    subjectAccuracy:
                        scoreMap[
                            u.id
                        ].total
                            ? (
                                  scoreMap[
                                      u.id
                                  ].correct /
                                  scoreMap[
                                      u.id
                                  ].total
                              ) * 100
                            : 0
                }))
                .sort(
                    (a, b) =>
                        b.subjectAccuracy -
                        a.subjectAccuracy
                );
        } else {
            users.sort(
                (a, b) =>
                    Number(b.xp || 0) -
                    Number(a.xp || 0)
            );
        }

        const leaderboard =
            users
                .slice(0, 100)
                .map((u, index) => ({
                    rank: index + 1,
                    userId: u.id,
                    username: u.username,
                    displayName:
                        u.displayName,
                    country: u.country,
                    institution:
                        u.institution,
                    xp: u.xp || 0,
                    level: u.level || 1,
                    streak:
                        u.streak || 0
                }));

        return sendSuccess(res, {
            type,
            leaderboard
        });
    }
);

/*
============================================================
 DAILY CHALLENGE
============================================================
*/

function getOrCreateDailyChallenge() {
    const key = todayKey();

    let db = readDatabase();

    let challenge =
        db.dailyChallenges.find(
            c => c.date === key
        );

    if (challenge) {
        return challenge;
    }

    const questions =
        selectRandomQuestions(
            db.questions.filter(
                q => q.published !== false
            ),
            Math.min(
                10,
                db.questions.length
            )
        );

    challenge = {
        id: generateId("daily"),
        date: key,
        questionIds:
            questions.map(q => q.id),
        createdAt:
            new Date().toISOString()
    };

    updateDatabase(database => {
        database.dailyChallenges.push(
            challenge
        );
    });

    return challenge;
}

app.get(
    "/api/v1/daily-challenge",
    requireAuth,
    (req, res) => {
        const challenge =
            getOrCreateDailyChallenge();

        const db = readDatabase();

        const questions =
            challenge.questionIds
                .map(id =>
                    db.questions.find(
                        q => q.id === id
                    )
                )
                .filter(Boolean);

        return sendSuccess(res, {
            challenge: {
                id: challenge.id,
                date: challenge.date,
                questions:
                    questions.map(
                        getQuestionForClient
                    )
            }
        });
    }
);

app.post(
    "/api/v1/daily-challenge/submit",
    requireAuth,
    (req, res) => {
        const {
            challengeId,
            answers
        } = req.body || {};

        const db = readDatabase();

        const challenge =
            db.dailyChallenges.find(
                c =>
                    c.id ===
                    challengeId
            );

        if (!challenge) {
            return sendError(
                res,
                "NOT_FOUND",
                "Daily challenge not found.",
                404
            );
        }

        const already =
            db.analytics.some(
                a =>
                    a.userId ===
                        req.user.id &&
                    a.type ===
                        "daily_challenge_completed" &&
                    a.reference ===
                        challengeId
            );

        if (already) {
            return sendError(
                res,
                "ALREADY_COMPLETED",
                "You have already completed today's challenge."
            );
        }

        let correct = 0;

        for (const id of challenge.questionIds) {
            const q =
                db.questions.find(
                    question =>
                        question.id === id
                );

            if (!q) continue;

            if (
                answers &&
                Number(answers[id]) ===
                    q.correctAnswer
            ) {
                correct++;
            }
        }

        updateDatabase(database => {
            database.analytics.push({
                id: generateId("analytics"),
                userId: req.user.id,
                type:
                    "daily_challenge_completed",
                reference:
                    challengeId,
                score: correct,
                createdAt:
                    new Date().toISOString()
            });
        });

        const xp = correct * 25;
        const coins = correct;

        addWalletReward(req.user.id, {
            xp,
            coins,
            type: "daily_challenge",
            reference: challengeId,
            description:
                "Daily challenge reward."
        });

        updateUserActivity(req.user.id);

        const achievements =
            checkAchievements(
                req.user.id
            );

        return sendSuccess(res, {
            correct,
            total:
                challenge.questionIds.length,
            rewards: {
                xp,
                coins
            },
            achievements
        });
    }
);

/*
============================================================
 ACHIEVEMENTS
============================================================
*/

app.get(
    "/api/v1/achievements",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const unlocked =
            db.userAchievements.filter(
                ua =>
                    ua.userId ===
                    req.user.id
            );

        const achievements =
            db.achievements.map(a => ({
                ...a,
                unlocked:
                    unlocked.some(
                        u =>
                            u.achievementId ===
                            a.id
                    ),
                unlockedAt:
                    unlocked.find(
                        u =>
                            u.achievementId ===
                            a.id
                    )?.unlockedAt ||
                    null
            }));

        return sendSuccess(res, {
            achievements
        });
    }
);

/*
============================================================
 GPA CALCULATOR
============================================================
*/

function calculateGPA(courses, gradingScale) {
    if (!Array.isArray(courses)) {
        throw new Error(
            "Courses must be an array."
        );
    }

    const scale =
        Array.isArray(gradingScale) &&
        gradingScale.length
            ? gradingScale
            : [
                  {
                      grade: "A",
                      points: 5
                  },
                  {
                      grade: "B",
                      points: 4
                  },
                  {
                      grade: "C",
                      points: 3
                  },
                  {
                      grade: "D",
                      points: 2
                  },
                  {
                      grade: "E",
                      points: 1
                  },
                  {
                      grade: "F",
                      points: 0
                  }
              ];

    let totalUnits = 0;
    let totalGradePoints = 0;

    const processed = courses.map(
        course => {
            const units =
                Number(
                    course.creditUnits
                );

            if (
                !Number.isFinite(units) ||
                units <= 0
            ) {
                throw new Error(
                    "Invalid credit units."
                );
            }

            const grade =
                String(
                    course.grade || ""
                ).toUpperCase();

            const found =
                scale.find(
                    item =>
                        String(
                            item.grade
                        ).toUpperCase() ===
                        grade
                );

            if (!found) {
                throw new Error(
                    `Grade ${grade} is not present in the grading scale.`
                );
            }

            const gradePoints =
                Number(found.points);

            totalUnits += units;

            totalGradePoints +=
                units * gradePoints;

            return {
                courseCode:
                    safeText(
                        course.courseCode,
                        50
                    ),
                courseTitle:
                    safeText(
                        course.courseTitle,
                        200
                    ),
                creditUnits: units,
                grade,
                gradePoints,
                qualityPoints:
                    units * gradePoints
            };
        }
    );

    const gpa =
        totalUnits > 0
            ? totalGradePoints /
              totalUnits
            : 0;

    return {
        courses: processed,
        totalUnits,
        totalGradePoints,
        gpa:
            Math.round(gpa * 100) /
            100
    };
}

app.post(
    "/api/v1/gpa/calculate",
    requireAuth,
    (req, res) => {
        try {
            const result =
                calculateGPA(
                    req.body.courses,
                    req.body.gradingScale
                );

            return sendSuccess(res, result);
        } catch (error) {
            return sendError(
                res,
                "GPA_CALCULATION_ERROR",
                error.message
            );
        }
    }
);

app.get(
    "/api/v1/gpa",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const records =
            db.gpaRecords
                .filter(
                    r =>
                        r.userId ===
                        req.user.id
                )
                .sort(
                    (a, b) =>
                        new Date(b.createdAt) -
                        new Date(a.createdAt)
                );

        return sendSuccess(res, {
            records
        });
    }
);

app.post(
    "/api/v1/gpa/save",
    requireAuth,
    (req, res) => {
        try {
            const result =
                calculateGPA(
                    req.body.courses,
                    req.body.gradingScale
                );

            const record = {
                id: generateId("gpa"),
                userId: req.user.id,
                semester:
                    safeText(
                        req.body.semester,
                        100
                    ),
                session:
                    safeText(
                        req.body.session,
                        100
                    ),
                ...result,
                createdAt:
                    new Date().toISOString()
            };

            updateDatabase(db => {
                db.gpaRecords.push(record);
            });

            return sendSuccess(
                res,
                { record },
                201
            );
        } catch (error) {
            return sendError(
                res,
                "GPA_SAVE_ERROR",
                error.message
            );
        }
    }
);

/*
============================================================
 WALLET
============================================================
*/

app.get(
    "/api/v1/wallet",
    requireAuth,
    (req, res) => {
        return sendSuccess(res, {
            wallet: getWallet(
                req.user.id
            )
        });
    }
);

app.get(
    "/api/v1/wallet/transactions",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const transactions =
            db.walletTransactions
                .filter(
                    tx =>
                        tx.userId ===
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

        return sendSuccess(res, {
            transactions
        });
    }
);

/*
============================================================
 REFERRALS
============================================================
*/

function generateReferralCode(user) {
    return (
        "DENEX-" +
        crypto
            .createHash("sha256")
            .update(
                user.id +
                    SESSION_SECRET
            )
            .digest("hex")
            .slice(0, 8)
            .toUpperCase()
    );
}

function applyReferralCodeInternal(
    newUserId,
    referralCode
) {
    const db = readDatabase();

    const newUser =
        db.users.find(
            u => u.id === newUserId
        );

    if (!newUser) {
        return {
            success: false,
            message: "User not found."
        };
    }

    const normalizedCode =
        String(referralCode)
            .trim()
            .toUpperCase();

    const referrer =
        db.users.find(
            u =>
                generateReferralCode(u) ===
                normalizedCode
        );

    if (!referrer) {
        return {
            success: false,
            message:
                "Invalid referral code."
        };
    }

    if (
        referrer.id === newUserId
    ) {
        return {
            success: false,
            message:
                "Self-referral is not allowed."
        };
    }

    const existing =
        db.referrals.find(
            r =>
                r.referredUserId ===
                newUserId
        );

    if (existing) {
        return {
            success: false,
            message:
                "Referral has already been applied."
        };
    }

    const referral = {
        id: generateId("referral"),
        referrerUserId:
            referrer.id,
        referredUserId:
            newUserId,
        code: normalizedCode,
        status: "pending",
        createdAt:
            new Date().toISOString()
    };

    updateDatabase(database => {
        database.referrals.push(
            referral
        );
    });

    return {
        success: true,
        referral
    };
}

app.get(
    "/api/v1/referrals",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const code =
            generateReferralCode(
                req.user
            );

        const referrals =
            db.referrals.filter(
                r =>
                    r.referrerUserId ===
                        req.user.id ||
                    r.referredUserId ===
                        req.user.id
            );

        return sendSuccess(res, {
            referralCode: code,
            referrals
        });
    }
);

app.post(
    "/api/v1/referrals/apply",
    requireAuth,
    (req, res) => {
        const result =
            applyReferralCodeInternal(
                req.user.id,
                safeText(
                    req.body.referralCode,
                    50
                )
            );

        if (!result.success) {
            return sendError(
                res,
                "REFERRAL_ERROR",
                result.message
            );
        }

        return sendSuccess(res, {
            referral: result.referral
        });
    }
);

/*
============================================================
 PREMIUM PLANS
============================================================
*/

const PREMIUM_PLANS = [
    {
        id: "weekly",
        name: "Weekly Premium",
        durationDays: 7,
        prices: {
            NGN: 1000,
            USD: 2,
            GBP: 2,
            EUR: 2
        }
    },
    {
        id: "monthly",
        name: "Monthly Premium",
        durationDays: 30,
        prices: {
            NGN: 3000,
            USD: 5,
            GBP: 5,
            EUR: 5
        }
    },
    {
        id: "quarterly",
        name: "Quarterly Premium",
        durationDays: 90,
        prices: {
            NGN: 7500,
            USD: 12,
            GBP: 12,
            EUR: 12
        }
    },
    {
        id: "annual",
        name: "Annual Premium",
        durationDays: 365,
        prices: {
            NGN: 25000,
            USD: 40,
            GBP: 40,
            EUR: 40
        }
    }
];

function getCurrentSubscription(userId) {
    const db = readDatabase();

    const subscription =
        db.subscriptions
            .filter(
                s =>
                    s.userId ===
                    userId
            )
            .sort(
                (a, b) =>
                    new Date(b.createdAt) -
                    new Date(a.createdAt)
            )[0];

    if (!subscription) {
        return null;
    }

    if (
        subscription.status ===
            "active" &&
        isExpired(
            subscription.expiryDate
        )
    ) {
        updateDatabase(database => {
            const target =
                database.subscriptions.find(
                    s =>
                        s.id ===
                        subscription.id
                );

            if (target) {
                target.status =
                    "expired";
            }

            const user =
                database.users.find(
                    u =>
                        u.id ===
                        userId
                );

            if (user) {
                user.subscriptionStatus =
                    "free";
            }
        });

        return {
            ...subscription,
            status: "expired"
        };
    }

    return subscription;
}

app.get(
    "/api/v1/subscriptions",
    (req, res) => {
        return sendSuccess(res, {
            plans: PREMIUM_PLANS,
            currencies: [
                "NGN",
                "USD",
                "GBP",
                "EUR"
            ]
        });
    }
);

app.get(
    "/api/v1/subscriptions/me",
    requireAuth,
    (req, res) => {
        return sendSuccess(res, {
            subscription:
                getCurrentSubscription(
                    req.user.id
                )
        });
    }
);

/*
============================================================
 PAYMENT ARCHITECTURE
============================================================
*/

app.post(
    "/api/v1/premium/upgrade",
    requireAuth,
    (req, res) => {
        const {
            planId,
            currency = req.user.currency ||
                "NGN"
        } = req.body || {};

        const plan =
            PREMIUM_PLANS.find(
                p =>
                    p.id === planId
            );

        if (!plan) {
            return sendError(
                res,
                "INVALID_PLAN",
                "Premium plan not found."
            );
        }

        const amount =
            plan.prices[
                String(
                    currency
                ).toUpperCase()
            ];

        if (
            amount === undefined
        ) {
            return sendError(
                res,
                "UNSUPPORTED_CURRENCY",
                "This currency is not configured for the selected plan."
            );
        }

        /*
         * This endpoint creates an internal pending
         * payment record.
         *
         * It DOES NOT activate premium.
         */
        const reference =
            "DENEX-" +
            Date.now() +
            "-" +
            crypto
                .randomBytes(5)
                .toString("hex")
                .toUpperCase();

        const payment = {
            id: generateId("payment"),
            userId: req.user.id,
            provider:
                process.env.PAYMENT_PROVIDER ||
                "not-configured",
            reference,
            planId,
            amount,
            currency:
                String(currency).toUpperCase(),
            status: "pending",
            createdAt:
                new Date().toISOString()
        };

        updateDatabase(db => {
            db.payments.push(
                payment
            );
        });

        return sendSuccess(res, {
            payment,
            message:
                "Payment initialized internally. Complete payment with the configured payment provider and wait for server-side verification."
        });
    }
);

app.get(
    "/api/v1/payments/:reference",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const payment =
            db.payments.find(
                p =>
                    p.reference ===
                        req.params
                            .reference &&
                    p.userId ===
                        req.user.id
            );

        if (!payment) {
            return sendError(
                res,
                "NOT_FOUND",
                "Payment not found.",
                404
            );
        }

        return sendSuccess(res, {
            payment
        });
    }
);

/*
============================================================
 PAYMENT VERIFICATION
============================================================
*/

function activateSubscriptionAfterVerifiedPayment(
    paymentId,
    providerReference,
    provider
) {
    return updateDatabase(db => {
        const payment =
            db.payments.find(
                p => p.id === paymentId
            );

        if (!payment) {
            throw new Error(
                "Payment not found."
            );
        }

        if (
            payment.status ===
            "verified"
        ) {
            return payment;
        }

        const plan =
            PREMIUM_PLANS.find(
                p =>
                    p.id ===
                    payment.planId
            );

        if (!plan) {
            throw new Error(
                "Premium plan not found."
            );
        }

        const start =
            new Date();

        const expiry =
            addDays(
                start,
                plan.durationDays
            );

        payment.status =
            "verified";
        payment.providerReference =
            providerReference;
        payment.provider =
            provider;
        payment.verifiedAt =
            new Date().toISOString();

        const subscription = {
            id: generateId(
                "subscription"
            ),
            userId:
                payment.userId,
            planId:
                payment.planId,
            provider,
            transactionReference:
                providerReference,
            paymentId:
                payment.id,
            startDate:
                start.toISOString(),
            expiryDate:
                expiry.toISOString(),
            status: "active",
            createdAt:
                new Date().toISOString()
        };

        db.subscriptions.push(
            subscription
        );

        const user =
            db.users.find(
                u =>
                    u.id ===
                    payment.userId
            );

        if (user) {
            user.subscriptionStatus =
                "premium";
        }

        return subscription;
    });
}

app.post(
    "/api/v1/subscriptions/verify",
    requireAuth,
    (req, res) => {
        /*
         * Generic verification hook.
         *
         * Production provider verification must verify
         * the provider transaction server-side before
         * calling activation.
         *
         * Do not pass "verified: true" from the browser
         * and trust it.
         */

        return sendError(
            res,
            "PROVIDER_VERIFICATION_REQUIRED",
            "Payment verification must be performed against the configured payment provider before premium access is activated."
        );
    }
);

/*
============================================================
 GENERIC WEBHOOK
============================================================
*/

app.post(
    "/api/v1/payments/webhook",
    (req, res) => {
        /*
         * Provider-specific signature verification belongs
         * here.

         * Never activate premium merely because this endpoint
         * receives a request.
         */

        const provider =
            process.env.PAYMENT_PROVIDER ||
            "";

        if (!provider) {
            return sendError(
                res,
                "PAYMENT_NOT_CONFIGURED",
                "Payment provider is not configured."
            );
        }

        /*
         * This generic implementation intentionally refuses
         * to activate subscriptions without provider-specific
         * verification.
         */
        return sendError(
            res,
            "WEBHOOK_VERIFICATION_REQUIRED",
            "Provider-specific webhook signature verification has not been configured."
        );
    }
);

/*
============================================================
 PHARMACOPOEIA
============================================================
*/

app.get(
    "/api/v1/pharmacopoeia",
    (req, res) => {
        const db = readDatabase();

        return sendSuccess(res, {
            resources:
                db.pharmacopoeia
        });
    }
);

app.get(
    "/api/v1/pharmacopoeia/:id",
    (req, res) => {
        const db = readDatabase();

        const item =
            db.pharmacopoeia.find(
                p =>
                    p.id ===
                    req.params.id
            );

        if (!item) {
            return sendError(
                res,
                "NOT_FOUND",
                "Pharmacopoeia resource not found.",
                404
            );
        }

        return sendSuccess(res, {
            resource: item,
            copyrightNotice:
                "DENexpharm provides original educational explanations and links. It does not reproduce copyrighted pharmacopoeial monographs."
        });
    }
);

/*
============================================================
 LIBRARY
============================================================
*/

app.get(
    "/api/v1/library",
    (req, res) => {
        const db = readDatabase();

        let resources =
            db.library;

        if (req.query.subject) {
            resources =
                resources.filter(
                    r =>
                        String(
                            r.subject
                        ).toLowerCase() ===
                        String(
                            req.query.subject
                        ).toLowerCase()
                );
        }

        if (req.query.type) {
            resources =
                resources.filter(
                    r =>
                        r.resourceType ===
                        req.query.type
                );
        }

        if (req.query.search) {
            const term =
                String(
                    req.query.search
                ).toLowerCase();

            resources =
                resources.filter(
                    r =>
                        [
                            r.title,
                            r.subject,
                            r.description,
                            r.author
                        ]
                            .join(" ")
                            .toLowerCase()
                            .includes(
                                term
                            )
                );
        }

        return sendSuccess(res, {
            resources
        });
    }
);

app.get(
    "/api/v1/library/:id",
    (req, res) => {
        const db = readDatabase();

        const resource =
            db.library.find(
                r =>
                    r.id ===
                    req.params.id
            );

        if (!resource) {
            return sendError(
                res,
                "NOT_FOUND",
                "Library resource not found.",
                404
            );
        }

        return sendSuccess(res, {
            resource
        });
    }
);

/*
============================================================
 LANGUAGE ASSISTANT
============================================================
*/

app.get(
    "/api/v1/language",
    (req, res) => {
        const db = readDatabase();

        return sendSuccess(res, {
            languages: db.languages,
            educationalNotice:
                "Translations are educational and should be professionally verified before clinical use."
        });
    }
);

app.get(
    "/api/v1/language/:id",
    (req, res) => {
        const db = readDatabase();

        const language =
            db.languages.find(
                l =>
                    l.id ===
                    req.params.id
            );

        if (!language) {
            return sendError(
                res,
                "NOT_FOUND",
                "Language not found.",
                404
            );
        }

        return sendSuccess(res, {
            language
        });
    }
);

app.get(
    "/api/v1/language/:id/phrases",
    (req, res) => {
        const db = readDatabase();

        const language =
            db.languages.find(
                l =>
                    l.id ===
                    req.params.id
            );

        if (!language) {
            return sendError(
                res,
                "NOT_FOUND",
                "Language not found.",
                404
            );
        }

        let phrases =
            db.languagePhrases;

        if (req.query.category) {
            phrases =
                phrases.filter(
                    p =>
                        p.category ===
                        req.query.category
                );
        }

        return sendSuccess(res, {
            language,
            phrases
        });
    }
);

/*
============================================================
 ANALYTICS
============================================================
*/

app.get(
    "/api/v1/analytics",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const results =
            db.quizResults.filter(
                r =>
                    r.userId ===
                    req.user.id
            );

        const totalQuestions =
            results.reduce(
                (sum, r) =>
                    sum +
                    Number(
                        r.totalQuestions ||
                            0
                    ),
                0
            );

        const correct =
            results.reduce(
                (sum, r) =>
                    sum +
                    Number(
                        r.correct || 0
                    ),
                0
            );

        const accuracy =
            totalQuestions
                ? Math.round(
                      (correct /
                          totalQuestions) *
                          10000
                  ) / 100
                : 0;

        const subjectStats = {};

        for (const result of results) {
            for (const item of
                result.questionResults ||
                []) {
                const question =
                    db.questions.find(
                        q =>
                            q.id ===
                            item.questionId
                    );

                if (!question)
                    continue;

                if (
                    !subjectStats[
                        question.subject
                    ]
                ) {
                    subjectStats[
                        question.subject
                    ] = {
                        attempted: 0,
                        correct: 0
                    };
                }

                subjectStats[
                    question.subject
                ].attempted++;

                if (item.correct) {
                    subjectStats[
                        question.subject
                    ].correct++;
                }
            }
        }

        const subjects =
            Object.entries(
                subjectStats
            ).map(
                ([
                    subject,
                    stats
                ]) => ({
                    subject,
                    attempted:
                        stats.attempted,
                    correct:
                        stats.correct,
                    accuracy:
                        Math.round(
                            (stats.correct /
                                stats.attempted) *
                                10000
                        ) / 100
                })
            );

        const weakAreas =
            subjects
                .filter(
                    s =>
                        s.accuracy < 70
                )
                .sort(
                    (a, b) =>
                        a.accuracy -
                        b.accuracy
                );

        return sendSuccess(res, {
            overview: {
                quizzes:
                    results.length,
                questions:
                    totalQuestions,
                correct,
                accuracy,
                streak:
                    req.user.streak ||
                    0,
                xp:
                    req.user.xp || 0,
                level:
                    req.user.level || 1
            },
            subjects,
            weakAreas
        });
    }
);

/*
============================================================
 SEARCH
============================================================
*/

app.get(
    "/api/v1/search",
    (req, res) => {
        const term =
            String(
                req.query.q || ""
            )
                .trim()
                .toLowerCase();

        if (!term) {
            return sendSuccess(res, {
                results: []
            });
        }

        const db = readDatabase();

        const results = [];

        for (const q of
            db.questions.filter(
                x =>
                    x.published !==
                    false
            )) {
            const haystack =
                [
                    q.question,
                    q.subject,
                    q.topic,
                    q.subtopic,
                    ...(q.tags || [])
                ]
                    .join(" ")
                    .toLowerCase();

            if (
                haystack.includes(
                    term
                )
            ) {
                results.push({
                    type: "question",
                    id: q.id,
                    title:
                        q.question,
                    subject:
                        q.subject,
                    topic:
                        q.topic
                });
            }
        }

        for (const r of
            db.library) {
            const haystack =
                [
                    r.title,
                    r.subject,
                    r.description
                ]
                    .join(" ")
                    .toLowerCase();

            if (
                haystack.includes(
                    term
                )
            ) {
                results.push({
                    type: "library",
                    id: r.id,
                    title:
                        r.title,
                    subject:
                        r.subject
                });
            }
        }

        for (const p of
            db.pharmacopoeia) {
            const haystack =
                [
                    p.name,
                    p.shortName,
                    p.description,
                    ...(p.concepts || [])
                ]
                    .join(" ")
                    .toLowerCase();

            if (
                haystack.includes(
                    term
                )
            ) {
                results.push({
                    type:
                        "pharmacopoeia",
                    id: p.id,
                    title:
                        p.name
                });
            }
        }

        for (const phrase of
            db.languagePhrases) {
            const haystack =
                [
                    phrase.english,
                    phrase.category,
                    ...Object.values(
                        phrase.translations ||
                            {}
                    )
                ]
                    .join(" ")
                    .toLowerCase();

            if (
                haystack.includes(
                    term
                )
            ) {
                results.push({
                    type: "language",
                    id: phrase.id,
                    title:
                        phrase.english
                });
            }
        }

        return sendSuccess(res, {
            query: term,
            results:
                results.slice(0, 100)
        });
    }
);

/*
============================================================
 BOOKMARKS
============================================================
*/

app.get(
    "/api/v1/bookmarks",
    requireAuth,
    (req, res) => {
        const db = readDatabase();

        const bookmarks =
            db.bookmarks.filter(
                b =>
                    b.userId ===
                    req.user.id
            );

        return sendSuccess(res, {
            bookmarks
        });
    }
);

app.post(
    "/api/v1/bookmarks",
    requireAuth,
    (req, res) => {
        const {
            type,
            resourceId
        } = req.body || {};

        if (
            !type ||
            !resourceId
        ) {
            return sendError(
                res,
                "INVALID_REQUEST",
                "type and resourceId are required."
            );
        }

        const allowedTypes = [
            "question",
            "library",
            "pharmacopoeia",
            "language"
        ];

        if (
            !allowedTypes.includes(
                type
            )
        ) {
            return sendError(
                res,
                "INVALID_TYPE",
                "Unsupported bookmark type."
            );
        }

        const db = readDatabase();

        const exists =
            db.bookmarks.some(
                b =>
                    b.userId ===
                        req.user.id &&
                    b.type === type &&
                    b.resourceId ===
                        resourceId
            );

        if (exists) {
            return sendError(
                res,
                "ALREADY_BOOKMARKED",
                "This item is already bookmarked."
            );
        }

        const bookmark = {
            id: generateId(
                "bookmark"
            ),
            userId: req.user.id,
            type,
            resourceId,
            createdAt:
                new Date().toISOString()
        };

        updateDatabase(database => {
            database.bookmarks.push(
                bookmark
            );
        });

        return sendSuccess(
            res,
            { bookmark },
            201
        );
    }
);

app.delete(
    "/api/v1/bookmarks/:id",
    requireAuth,
    (req, res) => {
        let removed = false;

        updateDatabase(db => {
            const before =
                db.bookmarks.length;

            db.bookmarks =
                db.bookmarks.filter(
                    b =>
                        !(
                            b.id ===
                                req.params.id &&
                            b.userId ===
                                req.user.id
                        )
                );

            removed =
                db.bookmarks.length <
                before;
        });

        if (!removed) {
            return sendError(
                res,
                "NOT_FOUND",
                "Bookmark not found.",
                404
            );
        }

        return sendSuccess(res, {
            message:
                "Bookmark removed."
        });
    }
);

/*
============================================================
 FEEDBACK
============================================================
*/

app.post(
    "/api/v1/feedback",
    requireAuth,
    (req, res) => {
        const {
            type,
            message,
            questionId,
            resourceId
        } = req.body || {};

        const allowed = [
            "wrong-question",
            "wrong-answer",
            "typo",
            "bad-explanation",
            "broken-resource",
            "translation",
            "technical",
            "suggestion"
        ];

        if (
            !allowed.includes(type)
        ) {
            return sendError(
                res,
                "INVALID_TYPE",
                "Invalid feedback type."
            );
        }

        if (
            !message ||
            String(message).trim().length <
                3
        ) {
            return sendError(
                res,
                "INVALID_MESSAGE",
                "Please provide meaningful feedback."
            );
        }

        const feedback = {
            id: generateId(
                "feedback"
            ),
            userId: req.user.id,
            type,
            message:
                safeText(message, 3000),
            questionId:
                questionId || null,
            resourceId:
                resourceId || null,
            status: "open",
            createdAt:
                new Date().toISOString()
        };

        updateDatabase(db => {
            db.feedback.push(
                feedback
            );
        });

        return sendSuccess(
            res,
            {
                feedback
            },
            201
        );
    }
);

/*
============================================================
 PUBLIC STATISTICS
============================================================
*/

app.get(
    "/api/v1/stats/public",
    (req, res) => {
        const db = readDatabase();

        const countries =
            new Set(
                db.users
                    .map(
                        u => u.country
                    )
                    .filter(Boolean)
            );

        return sendSuccess(res, {
            registeredStudents:
                db.users.length,
            questions:
                db.questions.filter(
                    q =>
                        q.published !==
                        false
                ).length,
            subjects:
                SUBJECTS.length,
            countriesRepresented:
                countries.size,
            quizzesCompleted:
                db.quizResults.length,
            battlesCompleted:
                db.battles.filter(
                    b =>
                        b.status ===
                        "completed"
                ).length
        });
    }
);

/*
============================================================
 ADMIN - QUESTIONS
============================================================
*/

app.get(
    "/api/v1/admin/questions",
    requireAuth,
    requireAdmin,
    (req, res) => {
        const db = readDatabase();

        const {
            page,
            limit
        } = parsePage(req);

        const result =
            paginate(
                db.questions,
                page,
                limit
            );

        return sendSuccess(res, result);
    }
);

app.post(
    "/api/v1/admin/questions",
    requireAuth,
    requireAdmin,
    (req, res) => {
        const body =
            req.body || {};

        if (
            !body.question ||
            !Array.isArray(
                body.options
            ) ||
            body.options.length < 2
        ) {
            return sendError(
                res,
                "INVALID_QUESTION",
                "Question and at least two options are required."
            );
        }

        const correctAnswer =
            Number(
                body.correctAnswer
            );

        if (
            !Number.isInteger(
                correctAnswer
            ) ||
            correctAnswer < 0 ||
            correctAnswer >=
                body.options.length
        ) {
            return sendError(
                res,
                "INVALID_ANSWER",
                "correctAnswer must reference a valid option."
            );
        }

        const question = {
            id:
                safeText(
                    body.id,
                    100
                ) ||
                generateId(
                    "question"
                ),

            subject:
                safeText(
                    body.subject,
                    150
                ),

            topic:
                safeText(
                    body.topic,
                    150
                ),

            subtopic:
                safeText(
                    body.subtopic,
                    150
                ),

            difficulty:
                safeText(
                    body.difficulty,
                    30
                ) || "medium",

            questionType:
                safeText(
                    body.questionType,
                    50
                ) || "mcq",

            question:
                safeText(
                    body.question,
                    3000
                ),

            options:
                body.options.map(
                    o =>
                        safeText(
                            o,
                            1000
                        )
                ),

            correctAnswer,

            explanation:
                safeText(
                    body.explanation,
                    5000
                ),

            whyCorrect:
                safeText(
                    body.whyCorrect,
                    5000
                ),

            optionExplanations:
                Array.isArray(
                    body.optionExplanations
                )
                    ? body.optionExplanations.map(
                          o =>
                              safeText(
                                  o,
                                  3000
                              )
                      )
                    : [],

            learningPoints:
                Array.isArray(
                    body.learningPoints
                )
                    ? body.learningPoints.map(
                          o =>
                              safeText(
                                  o,
                                  1000
                              )
                      )
                    : [],

            references:
                Array.isArray(
                    body.references
                )
                    ? body.references.map(
                          o =>
                              safeText(
                                  o,
                                  1000
                              )
                      )
                    : [],

            curriculum:
                safeText(
                    body.curriculum,
                    100
                ) || "international",

            yearLevel:
                safeText(
                    body.yearLevel,
                    50
                ) || "all",

            semester:
                safeText(
                    body.semester,
                    50
                ) || "all",

            classification:
                safeText(
                    body.classification,
                    50
                ) || "theory",

            tags:
                Array.isArray(
                    body.tags
                )
                    ? body.tags.map(
                          t =>
                              safeText(
                                  t,
                                  100
                              )
                      )
                    : [],

            sourceType:
                body.sourceType ===
                "generated"
                    ? "generated"
                    : "curated",

            published:
                body.published !==
                false,

            createdAt:
                new Date().toISOString(),

            updatedAt:
                new Date().toISOString()
        };

        updateDatabase(db => {
            db.questions.push(
                question
            );
        });

        createAuditLog({
            actorUserId:
                req.user.id,
            action:
                "question_created",
            targetType:
                "question",
            targetId:
                question.id
        });

        return sendSuccess(
            res,
            {
                question
            },
            201
        );
    }
);

app.put(
    "/api/v1/admin/questions/:id",
    requireAuth,
    requireAdmin,
    (req, res) => {
        let updated = null;

        updateDatabase(db => {
            const question =
                db.questions.find(
                    q =>
                        q.id ===
                        req.params.id
                );

            if (!question) {
                return;
            }

            const fields = [
                "subject",
                "topic",
                "subtopic",
                "difficulty",
                "questionType",
                "question",
                "explanation",
                "whyCorrect",
                "curriculum",
                "yearLevel",
                "semester",
                "classification",
                "sourceType"
            ];

