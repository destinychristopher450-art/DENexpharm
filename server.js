"use strict";

/*
============================================================
DENexpharm
FULL STACK PHARMACY LEARNING, GPA, COMPETITION & STUDENT PLATFORM
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
- Timed Battles
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
This is an MVP backend using JSON storage.

For serious production deployment with many concurrent users,
move the database to PostgreSQL/Supabase/Neon or another
proper database.

Payment activation is intentionally not trusted from the
browser. A real Paystack/Flutterwave webhook should verify
payments before activating premium subscriptions.
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

if (
    IS_PRODUCTION &&
    SESSION_SECRET === "CHANGE_THIS_SESSION_SECRET_IN_PRODUCTION"
) {
    console.warn(
        "WARNING: SESSION_SECRET has not been changed for production."
    );
}

/* ============================================================
   DATABASE
============================================================ */

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
        if (Array.isArray(DEFAULT_DATABASE[key])) {
            if (!Array.isArray(result[key])) {
                result[key] = [];
            }
        }
    }

    if (!result.meta || typeof result.meta !== "object") {
        result.meta = {
            app: APP_NAME,
            version: APP_VERSION,
            contentYear: CONTENT_YEAR,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString()
        };
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

        const backupFile =
            DB_FILE.replace(".json", "") +
            ".corrupt-" +
            Date.now() +
            ".json";

        try {
            fs.copyFileSync(DB_FILE, backupFile);
        } catch (_) {}

        const fresh = normalizeDatabase(DEFAULT_DATABASE);
        writeDatabase(fresh);
        return fresh;
    }
}

function writeDatabase(db) {
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }

    const normalized = normalizeDatabase(db);

    const tempFile = DB_FILE + ".tmp";

    fs.writeFileSync(
        tempFile,
        JSON.stringify(normalized, null, 2),
        "utf8"
    );

    fs.renameSync(tempFile, DB_FILE);

    return normalized;
}

function updateDatabase(mutator) {
    const db = readDatabase();

    const result = mutator(db);

    writeDatabase(db);

    return result;
}

/* ============================================================
   GENERAL HELPERS
============================================================ */

function sendSuccess(res, data = {}, message = "Success", status = 200) {
    return res.status(status).json({
        success: true,
        message,
        data
    });
}

function sendError(
    res,
    message = "Something went wrong",
    status = 400,
    code = "ERROR"
) {
    return res.status(status).json({
        success: false,
        message,
        code
    });
}

function generateId(prefix = "id") {
    return (
        prefix +
        "_" +
        Date.now().toString(36) +
        "_" +
        crypto.randomBytes(5).toString("hex")
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

function safeText(value, maxLength = 1000) {
    if (value === undefined || value === null) {
        return "";
    }

    return String(value).trim().slice(0, maxLength);
}

function normalizeEmail(email) {
    return safeText(email, 200).toLowerCase();
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 8 &&
        password.length <= 200
    );
}

function isValidUsername(username) {
    return /^[a-zA-Z0-9_.-]{3,30}$/.test(username);
}

function nowISO() {
    return new Date().toISOString();
}

function addDays(date, days) {
    const d = new Date(date);
    d.setDate(d.getDate() + days);
    return d;
}

function todayKey() {
    return new Date().toISOString().slice(0, 10);
}

function clampNumber(value, min, max, fallback = min) {
    const number = Number(value);

    if (!Number.isFinite(number)) {
        return fallback;
    }

    return Math.max(min, Math.min(max, number));
}

function secureCompare(a, b) {
    const bufferA = Buffer.from(String(a));
    const bufferB = Buffer.from(String(b));

    if (bufferA.length !== bufferB.length) {
        return false;
    }

    return crypto.timingSafeEqual(bufferA, bufferB);
}

function paginate(items, page, pageSize) {
    const safePage = Math.max(1, Number(page) || 1);
    const safeSize = Math.min(
        MAX_PAGE_SIZE,
        Math.max(1, Number(pageSize) || 20)
    );

    const total = items.length;
    const totalPages = Math.max(1, Math.ceil(total / safeSize));

    const start = (safePage - 1) * safeSize;

    return {
        items: items.slice(start, start + safeSize),
        pagination: {
            page: safePage,
            pageSize: safeSize,
            total,
            totalPages
        }
    };
}

/* ============================================================
   PASSWORD SECURITY
============================================================ */

const PASSWORD_ITERATIONS = 210000;
const PASSWORD_KEY_LENGTH = 64;
const PASSWORD_DIGEST = "sha512";

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString("hex");

    const hash = crypto
        .pbkdf2Sync(
            password,
            salt,
            PASSWORD_ITERATIONS,
            PASSWORD_KEY_LENGTH,
            PASSWORD_DIGEST
        )
        .toString("hex");

    return {
        salt,
        hash,
        iterations: PASSWORD_ITERATIONS
    };
}

function verifyPassword(password, stored) {
    if (!stored || !stored.hash || !stored.salt) {
        return false;
    }

    try {
        const iterations =
            Number(stored.iterations) || PASSWORD_ITERATIONS;

        const derived = crypto.pbkdf2Sync(
            password,
            stored.salt,
            iterations,
            PASSWORD_KEY_LENGTH,
            PASSWORD_DIGEST
        );

        const storedBuffer = Buffer.from(stored.hash, "hex");

        if (derived.length !== storedBuffer.length) {
            return false;
        }

        return crypto.timingSafeEqual(derived, storedBuffer);
    } catch (_) {
        return false;
    }
}

/* ============================================================
   RATE LIMITER
============================================================ */

const rateLimitStore = new Map();

function rateLimit(options = {}) {
    const windowMs = options.windowMs || 15 * 60 * 1000;
    const max = options.max || 300;

    return function rateLimitMiddleware(req, res, next) {
        const ip =
            req.ip ||
            req.headers["x-forwarded-for"] ||
            req.socket.remoteAddress ||
            "unknown";

        const key = `${ip}:${req.path}`;

        const now = Date.now();

        let record = rateLimitStore.get(key);

        if (!record || now > record.resetAt) {
            record = {
                count: 0,
                resetAt: now + windowMs
            };
        }

        record.count += 1;

        rateLimitStore.set(key, record);

        if (record.count > max) {
            return sendError(
                res,
                "Too many requests. Please try again later.",
                429,
                "RATE_LIMITED"
            );
        }

        next();
    };
}

/* ============================================================
   SUBJECTS
============================================================ */

const SUBJECTS = [
    {
        id: "pharmacology",
        name: "Pharmacology",
        category: "Core Pharmacy"
    },
    {
        id: "pharmaceutics",
        name: "Pharmaceutics",
        category: "Core Pharmacy"
    },
    {
        id: "pharmacognosy",
        name: "Pharmacognosy",
        category: "Core Pharmacy"
    },
    {
        id: "pharmaceutical-microbiology",
        name: "Pharmaceutical Microbiology",
        category: "Core Pharmacy"
    },
    {
        id: "pharmaceutical-chemistry",
        name: "Pharmaceutical Chemistry",
        category: "Core Pharmacy"
    },
    {
        id: "pharmaceutical-physical-chemistry",
        name: "Pharmaceutical Physical Chemistry",
        category: "Core Pharmacy"
    },
    {
        id: "pharmacy-practice",
        name: "Pharmacy Practice",
        category: "Clinical"
    },
    {
        id: "clinical-pharmacy",
        name: "Clinical Pharmacy",
        category: "Clinical"
    },
    {
        id: "anatomy",
        name: "Anatomy",
        category: "Health Sciences"
    },
    {
        id: "physiology",
        name: "Physiology",
        category: "Health Sciences"
    },
    {
        id: "biochemistry",
        name: "Biochemistry",
        category: "Health Sciences"
    },
    {
        id: "pharmaceutical-entrepreneurship",
        name: "Pharmaceutical Entrepreneurship",
        category: "Professional"
    },
    {
        id: "public-health",
        name: "Public Health",
        category: "Professional"
    },
    {
        id: "medicinal-chemistry",
        name: "Medicinal Chemistry",
        category: "Core Pharmacy"
    },
    {
        id: "pharmaceutical-analysis",
        name: "Pharmaceutical Analysis",
        category: "Core Pharmacy"
    },
    {
        id: "pharmaceutical-technology",
        name: "Pharmaceutical Technology",
        category: "Core Pharmacy"
    },
    {
        id: "toxicology",
        name: "Toxicology",
        category: "Clinical"
    },
    {
        id: "immunology",
        name: "Immunology",
        category: "Health Sciences"
    },
    {
        id: "pathophysiology",
        name: "Pathophysiology",
        category: "Health Sciences"
    },
    {
        id: "drug-delivery",
        name: "Drug Delivery Systems",
        category: "Core Pharmacy"
    },
    {
        id: "pharmacotherapy",
        name: "Pharmacotherapy",
        category: "Clinical"
    },
    {
        id: "hospital-pharmacy",
        name: "Hospital Pharmacy",
        category: "Professional"
    },
    {
        id: "community-pharmacy",
        name: "Community Pharmacy",
        category: "Professional"
    },
    {
        id: "industrial-pharmacy",
        name: "Industrial Pharmacy",
        category: "Professional"
    },
    {
        id: "regulatory-pharmacy",
        name: "Regulatory Pharmacy",
        category: "Professional"
    },
    {
        id: "biopharmaceutics",
        name: "Biopharmaceutics",
        category: "Core Pharmacy"
    },
    {
        id: "pharmacokinetics",
        name: "Pharmacokinetics",
        category: "Core Pharmacy"
    },
    {
        id: "clinical-biochemistry",
        name: "Clinical Biochemistry",
        category: "Clinical"
    },
    {
        id: "pharmaceutical-biotechnology",
        name: "Pharmaceutical Biotechnology",
        category: "Core Pharmacy"
    },
    {
        id: "health-economics",
        name: "Health Economics",
        category: "Professional"
    },
    {
        id: "pharmacy-law-ethics",
        name: "Pharmacy Law and Ethics",
        category: "Professional"
    },
    {
        id: "research-methods",
        name: "Research Methods",
        category: "Professional"
    },
    {
        id: "statistics",
        name: "Statistics / Biostatistics",
        category: "Health Sciences"
    },
    {
        id: "pharmacy-management",
        name: "Pharmacy Management",
        category: "Professional"
    },
    {
        id: "pharmaceutical-calculations",
        name: "Pharmaceutical Calculations",
        category: "Core Pharmacy"
    }
];

/* ============================================================
   STARTER QUESTION BANK
============================================================ */

const STARTER_QUESTIONS = [
    {
        id: "q_pharm_001",
        subject: "Pharmacology",
        topic: "Autonomic Pharmacology",
        subtopic: "Cholinergic receptors",
        difficulty: "easy",
        questionType: "mcq",
        question: "Which receptor is primarily responsible for parasympathetic effects at many effector organs?",
        options: [
            "Nicotinic receptor",
            "Muscarinic receptor",
            "Alpha-1 receptor",
            "Beta-2 receptor"
        ],
        correctAnswer: 1,
        explanation:
            "Muscarinic receptors mediate many parasympathetic effects at target organs.",
        whyCorrect:
            "Postganglionic parasympathetic nerves commonly release acetylcholine, which acts on muscarinic receptors at effector organs.",
        optionExplanations: [
            "Nicotinic receptors are important at autonomic ganglia and the neuromuscular junction.",
            "Muscarinic receptors mediate many parasympathetic effector-organ responses.",
            "Alpha-1 receptors are adrenergic receptors.",
            "Beta-2 receptors are adrenergic receptors associated with effects such as bronchodilation."
        ],
        learningPoints: [
            "Acetylcholine is the principal neurotransmitter of the parasympathetic system.",
            "Muscarinic receptors are found on many parasympathetic effector organs."
        ],
        references: [
            "Standard pharmacology textbooks",
            "Current pharmacology teaching resources"
        ],
        curriculum: "international",
        yearLevel: "200",
        semester: "1",
        classification: "core",
        tags: ["autonomic", "acetylcholine", "receptors"],
        sourceType: "curated",
        published: true,
        createdAt: nowISO(),
        updatedAt: nowISO()
    },

    {
        id: "q_pharm_002",
        subject: "Pharmaceutics",
        topic: "Solutions",
        subtopic: "Concentration",
        difficulty: "easy",
        questionType: "calculation",
        question:
            "How many grams of solute are required to prepare 100 mL of a 5% w/v solution?",
        options: [
            "0.5 g",
            "5 g",
            "10 g",
            "50 g"
        ],
        correctAnswer: 1,
        explanation:
            "A 5% w/v solution contains 5 g of solute in every 100 mL of solution.",
        whyCorrect:
            "Percentage weight/volume is expressed as grams of solute per 100 mL of solution.",
        optionExplanations: [
            "0.5 g corresponds to 0.5% w/v in 100 mL.",
            "5 g is correct for a 5% w/v solution in 100 mL.",
            "10 g would produce a 10% w/v solution in 100 mL.",
            "50 g would produce a much more concentrated solution."
        ],
        learningPoints: [
            "% w/v means grams per 100 mL.",
            "Always identify the type of percentage strength before calculating."
        ],
        references: [
            "Standard pharmaceutics textbooks",
            "Pharmaceutical calculations textbooks"
        ],
        curriculum: "international",
        yearLevel: "200",
        semester: "1",
        classification: "core",
        tags: ["solutions", "percentage", "calculation"],
        sourceType: "curated",
        published: true,
        createdAt: nowISO(),
        updatedAt: nowISO()
    },

    {
        id: "q_micro_001",
        subject: "Pharmaceutical Microbiology",
        topic: "Sterilization",
        subtopic: "Autoclave",
        difficulty: "easy",
        questionType: "mcq",
        question: "Which method commonly uses saturated steam under pressure for sterilization?",
        options: [
            "Autoclaving",
            "Filtration",
            "Dry heat sterilization",
            "Radiation"
        ],
        correctAnswer: 0,
        explanation:
            "Autoclaving uses saturated steam under pressure to achieve sterilization.",
        whyCorrect:
            "The combination of steam, pressure and temperature allows effective destruction of microorganisms including many bacterial spores.",
        optionExplanations: [
            "Autoclaving uses moist heat in the form of saturated steam under pressure.",
            "Filtration physically removes microorganisms rather than killing them.",
            "Dry heat uses hot air rather than saturated steam.",
            "Radiation uses ionizing or non-ionizing radiation depending on the application."
        ],
        learningPoints: [
            "Moist heat is generally more efficient than dry heat at comparable temperatures.",
            "Autoclaves are widely used for sterilizing suitable materials."
        ],
        references: [
            "Standard pharmaceutical microbiology textbooks"
        ],
        curriculum: "international",
        yearLevel: "200",
        semester: "1",
        classification: "core",
        tags: ["sterilization", "autoclave", "microbiology"],
        sourceType: "curated",
        published: true,
        createdAt: nowISO(),
        updatedAt: nowISO()
    },

    {
        id: "q_calc_001",
        subject: "Pharmaceutical Calculations",
        topic: "Percentage Strength",
        subtopic: "w/v",
        difficulty: "easy",
        questionType: "calculation",
        question:
            "What is the percentage w/v strength of a solution containing 10 g of solute in 200 mL?",
        options: [
            "2%",
            "5%",
            "10%",
            "20%"
        ],
        correctAnswer: 1,
        explanation:
            "Percentage w/v = grams of solute / mL of solution × 100. Therefore, 10/200 × 100 = 5%.",
        whyCorrect:
            "The calculation gives 5 g per 100 mL of solution.",
        optionExplanations: [
            "2% would correspond to 4 g in 200 mL.",
            "5% is correct.",
            "10% would require 20 g in 200 mL.",
            "20% would require 40 g in 200 mL."
        ],
        learningPoints: [
            "Percentage w/v = grams per 100 mL.",
            "Convert the given quantity to the 100 mL basis."
        ],
        references: [
            "Standard pharmaceutical calculations textbooks"
        ],
        curriculum: "international",
        yearLevel: "200",
        semester: "1",
        classification: "calculation",
        tags: ["calculations", "percentage", "w/v"],
        sourceType: "curated",
        published: true,
        createdAt: nowISO(),
        updatedAt: nowISO()
    },

    {
        id: "q_phys_001",
        subject: "Physiology",
        topic: "Blood",
        subtopic: "Red blood cells",
        difficulty: "easy",
        questionType: "mcq",
        question: "What is the major function of red blood cells?",
        options: [
            "Blood clotting",
            "Oxygen transport",
            "Antibody production",
            "Phagocytosis"
        ],
        correctAnswer: 1,
        explanation:
            "Red blood cells primarily transport oxygen through the body using hemoglobin.",
        whyCorrect:
            "Hemoglobin inside red blood cells binds oxygen and facilitates its transport.",
        optionExplanations: [
            "Platelets are primarily involved in clotting.",
            "Red blood cells transport oxygen.",
            "Antibody production is primarily associated with B lymphocytes and plasma cells.",
            "Phagocytosis is carried out by cells such as neutrophils and macrophages."
        ],
        learningPoints: [
            "Hemoglobin is the major oxygen-carrying protein in red blood cells.",
            "Red blood cells are specialized for gas transport."
        ],
        references: [
            "Standard physiology textbooks"
        ],
        curriculum: "international",
        yearLevel: "200",
        semester: "2",
        classification: "core",
        tags: ["blood", "RBC", "hemoglobin"],
        sourceType: "curated",
        published: true,
        createdAt: nowISO(),
        updatedAt: nowISO()
    }
];

/* ============================================================
   ACHIEVEMENTS
============================================================ */

const ACHIEVEMENTS = [
    {
        id: "first_quiz",
        name: "First Steps",
        description: "Complete your first quiz.",
        requirement: "quiz_count >= 1",
        rewardXP: 50,
        rewardCoins: 10,
        icon: "🎯"
    },
    {
        id: "questions_10",
        name: "Getting Started",
        description: "Answer at least 10 questions.",
        requirement: "questions >= 10",
        rewardXP: 100,
        rewardCoins: 25,
        icon: "📚"
    },
    {
        id: "questions_100",
        name: "Century Scholar",
        description: "Answer at least 100 questions.",
        requirement: "questions >= 100",
        rewardXP: 500,
        rewardCoins: 100,
        icon: "🏆"
    },
    {
        id: "perfect_score",
        name: "Perfect Score",
        description: "Complete a quiz with 100%.",
        requirement: "perfect_quiz >= 1",
        rewardXP: 250,
        rewardCoins: 50,
        icon: "⭐"
    },
    {
        id: "streak_7",
        name: "Seven Day Scholar",
        description: "Maintain a 7-day activity streak.",
        requirement: "streak >= 7",
        rewardXP: 200,
        rewardCoins: 40,
        icon: "🔥"
    },
    {
        id: "streak_30",
        name: "Thirty Day Scholar",
        description: "Maintain a 30-day activity streak.",
        requirement: "streak >= 30",
        rewardXP: 1000,
        rewardCoins: 200,
        icon: "👑"
    }
];

/* ============================================================
   PHARMACOPOEIA HUB
============================================================ */

const PHARMACOPOEIA_DATA = [
    {
        id: "bp",
        name: "British Pharmacopoeia",
        abbreviation: "BP",
        description:
            "Educational hub for understanding the role, structure and quality concepts associated with the British Pharmacopoeia.",
        officialResource: "https://www.pharmacopoeia.com/",
        copyrightNotice:
            "DENexpharm does not reproduce copyrighted BP monographs."
    },
    {
        id: "usp-nf",
        name: "United States Pharmacopeia–National Formulary",
        abbreviation: "USP–NF",
        description:
            "Educational overview of pharmacopeial standards, quality requirements and reference concepts.",
        officialResource: "https://www.usp.org/",
        copyrightNotice:
            "DENexpharm does not reproduce copyrighted USP–NF monographs."
    },
    {
        id: "ph-eur",
        name: "European Pharmacopoeia",
        abbreviation: "Ph. Eur.",
        description:
            "Educational overview of European pharmacopoeial standards and quality concepts.",
        officialResource: "https://www.edqm.eu/",
        copyrightNotice:
            "DENexpharm does not reproduce copyrighted Ph. Eur. monographs."
    },
    {
        id: "who",
        name: "WHO Quality Resources",
        abbreviation: "WHO",
        description:
            "Educational quality-assurance concepts and international pharmaceutical quality resources.",
        officialResource: "https://www.who.int/",
        copyrightNotice:
            "DENexpharm provides educational summaries and links to official resources."
    }
];

/* ============================================================
   LANGUAGES
============================================================ */

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
        category: "patient_counselling",
        english: "How are you feeling today?",
        translations: {
            fr: "Comment vous sentez-vous aujourd'hui ?",
            es: "¿Cómo se siente hoy?",
            pt: "Como você está se sentindo hoje?"
        }
    },
    {
        id: "phrase_002",
        category: "medication_history",
        english: "Are you currently taking any medicines?",
        translations: {
            fr: "Prenez-vous actuellement des médicaments ?",
            es: "¿Está tomando algún medicamento actualmente?",
            pt: "Você está tomando algum medicamento atualmente?"
        }
    },
    {
        id: "phrase_003",
        category: "patient_counselling",
        english: "Take this medicine exactly as directed.",
        translations: {
            fr: "Prenez ce médicament exactement comme indiqué.",
            es: "Tome este medicamento exactamente como se le indicó.",
            pt: "Tome este medicamento exatamente conforme indicado."
        }
    }
];

/* ============================================================
   LIBRARY
============================================================ */

const LIBRARY_DATA = [
    {
        id: "library_pharmacology_intro",
        title: "Introduction to Pharmacology",
        subject: "Pharmacology",
        type: "revision",
        description:
            "A student-friendly introductory resource covering basic pharmacology concepts.",
        content:
            "Pharmacology is the study of drugs and their interactions with living systems. Major areas include pharmacodynamics, pharmacokinetics and clinical pharmacology.",
        premium: false
    },
    {
        id: "library_calculations",
        title: "Pharmaceutical Calculations Revision Guide",
        subject: "Pharmaceutical Calculations",
        type: "revision",
        description:
            "A concise revision resource for common pharmaceutical calculation concepts.",
        content:
            "Important areas include percentage strength, ratio strength, dilution, concentration, dose calculations and unit conversions.",
        premium: false
    },
    {
        id: "library_microbiology",
        title: "Pharmaceutical Microbiology Quick Review",
        subject: "Pharmaceutical Microbiology",
        type: "revision",
        description:
            "Quick revision material covering microorganisms, sterilization and contamination control.",
        content:
            "Important topics include sterilization, disinfection, culture media, microbial growth and contamination control.",
        premium: false
    }
];

/* ============================================================
   SEED CONTENT
============================================================ */

function seedContent() {
    updateDatabase((db) => {
        if (db.questions.length === 0) {
            db.questions = STARTER_QUESTIONS;
        }

        if (db.achievements.length === 0) {
            db.achievements = ACHIEVEMENTS;
        }

        if (db.pharmacopoeia.length === 0) {
            db.pharmacopoeia = PHARMACOPOEIA_DATA;
        }

        if (db.languages.length === 0) {
            db.languages = LANGUAGE_DATA;
        }

        if (db.languagePhrases.length === 0) {
            db.languagePhrases = LANGUAGE_PHRASES;
        }

        if (db.library.length === 0) {
            db.library = LIBRARY_DATA;
        }
    });
}

/* ============================================================
WALLET
============================================================ */

const WALLET_REWARD_LIMITS = {
  dailyCoins: 500,
  referralCoins: 250,
  quizCoins: 100,
  battleCoins: 200
};

function getUserById(db, userId) {
  return db.users.find((user) => user.id === userId) || null;
}

function getPublicUser(user) {
  if (!user) return null;

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    displayName: user.displayName,
    country: user.country,
    institution: user.institution,
    program: user.program,
    yearLevel: user.yearLevel,
    semester: user.semester,
    curriculum: user.curriculum,
    xp: user.xp || 0,
    coins: user.coins || 0,
    level: user.level || 1,
    streak: user.streak || 0,
    longestStreak: user.longestStreak || 0,
    questionsAnswered: user.questionsAnswered || 0,
    questionsCorrect: user.questionsCorrect || 0,
    quizzesCompleted: user.quizzesCompleted || 0,
    battlesPlayed: user.battlesPlayed || 0,
    battlesWon: user.battlesWon || 0,
    createdAt: user.createdAt,
    lastActiveAt: user.lastActiveAt
  };
}

function ensureUserDefaults(user) {
  user.xp = Number(user.xp) || 0;
  user.coins = Number(user.coins) || 0;
  user.level = Number(user.level) || 1;
  user.streak = Number(user.streak) || 0;
  user.longestStreak = Number(user.longestStreak) || 0;
  user.questionsAnswered = Number(user.questionsAnswered) || 0;
  user.questionsCorrect = Number(user.questionsCorrect) || 0;
  user.quizzesCompleted = Number(user.quizzesCompleted) || 0;
  user.battlesPlayed = Number(user.battlesPlayed) || 0;
  user.battlesWon = Number(user.battlesWon) || 0;
  user.lastActiveDate = user.lastActiveDate || null;
  user.lastActiveAt = user.lastActiveAt || null;
}

function calculateLevel(xp) {
  const safeXP = Math.max(0, Number(xp) || 0);
  return Math.floor(Math.sqrt(safeXP / 100)) + 1;
}

function awardXPAndCoins(db, userId, xp, coins, reason = "reward") {
  const user = getUserById(db, userId);

  if (!user) {
    return {
      xpAwarded: 0,
      coinsAwarded: 0,
      level: 1,
      xp: 0,
      coins: 0
    };
  }

  ensureUserDefaults(user);

  const safeXP = Math.max(0, Math.floor(Number(xp) || 0));
  const safeCoins = Math.max(0, Math.floor(Number(coins) || 0));

  user.xp += safeXP;
  user.coins += safeCoins;
  user.level = calculateLevel(user.xp);

  if (safeCoins > 0) {
    db.walletTransactions.push({
      id: generateId("wallet_tx"),
      userId,
      type: "credit",
      amount: safeCoins,
      reason,
      createdAt: nowISO()
    });
  }

  return {
    xpAwarded: safeXP,
    coinsAwarded: safeCoins,
    level: user.level,
    xp: user.xp,
    coins: user.coins
  };
}

function updateUserActivity(db, userId) {
  const user = getUserById(db, userId);

  if (!user) return;

  ensureUserDefaults(user);

  const today = todayKey();
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayKey = yesterday.toISOString().slice(0, 10);

  if (user.lastActiveDate !== today) {
    if (user.lastActiveDate === yesterdayKey) {
      user.streak += 1;
    } else {
      user.streak = 1;
    }

    user.longestStreak = Math.max(
      user.longestStreak,
      user.streak
    );

    user.lastActiveDate = today;
  }

  user.lastActiveAt = nowISO();
}

/* ============================================================
SESSION / AUTHENTICATION
============================================================ */

function createSession(db, userId) {
  const rawToken = generateSecureToken();

  const session = {
    id: generateId("session"),
    userId,
    tokenHash: sha256(rawToken),
    createdAt: nowISO(),
    expiresAt: addDays(new Date(), SESSION_DAYS).toISOString()
  };

  db.sessions.push(session);

  return rawToken;
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return null;
  }

  return header.slice(7).trim() || null;
}

function getAuthenticatedUser(req) {
  const token = getBearerToken(req);

  if (!token) return null;

  const db = readDatabase();
  const tokenHash = sha256(token);

  const session = db.sessions.find(
    (item) =>
      item.tokenHash === tokenHash &&
      new Date(item.expiresAt).getTime() > Date.now()
  );

  if (!session) return null;

  return getUserById(db, session.userId);
}

function authRequired(req, res, next) {
  const user = getAuthenticatedUser(req);

  if (!user) {
    return sendError(
      res,
      "Authentication required.",
      401,
      "AUTH_REQUIRED"
    );
  }

  req.user = user;
  next();
}

function adminRequired(req, res, next) {
  const user = getAuthenticatedUser(req);

  if (!user) {
    return sendError(
      res,
      "Authentication required.",
      401,
      "AUTH_REQUIRED"
    );
  }

  if (user.role !== "admin") {
    return sendError(
      res,
      "Administrator access required.",
      403,
      "ADMIN_REQUIRED"
    );
  }

  req.user = user;
  next();
}

/* ============================================================
ACHIEVEMENT ENGINE
============================================================ */

function checkAchievements(db, userId) {
  const user = getUserById(db, userId);

  if (!user) return [];

  ensureUserDefaults(user);

  const unlocked = [];

  for (const achievement of db.achievements) {
    const alreadyUnlocked = db.userAchievements.some(
      (item) =>
        item.userId === userId &&
        item.achievementId === achievement.id
    );

    if (alreadyUnlocked) continue;

    let qualifies = false;

    if (
      achievement.id === "first_quiz" &&
      user.quizzesCompleted >= 1
    ) {
      qualifies = true;
    }

    if (
      achievement.id === "questions_10" &&
      user.questionsAnswered >= 10
    ) {
      qualifies = true;
    }

    if (
      achievement.id === "questions_100" &&
      user.questionsAnswered >= 100
    ) {
      qualifies = true;
    }

    if (
      achievement.id === "perfect_score" &&
      user.perfectQuizzes >= 1
    ) {
      qualifies = true;
    }

    if (
      achievement.id === "streak_7" &&
      user.streak >= 7
    ) {
      qualifies = true;
    }

    if (
      achievement.id === "streak_30" &&
      user.streak >= 30
    ) {
      qualifies = true;
    }

    if (!qualifies) continue;

    const reward = awardXPAndCoins(
      db,
      userId,
      achievement.rewardXP || 0,
      achievement.rewardCoins || 0,
      `achievement:${achievement.id}`
    );

    const record = {
      id: generateId("user_achievement"),
      userId,
      achievementId: achievement.id,
      unlockedAt: nowISO(),
      reward
    };

    db.userAchievements.push(record);
    unlocked.push({
      achievement,
      reward
    });
  }

  return unlocked;
}

/* ============================================================
QUESTION HELPERS
============================================================ */

function sanitizeQuestion(question) {
  if (!question) return null;

  return {
    id: question.id,
    subject: question.subject,
    topic: question.topic,
    subtopic: question.subtopic,
    difficulty: question.difficulty,
    questionType: question.questionType,
    question: question.question,
    options: question.options || [],
    curriculum: question.curriculum,
    yearLevel: question.yearLevel,
    semester: question.semester,
    classification: question.classification,
    tags: question.tags || [],
    published: question.published !== false
  };
}

function sanitizeQuestionWithAnswer(question) {
  if (!question) return null;

  return {
    ...sanitizeQuestion(question),
    correctAnswer: question.correctAnswer,
    explanation: question.explanation,
    whyCorrect: question.whyCorrect,
    optionExplanations: question.optionExplanations || [],
    learningPoints: question.learningPoints || [],
    references: question.references || []
  };
}

function findQuestion(db, questionId) {
  return db.questions.find(
    (question) => question.id === questionId
  );
}

function calculateQuizScore(questions, answers) {
  let correct = 0;

  for (const question of questions) {
    const supplied = answers?.[question.id];

    if (
      supplied !== undefined &&
      Number(supplied) === Number(question.correctAnswer)
    ) {
      correct += 1;
    }
  }

  const total = questions.length;
  const percentage =
    total > 0 ? Number(((correct / total) * 100).toFixed(2)) : 0;

  return {
    correct,
    total,
    percentage
  };
}

/* ============================================================
DAILY CHALLENGE
============================================================ */

function getDailyChallenge(db) {
  const today = todayKey();

  let challenge = db.dailyChallenges.find(
    (item) => item.date === today
  );

  if (challenge) return challenge;

  const publishedQuestions = db.questions.filter(
    (question) => question.published !== false
  );

  if (publishedQuestions.length === 0) {
    return null;
  }

  const selected =
    publishedQuestions[
      Math.floor(Math.random() * publishedQuestions.length)
    ];

  challenge = {
    id: generateId("daily"),
    date: today,
    questionId: selected.id,
    xpReward: 100,
    coinReward: 20,
    createdAt: nowISO()
  };

  db.dailyChallenges.push(challenge);

  return challenge;
}

/* ============================================================
SUBSCRIPTION HELPERS
============================================================ */

function getActiveSubscription(db, userId) {
  const now = Date.now();

  return (
    db.subscriptions
      .filter(
        (subscription) =>
          subscription.userId === userId &&
          subscription.status === "active" &&
          new Date(subscription.expiresAt).getTime() > now
      )
      .sort(
        (a, b) =>
          new Date(b.expiresAt) - new Date(a.expiresAt)
      )[0] || null
  );
}

function isPremiumUser(db, userId) {
  return Boolean(getActiveSubscription(db, userId));
}

/* ============================================================
APPLICATION MIDDLEWARE
============================================================ */

app.set("trust proxy", 1);

app.use(
  cors({
    origin:
      FRONTEND_ORIGIN === "*"
        ? true
        : FRONTEND_ORIGIN,
    credentials: true
  })
);

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb"
  })
);

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500
}));

app.disable("x-powered-by");

/* ============================================================
REQUEST LOGGING
============================================================ */

app.use((req, res, next) => {
  const started = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - started;

    if (
      process.env.NODE_ENV !== "test"
    ) {
      console.log(
        `${req.method} ${req.originalUrl} ${res.statusCode} ${duration}ms`
      );
    }
  });

  next();
});

/* ============================================================
HEALTH / VERSION
============================================================ */

app.get("/health", (req, res) => {
  return sendSuccess(
    res,
    {
      app: APP_NAME,
      status: "healthy",
      environment: NODE_ENV,
      nodeVersion: process.version,
      timestamp: nowISO()
    },
    "DENexpharm server is healthy."
  );
});

app.get("/api/health", (req, res) => {
  return sendSuccess(
    res,
    {
      app: APP_NAME,
      status: "healthy",
      version: APP_VERSION,
      contentYear: CONTENT_YEAR,
      timestamp: nowISO()
    },
    "API is healthy."
  );
});

app.get("/api/version", (req, res) => {
  return sendSuccess(
    res,
    {
      name: APP_NAME,
      version: APP_VERSION,
      contentYear: CONTENT_YEAR,
      node: process.version
    },
    "Version information."
  );
});

/* ============================================================
PUBLIC APP INFORMATION
============================================================ */

app.get("/api", (req, res) => {
  return sendSuccess(
    res,
    {
      name: APP_NAME,
      version: APP_VERSION,
      description:
        "Global pharmacy learning, GPA, competition and student-support platform.",
      features: [
        "Pharmacy learning",
        "Question bank",
        "Detailed explanations",
        "Quiz system",
        "Quick Battle",
        "Timed Battle",
        "Daily Challenge",
        "XP and coins",
        "Achievements",
        "Leaderboards",
        "GPA calculator",
        "Mini Library",
        "Pharmacopoeia Hub",
        "Pharmacy Language Assistant",
        "Premium subscriptions",
        "Analytics"
      ]
    },
    "Welcome to DENexpharm API."
  );
});

app.get("/api/subjects", (req, res) => {
  return sendSuccess(res, SUBJECTS);
});

/* ============================================================
REGISTER
============================================================ */

app.post("/api/auth/register", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const username = safeText(req.body.username, 30);
  const password = req.body.password;

  const displayName =
    safeText(
      req.body.displayName ||
      req.body.name ||
      username,
      80
    );

  if (!isValidEmail(email)) {
    return sendError(
      res,
      "Please provide a valid email address.",
      400,
      "INVALID_EMAIL"
    );
  }

  if (!isValidUsername(username)) {
    return sendError(
      res,
      "Username must contain 3–30 letters, numbers, dots, underscores or hyphens.",
      400,
      "INVALID_USERNAME"
    );
  }

  if (!isValidPassword(password)) {
    return sendError(
      res,
      "Password must contain at least 8 characters.",
      400,
      "INVALID_PASSWORD"
    );
  }

  const result = updateDatabase((db) => {
    const existingEmail = db.users.find(
      (user) => user.email === email
    );

    if (existingEmail) {
      return {
        error: "An account with this email already exists."
      };
    }

    const existingUsername = db.users.find(
      (user) =>
        user.username.toLowerCase() === username.toLowerCase()
    );

    if (existingUsername) {
      return {
        error: "That username is already in use."
      };
    }

    const passwordData = hashPassword(password);

    const user = {
      id: generateId("user"),
      email,
      username,
      displayName,
      password: passwordData,
      role: "student",
      country: safeText(req.body.country, 80),
      institution: safeText(req.body.institution, 150),
      program: safeText(req.body.program, 150),
      yearLevel: safeText(req.body.yearLevel, 50),
      semester: safeText(req.body.semester, 50),
      curriculum: safeText(
        req.body.curriculum || "international",
        80
      ),
      xp: 0,
      coins: 0,
      level: 1,
      streak: 0,
      longestStreak: 0,
      questionsAnswered: 0,
      questionsCorrect: 0,
      quizzesCompleted: 0,
      perfectQuizzes: 0,
      battlesPlayed: 0,
      battlesWon: 0,
      createdAt: nowISO(),
      lastActiveAt: nowISO(),
      lastActiveDate: todayKey()
    };

    db.users.push(user);

    const token = createSession(db, user.id);

    db.auditLogs.push({
      id: generateId("audit"),
      action: "register",
      userId: user.id,
      createdAt: nowISO()
    });

    return {
      user: getPublicUser(user),
      token
    };
  });

  if (result.error) {
    return sendError(res, result.error, 409, "REGISTER_FAILED");
  }

  return sendSuccess(
    res,
    result,
    "Account created successfully.",
    201
  );
});

/* ============================================================
LOGIN
============================================================ */

app.post("/api/auth/login", (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = req.body.password;

  const result = updateDatabase((db) => {
    const user = db.users.find(
      (item) => item.email === email
    );

    if (
      !user ||
      !verifyPassword(password, user.password)
    ) {
      return {
        error: "Invalid email or password."
      };
    }

    ensureUserDefaults(user);
    updateUserActivity(db, user.id);

    const token = createSession(db, user.id);

    db.auditLogs.push({
      id: generateId("audit"),
      action: "login",
      userId: user.id,
      createdAt: nowISO()
    });

    return {
      user: getPublicUser(user),
      token
    };
  });

  if (result.error) {
    return sendError(
      res,
      result.error,
      401,
      "LOGIN_FAILED"
    );
  }

  return sendSuccess(
    res,
    result,
    "Login successful."
  );
});

/* ============================================================
CURRENT USER
============================================================ */

app.get("/api/auth/me", authRequired, (req, res) => {
  const db = readDatabase();

  const user = getUserById(db, req.user.id);

  if (!user) {
    return sendError(
      res,
      "User account not found.",
      404,
      "USER_NOT_FOUND"
    );
  }

  const subscription = getActiveSubscription(
    db,
    user.id
  );

  return sendSuccess(res, {
    user: getPublicUser(user),
    premium: Boolean(subscription),
    subscription
  });
});

/* ============================================================
LOGOUT
============================================================ */

app.post("/api/auth/logout", authRequired, (req, res) => {
  const token = getBearerToken(req);

  updateDatabase((db) => {
    const tokenHash = sha256(token);

    db.sessions = db.sessions.filter(
      (session) => session.tokenHash !== tokenHash
    );

    db.auditLogs.push({
      id: generateId("audit"),
      action: "logout",
      userId: req.user.id,
      createdAt: nowISO()
    });
  });

  return sendSuccess(
    res,
    {},
    "Logged out successfully."
  );
});

/* ============================================================
PROFILE
============================================================ */

app.get("/api/profile", authRequired, (req, res) => {
  const db = readDatabase();
  const user = getUserById(db, req.user.id);

  return sendSuccess(res, {
    user: getPublicUser(user)
  });
});

app.patch("/api/profile", authRequired, (req, res) => {
  const result = updateDatabase((db) => {
    const user = getUserById(db, req.user.id);

    if (!user) {
      return { error: "User not found." };
    }

    if (req.body.username !== undefined) {
      const username = safeText(req.body.username, 30);

      if (!isValidUsername(username)) {
        return {
          error: "Invalid username."
        };
      }

      const conflict = db.users.find(
        (item) =>
          item.id !== user.id &&
          item.username.toLowerCase() === username.toLowerCase()
      );

      if (conflict) {
        return {
          error: "Username already exists."
        };
      }

      user.username = username;
    }

    if (req.body.displayName !== undefined) {
      user.displayName = safeText(
        req.body.displayName,
        80
      );
    }

    const fields = [
      "country",
      "institution",
      "program",
      "yearLevel",
      "semester",
      "curriculum"
    ];

    for (const field of fields) {
      if (req.body[field] !== undefined) {
        user[field] = safeText(req.body[field], 150);
      }
    }

    user.updatedAt = nowISO();

    return {
      user: getPublicUser(user)
    };
  });

  if (result.error) {
    return sendError(
      res,
      result.error,
      400,
      "PROFILE_UPDATE_FAILED"
    );
  }

  return sendSuccess(
    res,
    result,
    "Profile updated."
  );
});

/* ============================================================
QUESTIONS
============================================================ */

app.get("/api/questions", (req, res) => {
  const db = readDatabase();

  let questions = db.questions.filter(
    (question) => question.published !== false
  );

  if (req.query.subject) {
    const subject = safeText(req.query.subject, 100)
      .toLowerCase();

    questions = questions.filter(
      (question) =>
        String(question.subject).toLowerCase() === subject
    );
  }

  if (req.query.topic) {
    const topic = safeText(req.query.topic, 150)
      .toLowerCase();

    questions = questions.filter(
      (question) =>
        String(question.topic).toLowerCase() === topic
    );
  }

  if (req.query.difficulty) {
    questions = questions.filter(
      (question) =>
        question.difficulty === req.query.difficulty
    );
  }

  if (req.query.yearLevel) {
    questions = questions.filter(
      (question) =>
        String(question.yearLevel) ===
        String(req.query.yearLevel)
    );
  }

  if (req.query.semester) {
    questions = questions.filter(
      (question) =>
        String(question.semester) ===
        String(req.query.semester)
    );
  }

  const result = paginate(
    questions.map(sanitizeQuestion),
    req.query.page,
    req.query.pageSize
  );

  return sendSuccess(res, result);
});

app.get("/api/questions/:id", (req, res) => {
  const db = readDatabase();
  const question = findQuestion(
    db,
    req.params.id
  );

  if (!question || question.published === false) {
    return sendError(
      res,
      "Question not found.",
      404,
      "QUESTION_NOT_FOUND"
    );
  }

  return sendSuccess(
    res,
    sanitizeQuestionWithAnswer(question)
  );
});

/* ============================================================
QUIZ
============================================================ */

app.post("/api/quiz/start", authRequired, (req, res) => {
  const db = readDatabase();

  let questions = db.questions.filter(
    (question) => question.published !== false
  );

  if (req.body.subject) {
    questions = questions.filter(
      (question) =>
        String(question.subject).toLowerCase() ===
        String(req.body.subject).toLowerCase()
    );
  }

  if (req.body.difficulty) {
    questions = questions.filter(
      (question) =>
        question.difficulty === req.body.difficulty
    );
  }

  const requestedCount = clampNumber(
    req.body.count || 10,
    1,
    50,
    10
  );

  questions = questions
    .sort(() => Math.random() - 0.5)
    .slice(0, requestedCount);

  const quizId = generateId("quiz");

  const quiz = {
    id: quizId,
    userId: req.user.id,
    questionIds: questions.map(
      (question) => question.id
    ),
    subject: req.body.subject || "Mixed",
    startedAt: nowISO(),
    status: "active"
  };

  updateDatabase((database) => {
    database.quizAttempts.push(quiz);
  });

  return sendSuccess(
    res,
    {
      quizId,
      questions: questions.map(sanitizeQuestion),
      totalQuestions: questions.length
    },
    "Quiz started.",
    201
  );
});

app.post(
  "/api/quiz/:quizId/submit",
  authRequired,
  (req, res) => {
    const result = updateDatabase((db) => {
      const quiz = db.quizAttempts.find(
        (item) =>
          item.id === req.params.quizId &&
          item.userId === req.user.id
      );

      if (!quiz) {
        return {
          error: "Quiz not found."
        };
      }

      if (quiz.status === "completed") {
        return {
          error: "This quiz has already been submitted."
        };
      }

      const questions = quiz.questionIds
        .map((id) => findQuestion(db, id))
        .filter(Boolean);

      const score = calculateQuizScore(
        questions,
        req.body.answers || {}
      );

      const xpReward =
        score.correct * 10 +
        (score.percentage === 100 ? 100 : 0);

      const coinReward =
        Math.min(
          WALLET_REWARD_LIMITS.quizCoins,
          score.correct * 2
        );

      const reward = awardXPAndCoins(
        db,
        req.user.id,
        xpReward,
        coinReward,
        "quiz"
      );

      const user = getUserById(
        db,
        req.user.id
      );

      ensureUserDefaults(user);

      user.questionsAnswered += score.total;
      user.questionsCorrect += score.correct;
      user.quizzesCompleted += 1;

      if (score.percentage === 100) {
        user.perfectQuizzes += 1;
      }

      updateUserActivity(
        db,
        req.user.id
      );

      quiz.status = "completed";
      quiz.completedAt = nowISO();

      const resultRecord = {
        id: generateId("quiz_result"),
        quizId: quiz.id,
        userId: req.user.id,
        answers: req.body.answers || {},
        score,
        reward,
        completedAt: nowISO()
      };

      db.quizResults.push(resultRecord);

      const unlocked = checkAchievements(
        db,
        req.user.id
      );

      return {
        score,
        reward,
        achievements: unlocked,
        explanations: questions.map(
          sanitizeQuestionWithAnswer
        )
      };
    });

    if (result.error) {
      return sendError(
        res,
        result.error,
        400,
        "QUIZ_SUBMISSION_FAILED"
      );
    }

    return sendSuccess(
      res,
      result,
      "Quiz submitted successfully."
    );
  }
);

/* ============================================================
QUIZ HISTORY
============================================================ */

app.get(
  "/api/quiz/history",
  authRequired,
  (req, res) => {
    const db = readDatabase();

    const results = db.quizResults
      .filter(
        (item) => item.userId === req.user.id
      )
      .sort(
        (a, b) =>
          new Date(b.completedAt) -
          new Date(a.completedAt)
      );

    return sendSuccess(
      res,
      paginate(
        results,
        req.query.page,
        req.query.pageSize
      )
    );
  }
);

/* ============================================================
DAILY CHALLENGE
============================================================ */

app.get(
  "/api/daily-challenge",
  authRequired,
  (req, res) => {
    const result = updateDatabase((db) => {
      const challenge = getDailyChallenge(db);

      if (!challenge) {
        return {
          error: "No questions are available."
        };
      }

      const question = findQuestion(
        db,
        challenge.questionId
      );

      return {
        challenge,
        question: sanitizeQuestion(question)
      };
    });

    if (result.error) {
      return sendError(
        res,
        result.error,
        404,
        "DAILY_CHALLENGE_UNAVAILABLE"
      );
    }

    return sendSuccess(
      res,
      result
    );
  }
);

app.post(
  "/api/daily-challenge/submit",
  authRequired,
  (req, res) => {
    const result = updateDatabase((db) => {
      const challenge = getDailyChallenge(db);

      if (!challenge) {
        return {
          error: "Daily challenge unavailable."
        };
      }

      const existing = db.analytics.find(
        (item) =>
          item.userId === req.user.id &&
          item.type === "daily_challenge" &&
          item.challengeId === challenge.id
      );

      if (existing) {
        return {
          error: "You have already completed today's challenge."
        };
      }

      const question = findQuestion(
        db,
        challenge.questionId
      );

      const correct =
        Number(req.body.answer) ===
        Number(question.correctAnswer);

      let reward = {
        xpAwarded: 0,
        coinsAwarded: 0
      };

      if (correct) {
        reward = awardXPAndCoins(
          db,
          req.user.id,
          challenge.xpReward,
          challenge.coinReward,
          "daily_challenge"
        );
      }

      const user = getUserById(
        db,
        req.user.id
      );

      ensureUserDefaults(user);

      user.questionsAnswered += 1;

      if (correct) {
        user.questionsCorrect += 1;
      }

      updateUserActivity(
        db,
        req.user.id
      );

      db.analytics.push({
        id: generateId("analytics"),
        userId: req.user.id,
        type: "daily_challenge",
        challengeId: challenge.id,
        correct,
        createdAt: nowISO()
      });

      const achievements =
        checkAchievements(
          db,
          req.user.id
        );

      return {
        correct,
        reward,
        achievements,
        explanation:
          sanitizeQuestionWithAnswer(question)
      };
    });

    if (result.error) {
      return sendError(
        res,
        result.error,
        400,
        "DAILY_CHALLENGE_FAILED"
      );
    }

    return sendSuccess(
      res,
      result,
      "Daily challenge submitted."
    );
  }
);

/* ============================================================
BATTLES
============================================================ */

app.post(
  "/api/battles/quick",
  authRequired,
  (req, res) => {
    const result = updateDatabase((db) => {
      const questions = db.questions
        .filter(
          (question) =>
            question.published !== false
        )
        .sort(() => Math.random() - 0.5)
        .slice(0, 10);

      const battle = {
        id: generateId("battle"),
        userId: req.user.id,
        mode: "quick",
        questionIds: questions.map(
          (question) => question.id
        ),
        status: "active",
        startedAt: nowISO()
      };

      db.battles.push(battle);

      return {
        battleId: battle.id,
        mode: battle.mode,
        questions: questions.map(
          sanitizeQuestion
        )
      };
    });

    return sendSuccess(
      res,
      result,
      "Quick Battle created.",
      201
    );
  }
);

app.post(
  "/api/battles/timed",
  authRequired,
  (req, res) => {
    const durationSeconds = clampNumber(
      req.body.durationSeconds || 60,
      15,
      600,
      60
    );

    const result = updateDatabase((db) => {
      const questions = db.questions
        .filter(
          (question) =>
            question.published !== false
        )
        .sort(() => Math.random() - 0.5)
        .slice(0, 20);

      const battle = {
        id: generateId("battle"),
        userId: req.user.id,
        mode: "timed",
        durationSeconds,
        questionIds: questions.map(
          (question) => question.id
        ),
        status: "active",
        startedAt: nowISO()
      };

      db.battles.push(battle);

      return {
        battleId: battle.id,
        mode: "timed",
        durationSeconds,
        questions: questions.map(
          sanitizeQuestion
        )
      };
    });

    return sendSuccess(
      res,
      result,
      "Timed Battle created.",
      201
    );
  }
);

app.post(
  "/api/battles/:battleId/submit",
  authRequired,
  (req, res) => {
    const result = updateDatabase((db) => {
      const battle = db.battles.find(
        (item) =>
          item.id === req.params.battleId &&
          item.userId === req.user.id
      );

      if (!battle) {
        return {
          error: "Battle not found."
        };
      }

      if (battle.status === "completed") {
        return {
          error: "Battle already submitted."
        };
      }

      const questions = battle.questionIds
        .map((id) => findQuestion(db, id))
        .filter(Boolean);

      const score = calculateQuizScore(
        questions,
        req.body.answers || {}
      );

      const reward = awardXPAndCoins(
        db,
        req.user.id,
        score.correct * 15,
        Math.min(
          WALLET_REWARD_LIMITS.battleCoins,
          score.correct * 3
        ),
        "battle"
      );

      const user = getUserById(
        db,
        req.user.id
      );

      ensureUserDefaults(user);

      user.questionsAnswered += score.total;
      user.questionsCorrect += score.correct;
      user.battlesPlayed += 1;

      if (
        req.body.won === true ||
        req.body.result === "win"
      ) {
        user.battlesWon += 1;
      }

      updateUserActivity(
        db,
        req.user.id
      );

      battle.status = "completed";
      battle.completedAt = nowISO();
      battle.score = score;

      const achievements =
        checkAchievements(
          db,
          req.user.id
        );

      return {
        score,
        reward,
        achievements
      };
    });

    if (result.error) {
      return sendError(
        res,
        result.error,
        400,
        "BATTLE_SUBMISSION_FAILED"
      );
    }

    return sendSuccess(
      res,
      result,
      "Battle submitted."
    );
  }
);

/* ============================================================
LEADERBOARDS
============================================================ */

app.get(
  "/api/leaderboards",
  (req, res) => {
    const db = readDatabase();

    const type =
      safeText(req.query.type || "xp", 30);

    const users = db.users.map(
      (user) => {
        ensureUserDefaults(user);

        return {
          id: user.id,
          username: user.username,
          displayName: user.displayName,
          country: user.country,
          institution: user.institution,
          xp: user.xp,
          coins: user.coins,
          level: user.level,
          streak: user.streak,
          questionsAnswered:
            user.questionsAnswered,
          quizzesCompleted:
            user.quizzesCompleted,
          battlesWon: user.battlesWon
        };
      }
    );

    if (type === "coins") {
      users.sort(
        (a, b) => b.coins - a.coins
      );
    } else if (type === "streak") {
      users.sort(
        (a, b) => b.streak - a.streak
      );
    } else if (type === "battles") {
      users.sort(
        (
