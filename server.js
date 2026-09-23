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
   WAL
