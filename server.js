'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const QUESTION_FILE = path.join(ROOT, 'question.json');
const SCHEMA_FILE = path.join(ROOT, 'schema.sql');
const isProduction = process.env.NODE_ENV === 'production';
const JWT_SECRET = process.env.JWT_SECRET || (isProduction ? '' : 'DENexPharm-development-secret-change-me');
const MAX_BODY = process.env.MAX_BODY || '1mb';
const FREE_QUESTIONS_PER_SUBJECT = 10;
const PREMIUM_PRICE = Number(process.env.PREMIUM_PRICE || 5000);
const PREMIUM_CURRENCY = String(process.env.PREMIUM_CURRENCY || 'NGN').trim().toUpperCase();
const SUPPORTED_LEVELS = ['100', '200', '300', '400', '500', '600'];

const frontendOrigin = process.env.FRONTEND_ORIGIN
  ? process.env.FRONTEND_ORIGIN.split(',').map(v => v.trim()).filter(Boolean)
  : isProduction ? false : true;

if (isProduction) {
  if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error('STARTUP ERROR: JWT_SECRET must be configured and at least 32 characters long in production.');
    process.exit(1);
  }
  if (!process.env.DATABASE_URL) {
    console.error('STARTUP ERROR: DATABASE_URL must be configured in production.');
    process.exit(1);
  }
}
if (!Number.isFinite(PREMIUM_PRICE) || PREMIUM_PRICE <= 0) {
  console.error('STARTUP ERROR: PREMIUM_PRICE must be a positive number.');
  process.exit(1);
}

if (isProduction) {
  const paystackKey = String(process.env.PAYSTACK_SECRET_KEY || '').trim();
  if (!paystackKey) {
    console.warn('WARNING: PAYSTACK_SECRET_KEY is not configured. Premium payments will remain disabled until it is added.');
  } else if (!paystackKey.startsWith('sk_live_')) {
    console.warn('WARNING: Production is using a non-live Paystack key. Real Premium payments will be blocked until PAYSTACK_SECRET_KEY starts with sk_live_.');
  }
  const callback = cleanText(process.env.PAYSTACK_CALLBACK_URL);
  if (callback) {
    try {
      const callbackUrl = new URL(callback);
      if (callbackUrl.protocol !== 'https:') console.warn('WARNING: PAYSTACK_CALLBACK_URL should use HTTPS in production.');
    } catch {
      console.warn('WARNING: PAYSTACK_CALLBACK_URL is not a valid URL.');
    }
  } else {
    console.warn('WARNING: PAYSTACK_CALLBACK_URL is not set. Ensure the callback URL is configured in the Paystack Dashboard.');
  }
}

const DEFAULT_DB = { users: [], questions: [], scores: [], payments: [] };
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULT_DB, null, 2), 'utf8');

function loadLocalDb() {
  try {
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    for (const key of Object.keys(DEFAULT_DB)) if (!Array.isArray(data[key])) data[key] = [];
    return data;
  } catch (error) {
    console.error('Could not read data/db.json:', error.message);
    fs.writeFileSync(DB_FILE, JSON.stringify(DEFAULT_DB, null, 2), 'utf8');
    return structuredClone(DEFAULT_DB);
  }
}
let db = loadLocalDb();
function saveLocalDb() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), 'utf8'); }

const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: Math.max(1, Number(process.env.DB_POOL_MAX || 10))
}) : null;

async function sql(query, params = []) {
  if (!pool) return [];
  const result = await pool.query(query, params);
  return result.rows;
}

function generateId() { return crypto.randomUUID(); }
function cleanText(value, fallback = '') { return String(value ?? fallback).trim(); }
function canonical(value) { return cleanText(value).toLowerCase(); }
function validLevel(level) { return SUPPORTED_LEVELS.includes(String(level)); }
function safeUser(user) {
  return {
    id: user.id, email: user.email, name: user.name,
    university: user.university || '', country: user.country || '',
    level: user.level || '200', xp: Number(user.xp || 0),
    premium: Boolean(user.premium), admin: Boolean(user.admin)
  };
}
function signUser(user) {
  return jwt.sign({ id: user.id, email: user.email, admin: Boolean(user.admin) }, JWT_SECRET, { expiresIn: '30d' });
}
function getTokenFromRequest(req) {
  const header = req.get('authorization') || '';
  return header.startsWith('Bearer ') ? header.slice(7).trim() : null;
}
function authenticate(req) {
  const token = getTokenFromRequest(req);
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}
function requireAuth(req, res, next) {
  const auth = authenticate(req);
  if (!auth) return res.status(401).json({ error: 'Sign in required' });
  req.auth = auth;
  next();
}
async function requireAdmin(req, res, next) {
  const auth = authenticate(req);
  if (!auth) return res.status(401).json({ error: 'Sign in required' });
  try {
    const user = await getUserById(auth.id);
    if (!user || !user.admin) return res.status(403).json({ error: 'Admin access required' });
    req.auth = auth;
    req.currentUser = user;
    next();
  } catch (error) { next(error); }
}

function normalizeQuestion(question, fallbackId) {
  if (!question || typeof question !== 'object') return null;
  const numericId = Number(question.id ?? fallbackId);
  const country = cleanText(question.country || 'Nigeria');
  const level = cleanText(question.level || '200');
  const subject = cleanText(question.subject);
  const topic = cleanText(question.topic || 'General');
  const questionText = cleanText(question.question);
  const options = Array.isArray(question.options) ? question.options.map(v => String(v)) : [];
  const answerIndex = Number(question.answer_index);
  if (!Number.isInteger(numericId) || numericId < 1) return null;
  if (!country || !level || !subject || !topic || !questionText) return null;
  if (options.length !== 4) return null;
  if (!Number.isInteger(answerIndex) || answerIndex < 0 || answerIndex > 3) return null;
  return {
    id: numericId, country, level, subject, topic,
    question: questionText, options, answer_index: answerIndex,
    explanation: cleanText(question.explanation), active: question.active !== false
  };
}

function loadQuestionBank() {
  if (!fs.existsSync(QUESTION_FILE)) throw new Error('question.json was not found. Place question.json beside server.js.');
  let parsed;
  try { parsed = JSON.parse(fs.readFileSync(QUESTION_FILE, 'utf8')); }
  catch (error) { throw new Error(`Could not parse question.json: ${error.message}`); }
  if (!Array.isArray(parsed)) throw new Error('question.json must contain a JSON array.');
  const seenIds = new Set();
  const validQuestions = [];
  for (let index = 0; index < parsed.length; index++) {
    const normalized = normalizeQuestion(parsed[index], index + 1);
    if (!normalized) { console.warn(`Skipping invalid question at question.json index ${index}.`); continue; }
    if (seenIds.has(normalized.id)) { console.warn(`Skipping duplicate question ID ${normalized.id}.`); continue; }
    seenIds.add(normalized.id); validQuestions.push(normalized);
  }
  validQuestions.sort((a, b) => a.id - b.id);
  console.log(`Loaded ${validQuestions.length} valid questions from question.json.`);
  return validQuestions;
}
let questionBank = [];

function normalizeStoredQuestion(question, fallbackId) { return normalizeQuestion(question, fallbackId); }
function getLocalQuestions() {
  return db.questions.map((q, i) => normalizeStoredQuestion(q, i + 1)).filter(q => q && q.active !== false);
}
function shuffle(array) {
  const result = [...array];
  for (let i = result.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }
  return result;
}
function filterQuestions(questions, { country, level, subject, topic } = {}) {
  const c = country ? canonical(country) : null;
  const l = level ? canonical(level) : null;
  const s = subject ? canonical(subject) : null;
  const t = topic ? canonical(topic) : null;
  return questions.filter(q =>
    (!c || canonical(q.country) === c) &&
    (!l || canonical(q.level) === l) &&
    (!s || canonical(q.subject) === s) &&
    (!t || canonical(q.topic) === t)
  );
}
function limitFreeQuestions(questions) {
  const groups = new Map();
  for (const question of questions) {
    const key = [canonical(question.country), canonical(question.level), canonical(question.subject)].join('|');
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(question);
  }
  const result = [];
  for (const group of groups.values()) {
    result.push(...group.sort((a, b) => a.id - b.id).slice(0, FREE_QUESTIONS_PER_SUBJECT));
  }
  return result.sort((a, b) => a.id - b.id);
}

async function getAllQuestions() {
  if (pool) {
    const rows = await sql(`SELECT id, country, level, subject, topic, question, options, answer_index, explanation, active FROM questions WHERE active = true ORDER BY id ASC`);
    return rows.map(row => normalizeQuestion(row, row.id)).filter(Boolean);
  }
  const merged = new Map();
  for (const q of questionBank) if (q.active !== false) merged.set(String(q.id), q);
  for (const q of getLocalQuestions()) merged.set(String(q.id), q);
  return Array.from(merged.values()).filter(q => q.active !== false);
}
async function getQuestionById(questionId) {
  if (pool) {
    const rows = await sql(`SELECT id, country, level, subject, topic, question, options, answer_index, explanation, active FROM questions WHERE id = $1 AND active = true LIMIT 1`, [questionId]);
    return rows.length ? normalizeQuestion(rows[0], rows[0].id) : null;
  }
  const idString = String(questionId);
  return getLocalQuestions().find(q => String(q.id) === idString) || questionBank.find(q => String(q.id) === idString) || null;
}

async function getUserById(userId) {
  if (pool) {
    const rows = await sql('SELECT * FROM users WHERE id = $1 LIMIT 1', [userId]);
    return rows[0] || null;
  }
  return db.users.find(user => String(user.id) === String(userId)) || null;
}
async function getUserByEmail(email) {
  const normalized = cleanText(email).toLowerCase();
  if (!normalized) return null;
  if (pool) {
    const rows = await sql('SELECT * FROM users WHERE email = $1 LIMIT 1', [normalized]);
    return rows[0] || null;
  }
  return db.users.find(user => String(user.email || '').toLowerCase() === normalized) || null;
}

async function getFilterData() {
  const questions = await getAllQuestions();
  const countryMap = new Map();
  const subjectMap = new Map();
  const topicMap = new Map();
  for (const q of questions) {
    countryMap.set(canonical(q.country), q.country);
    subjectMap.set(canonical(q.subject), q.subject);
    const topicKey = [canonical(q.country), canonical(q.level), canonical(q.subject), canonical(q.topic)].join('|');
    topicMap.set(topicKey, q.topic);
  }
  return {
    countries: Array.from(countryMap.values()).sort((a, b) => a.localeCompare(b)),
    levels: [...SUPPORTED_LEVELS],
    subjects: Array.from(subjectMap.values()).sort((a, b) => a.localeCompare(b)),
    topics: Array.from(topicMap.entries()).map(([key, topic]) => {
      const [country, level, subject] = key.split('|');
      return { country, level, subject, topic };
    }).sort((a, b) => a.topic.localeCompare(b.topic))
  };
}
async function countQuestions(filters = {}) { return filterQuestions(await getAllQuestions(), filters).length; }
async function getSubjects() {
  const questions = await getAllQuestions();
  const map = new Map();
  for (const q of questions) map.set(q.subject, (map.get(q.subject) || 0) + 1);
  return Array.from(map.entries()).sort(([a], [b]) => a.localeCompare(b)).map(([subject, count]) => ({ subject, name: subject, count, total_questions: count, free_questions: Math.min(count, FREE_QUESTIONS_PER_SUBJECT) }));
}

async function importQuestionsToDatabase() {
  if (!pool) { console.log(`Local mode: using ${questionBank.length} questions directly from question.json.`); return; }
  for (const q of questionBank) {
    await pool.query(`
      INSERT INTO questions (id, country, level, subject, topic, question, options, answer_index, explanation, active)
      VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10)
      ON CONFLICT (id) DO UPDATE SET
        country=EXCLUDED.country, level=EXCLUDED.level, subject=EXCLUDED.subject, topic=EXCLUDED.topic,
        question=EXCLUDED.question, options=EXCLUDED.options, answer_index=EXCLUDED.answer_index,
        explanation=EXCLUDED.explanation, active=EXCLUDED.active, updated_at=NOW()
    `, [q.id, q.country, q.level, q.subject, q.topic, q.question, JSON.stringify(q.options), q.answer_index, q.explanation, q.active]);
  }
  const sequenceResult = await pool.query(`SELECT pg_get_serial_sequence('questions','id') AS sequence_name`);
  const sequenceName = sequenceResult.rows[0]?.sequence_name;
  if (sequenceName) {
    const maxResult = await pool.query('SELECT COALESCE(MAX(id),0) AS max_id FROM questions');
    const nextId = Number(maxResult.rows[0]?.max_id || 0) + 1;
    await pool.query('SELECT setval($1::regclass,$2,false)', [sequenceName, nextId]);
  }
  console.log(`PostgreSQL question synchronization complete. ${questionBank.length} records processed.`);
}

async function repairAuditLogUserIdType() {
  // Older DENexPharm databases may have audit_logs.user_id as TEXT while
  // users.id is SERIAL/INTEGER. PostgreSQL will reject the FK in schema.sql
  // before the application can finish startup. Repair the existing table first.
  const usersColumn = await pool.query(`
    SELECT data_type, udt_name
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='users' AND column_name='id'
    LIMIT 1
  `);
  const auditTable = await pool.query(`
    SELECT EXISTS (
      SELECT 1 FROM information_schema.tables
      WHERE table_schema='public' AND table_name='audit_logs'
    ) AS exists
  `);
  if (!auditTable.rows[0]?.exists || !usersColumn.rows[0]) return;

  const auditColumn = await pool.query(`
    SELECT data_type, udt_name
    FROM information_schema.columns
    WHERE table_schema='public' AND table_name='audit_logs' AND column_name='user_id'
    LIMIT 1
  `);
  if (!auditColumn.rows[0]) return;

  const userType = usersColumn.rows[0].data_type;
  const auditType = auditColumn.rows[0].data_type;
  console.log(`Database ID types before schema: users.id=${userType}, audit_logs.user_id=${auditType}`);

  if (userType === 'integer' && auditType === 'text') {
    console.log('Repairing audit_logs.user_id TEXT -> INTEGER before schema initialization...');
    await pool.query('ALTER TABLE audit_logs DROP CONSTRAINT IF EXISTS audit_logs_user_id_fkey');
    await pool.query(`
      ALTER TABLE audit_logs
      ALTER COLUMN user_id TYPE INTEGER
      USING (CASE WHEN user_id ~ '^[0-9]+$' THEN user_id::INTEGER ELSE NULL END)
    `);
    await pool.query(`
      ALTER TABLE audit_logs
      ADD CONSTRAINT audit_logs_user_id_fkey
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    `);
    console.log('audit_logs.user_id repaired successfully.');
  }
}

function makeSchemaCompatible(schema) {
  // The deployed schema may contain an old audit_logs definition with a TEXT
  // user_id. Change only that column definition in the SQL sent to PostgreSQL.
  // Existing tables are repaired separately above.
  return schema.replace(
    /(CREATE\s+TABLE(?:\s+IF\s+NOT\s+EXISTS)?\s+audit_logs\s*\([\s\S]*?\buser_id\s+)TEXT\b/ig,
    '$1INTEGER'
  );
}

async function initDb() {
  if (!pool) { console.log('DATABASE_URL not configured. Using local JSON fallback.'); return; }
  if (!fs.existsSync(SCHEMA_FILE)) throw new Error('schema.sql was not found in the project root.');
  const schema = fs.readFileSync(SCHEMA_FILE, 'utf8');
  if (!schema.trim()) throw new Error('schema.sql is empty.');

  // Repair an old deployed table before schema.sql is executed. This is the
  // critical fix for: text and integer incompatible foreign-key types.
  await repairAuditLogUserIdType();

  // Also make a fresh audit_logs CREATE TABLE compatible with INTEGER users.id.
  const compatibleSchema = makeSchemaCompatible(schema);
  await pool.query(compatibleSchema);

  // A schema run may have just created audit_logs. Ensure its FK is compatible
  // after creation as well.
  await repairAuditLogUserIdType();

  await importQuestionsToDatabase();
  const adminEmail = cleanText(process.env.ADMIN_EMAIL).toLowerCase();
  const adminPassword = String(process.env.ADMIN_PASSWORD || '');
  if (adminEmail && adminPassword && adminEmail !== 'admin@example.com') {
    const existing = await sql('SELECT id FROM users WHERE email = $1 LIMIT 1', [adminEmail]);
    if (!existing.length) {
      const passwordHash = await bcrypt.hash(adminPassword, 12);
      await sql(`INSERT INTO users (email,password_hash,name,admin) VALUES ($1,$2,$3,true)`, [adminEmail,passwordHash,'DENexPharm Admin']);
      console.log(`Admin account created: ${adminEmail}`);
    } else {
      await sql('UPDATE users SET admin = true WHERE email = $1', [adminEmail]);
      console.log(`Admin privileges confirmed: ${adminEmail}`);
    }
  }
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: frontendOrigin, credentials: true }));
app.use(express.json({ limit: MAX_BODY, verify: (req, res, buffer) => { req.rawBody = buffer; } }));
app.use(rateLimit({ windowMs: 15*60*1000, limit: 300, standardHeaders: 'draft-8', legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });

app.get('/api/health', async (req,res) => {
  try {
    res.json({ ok:true, version:'7.1.0', database:Boolean(pool), payments:paystackConfigured(), paystackMode:paystackConfigured() ? (paystackIsLive() ? 'live' : 'non-live') : 'not-configured', questions:await countQuestions(), freeQuestionsPerSubject:FREE_QUESTIONS_PER_SUBJECT, premiumPrice:PREMIUM_PRICE, premiumCurrency:PREMIUM_CURRENCY });
  } catch { res.status(503).json({ ok:false, database:Boolean(pool), error:'Health check failed.' }); }
});

app.post('/api/auth/register', authLimiter, async (req,res,next) => {
  try {
    const {name,email,password,university='',country='',level='200'} = req.body || {};
    if (!cleanText(name) || !cleanText(email) || !password) return res.status(400).json({error:'Name, email and password are required.'});
    if (String(password).length < 6) return res.status(400).json({error:'Password must be at least 6 characters.'});
    const normalizedEmail=cleanText(email).toLowerCase();
    if (await getUserByEmail(normalizedEmail)) return res.status(409).json({error:'Email already registered.'});
    const cleanLevel=cleanText(level,'200');
    const passwordHash=await bcrypt.hash(String(password),12);
    if (pool) {
      const rows=await sql(`INSERT INTO users (email,password_hash,name,university,country,level) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,[normalizedEmail,passwordHash,cleanText(name),cleanText(university),cleanText(country),cleanLevel]);
      return res.status(201).json({token:signUser(rows[0]),user:safeUser(rows[0])});
    }
    const user={id:generateId(),email:normalizedEmail,password_hash:passwordHash,name:cleanText(name),university:cleanText(university),country:cleanText(country),level:cleanLevel,xp:0,premium:false,admin:false,created_at:new Date().toISOString()};
    db.users.push(user); saveLocalDb();
    return res.status(201).json({token:signUser(user),user:safeUser(user)});
  } catch(error) { next(error); }
});

app.post('/api/auth/login', authLimiter, async (req,res,next) => {
  try {
    const email=cleanText(req.body?.email).toLowerCase(); const password=String(req.body?.password || '');
    if (!email || !password) return res.status(400).json({error:'Email and password are required.'});
    const user=await getUserByEmail(email);
    if (!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:'Invalid email or password.'});
    res.json({token:signUser(user),user:safeUser(user)});
  } catch(error) { next(error); }
});

app.get('/api/me', requireAuth, async (req,res,next) => {
  try { const user=await getUserById(req.auth.id); if(!user)return res.status(404).json({error:'User not found.'}); res.json({user:safeUser(user)}); } catch(error){next(error);}
});

app.put('/api/users/profile', requireAuth, async (req,res,next) => {
  try {
    const cleanName=cleanText(req.body?.name), cleanUniversity=cleanText(req.body?.university), cleanCountry=cleanText(req.body?.country), cleanLevel=cleanText(req.body?.level,'200');
    if (pool) {
      const rows=await sql(`UPDATE users SET name=CASE WHEN $1<>'' THEN $1 ELSE name END, university=$2, country=$3, level=$4 WHERE id=$5 RETURNING *`,[cleanName,cleanUniversity,cleanCountry,cleanLevel,req.auth.id]);
      if(!rows.length)return res.status(404).json({error:'User not found.'});
      return res.json({user:safeUser(rows[0])});
    }
    const user=db.users.find(u=>String(u.id)===String(req.auth.id)); if(!user)return res.status(404).json({error:'User not found.'});
    if(cleanName)user.name=cleanName; user.university=cleanUniversity; user.country=cleanCountry; user.level=cleanLevel; saveLocalDb();
    res.json({user:safeUser(user)});
  } catch(error){next(error);}
});

app.get('/api/subjects', async (req,res,next)=>{try{res.json({subjects:await getSubjects()});}catch(error){next(error);}});

app.get('/api/question-filters', async (req,res,next)=>{try{res.json(await getFilterData());}catch(error){next(error);}});

app.get('/api/questions', requireAuth, async (req,res,next) => {
  try {
    const user=await getUserById(req.auth.id); if(!user)return res.status(404).json({error:'User not found.'});
    const premium=Boolean(user.premium);
    const country=cleanText(req.query.country || user.country);
    const level=cleanText(req.query.level || user.level);
    const subject=cleanText(req.query.subject);
    const topic=cleanText(req.query.topic);
    if (!country) return res.status(400).json({error:'Select a country.'});
    if (!validLevel(level)) return res.status(400).json({error:'Level must be 100, 200, 300, 400, 500 or 600.'});
    let questions=filterQuestions(await getAllQuestions(),{country,level,subject,topic});
    const total=questions.length;
    if(!premium) questions=limitFreeQuestions(questions);
    const random=canonical(req.query.random)==='true';
    if(random)questions=shuffle(questions); else questions.sort((a,b)=>a.id-b.id);
    const requestedLimit=Number(req.query.limit); const requestedOffset=Number(req.query.offset);
    const offset=Number.isInteger(requestedOffset)&&requestedOffset>=0?requestedOffset:0;
    const limit=Number.isInteger(requestedLimit)&&requestedLimit>0?Math.min(requestedLimit,2000):2000;
    const returned=premium?questions.slice(offset,offset+limit):questions;
    res.json({questions:returned,premium,access:premium?'premium':'free',country,level,subject:subject||null,topic:topic||null,total_available:total,free_limit:FREE_QUESTIONS_PER_SUBJECT,returned:returned.length,offset:premium?offset:0,limit:premium?limit:FREE_QUESTIONS_PER_SUBJECT,premium_required:!premium&&total>FREE_QUESTIONS_PER_SUBJECT});
  } catch(error){next(error);}
});

app.get('/api/questions/:id', requireAuth, async (req,res,next)=>{
  try {
    const user=await getUserById(req.auth.id); if(!user)return res.status(404).json({error:'User not found.'});
    const question=await getQuestionById(req.params.id); if(!question)return res.status(404).json({error:'Question not found.'});
    if(!user.premium){
      const scoped=filterQuestions(await getAllQuestions(),{country:question.country,level:question.level,subject:question.subject});
      const allowed=scoped.sort((a,b)=>a.id-b.id).slice(0,FREE_QUESTIONS_PER_SUBJECT).some(q=>String(q.id)===String(question.id));
      if(!allowed)return res.status(403).json({error:'This question requires Premium. Free accounts have access to the first 10 questions in each country, level and subject.'});
    }
    res.json({question,premium:Boolean(user.premium)});
  }catch(error){next(error);}
});

app.get('/api/questions/access', requireAuth, async (req,res,next)=>{
  try{
    const user=await getUserById(req.auth.id); if(!user)return res.status(404).json({error:'User not found.'});
    const country=cleanText(req.query.country || user.country), level=cleanText(req.query.level || user.level), subject=cleanText(req.query.subject), topic=cleanText(req.query.topic);
    const total=await countQuestions({country,level,subject,topic});
    res.json({premium:Boolean(user.premium),country,level,subject:subject||null,topic:topic||null,total_questions:total,free_questions:Math.min(total,FREE_QUESTIONS_PER_SUBJECT),remaining_after_free:Math.max(0,total-FREE_QUESTIONS_PER_SUBJECT),premium_required:!user.premium&&total>FREE_QUESTIONS_PER_SUBJECT});
  }catch(error){next(error);}
});

app.post('/api/scores', requireAuth, async (req,res,next)=>{
  try{
    const subject=cleanText(req.body?.subject,'General')||'General'; const rawScore=Number(req.body?.score), rawTotal=Number(req.body?.total);
    if(!Number.isFinite(rawScore)||!Number.isFinite(rawTotal)||rawTotal<=0||rawScore<0||rawScore>rawTotal)return res.status(400).json({error:'Invalid score or total.'});
    const score=Math.floor(rawScore), total=Math.floor(rawTotal), xp=Math.min(score*10,total*10);
    if(pool){await sql('INSERT INTO scores (user_id,subject,score,total) VALUES ($1,$2,$3,$4)',[req.auth.id,subject,score,total]);await sql('UPDATE users SET xp=xp+$1 WHERE id=$2',[xp,req.auth.id]);}
    else{db.scores.push({id:generateId(),user_id:req.auth.id,subject,score,total,created_at:new Date().toISOString()});const user=db.users.find(u=>String(u.id)===String(req.auth.id));if(user)user.xp=Number(user.xp||0)+xp;saveLocalDb();}
    res.status(201).json({ok:true,xp});
  }catch(error){next(error);}
});

app.get('/api/leaderboard', async(req,res,next)=>{
  try{
    let leaderboard;
    if(pool){leaderboard=await sql(`SELECT id,name,university,country,xp FROM users ORDER BY xp DESC,name ASC LIMIT 100`);leaderboard=leaderboard.map(u=>({id:u.id,name:u.name,university:u.university||'',country:u.country||'',xp:Number(u.xp||0)}));}
    else leaderboard=db.users.map(safeUser).sort((a,b)=>b.xp-a.xp||a.name.localeCompare(b.name)).slice(0,100);
    res.json({leaderboard});
  }catch(error){next(error);}
});

function validateAdminQuestion(body,current={}){
  const country=cleanText(body.country !== undefined ? body.country : current.country,'Nigeria');
  const level=cleanText(body.level !== undefined ? body.level : current.level,'200');
  const subject=cleanText(body.subject !== undefined ? body.subject : current.subject);
  const topic=cleanText(body.topic !== undefined ? body.topic : current.topic,'General');
  const question=cleanText(body.question !== undefined ? body.question : current.question);
  const options=body.options !== undefined ? body.options : current.options;
  const answerIndex=body.answer_index !== undefined ? Number(body.answer_index) : Number(current.answer_index);
  const explanation=cleanText(body.explanation !== undefined ? body.explanation : current.explanation);
  const active=body.active !== undefined ? Boolean(body.active) : Boolean(current.active ?? true);
  if(!country||!validLevel(level)||!subject||!topic||!question||!Array.isArray(options)||options.length!==4||!Number.isInteger(answerIndex)||answerIndex<0||answerIndex>3)return null;
  return {country,level,subject,topic,question,options:options.map(String),answer_index:answerIndex,explanation,active};
}

app.get('/api/admin/questions', requireAdmin, async(req,res,next)=>{try{if(pool)return res.json({questions:await sql('SELECT * FROM questions ORDER BY id DESC')});res.json({questions:db.questions});}catch(error){next(error);}});

app.post('/api/admin/questions', requireAdmin, async(req,res,next)=>{
  try{
    const data=validateAdminQuestion(req.body||{}); if(!data)return res.status(400).json({error:'Invalid question data. Country, level, subject, topic, question, four options and answer_index 0-3 are required.'});
    if(pool){const rows=await sql(`INSERT INTO questions (country,level,subject,topic,question,options,answer_index,explanation,active) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9) RETURNING *`,[data.country,data.level,data.subject,data.topic,data.question,JSON.stringify(data.options),data.answer_index,data.explanation,data.active]);return res.status(201).json({question:rows[0]});}
    const newQuestion={id:generateId(),...data,updated_at:new Date().toISOString()};db.questions.push(newQuestion);saveLocalDb();res.status(201).json({question:newQuestion});
  }catch(error){next(error);}
});

app.patch('/api/admin/questions/:id', requireAdmin, async(req,res,next)=>{
  try{
    const id=req.params.id;
    if(pool){const rows=await sql('SELECT * FROM questions WHERE id=$1 LIMIT 1',[id]);if(!rows.length)return res.status(404).json({error:'Question not found.'});const data=validateAdminQuestion(req.body||{},rows[0]);if(!data)return res.status(400).json({error:'Invalid question data.'});const updated=await sql(`UPDATE questions SET country=$1,level=$2,subject=$3,topic=$4,question=$5,options=$6::jsonb,answer_index=$7,explanation=$8,active=$9,updated_at=NOW() WHERE id=$10 RETURNING *`,[data.country,data.level,data.subject,data.topic,data.question,JSON.stringify(data.options),data.answer_index,data.explanation,data.active,id]);return res.json({question:updated[0]});}
    const existing=db.questions.find(q=>String(q.id)===String(id));if(!existing)return res.status(404).json({error:'Question not found.'});const data=validateAdminQuestion(req.body||{},existing);if(!data)return res.status(400).json({error:'Invalid question data.'});Object.assign(existing,data,{updated_at:new Date().toISOString()});saveLocalDb();res.json({question:existing});
  }catch(error){next(error);}
});

// -----------------------------------------------------------------------------
// Paystack production payments
// -----------------------------------------------------------------------------
// Important: Premium price/currency are controlled by the server. The frontend
// cannot choose the amount or currency. Paystack's secret key never leaves this
// backend.
function paystackConfigured() {
  return Boolean(String(process.env.PAYSTACK_SECRET_KEY || '').trim());
}

function paystackIsLive() {
  return String(process.env.PAYSTACK_SECRET_KEY || '').trim().startsWith('sk_live_');
}

function makePaystackReference() {
  // Paystack references may contain alphanumeric characters plus -, ., =.
  return `DENEX-${Date.now()}-${crypto.randomBytes(8).toString('hex').toUpperCase()}`;
}

function safePaystackCallbackUrl() {
  const value = cleanText(process.env.PAYSTACK_CALLBACK_URL);
  if (!value) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:') return undefined;
    return url.toString();
  } catch {
    return undefined;
  }
}

function paymentAmountInMinorUnits(amount) {
  const minor = Math.round(Number(amount) * 100);
  if (!Number.isSafeInteger(minor) || minor <= 0) throw new Error('Invalid Premium amount.');
  return minor;
}

async function findPaymentByReference(reference) {
  if (pool) {
    const rows = await sql(
      'SELECT reference,user_id,amount,currency,status,provider_reference FROM payments WHERE reference=$1 LIMIT 1',
      [reference]
    );
    return rows[0] || null;
  }
  return db.payments.find(p => String(p.reference) === String(reference)) || null;
}

async function initializePaystackTransaction(user, reference) {
  const amount = PREMIUM_PRICE;
  const currency = PREMIUM_CURRENCY;
  const callbackUrl = safePaystackCallbackUrl();
  const body = {
    email: String(user.email).toLowerCase(),
    amount: paymentAmountInMinorUnits(amount),
    currency,
    reference,
    metadata: {
      user_id: String(user.id),
      product: 'DENexPharm Premium'
    }
  };
  if (callbackUrl) body.callback_url = callbackUrl;

  const response = await fetch('https://api.paystack.co/transaction/initialize', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  let data;
  try { data = await response.json(); }
  catch { throw new Error('Invalid response from Paystack.'); }

  if (!response.ok || !data?.status || !data?.data?.authorization_url) {
    throw new Error(data?.message || 'Payment initialization failed.');
  }
  return data.data;
}

app.post('/api/payments/initialize', requireAuth, async (req, res, next) => {
  try {
    if (!paystackConfigured()) {
      return res.status(503).json({
        error: 'Paystack is not configured. Add PAYSTACK_SECRET_KEY to the Render environment variables.'
      });
    }
    if (isProduction && !paystackIsLive()) {
      return res.status(503).json({
        error: 'Live payments are not enabled. Configure a Paystack live secret key (sk_live_...) in production.'
      });
    }

    const user = await getUserById(req.auth.id);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    if (user.premium) return res.status(409).json({ error: 'This account already has Premium access.' });

    // Do not allow the client to supply amount/currency. These are server-side
    // configuration values so a modified browser cannot lower the price.
    const amount = PREMIUM_PRICE;
    const currency = PREMIUM_CURRENCY;
    paymentAmountInMinorUnits(amount);

    // Reuse a recent pending transaction rather than creating multiple charges
    // when a user double-clicks Upgrade or retries immediately after a timeout.
    const recentWindowMs = 10 * 60 * 1000;
    const now = Date.now();
    if (pool) {
      const existing = await sql(
        `SELECT reference,status,created_at
           FROM payments
          WHERE user_id=$1
            AND status IN ('initialized','pending')
            AND amount=$2
            AND UPPER(currency)=UPPER($3)
            AND created_at > NOW() - INTERVAL '10 minutes'
          ORDER BY created_at DESC
          LIMIT 1`,
        [req.auth.id, amount, currency]
      );
      if (existing.length) {
        try {
          const providerData = await verifyPaystack(existing[0].reference);
          if (providerData?.status === 'success') {
            const activated = await markPremium(existing[0].reference, providerData);
            if (activated) return res.json({ already_paid: true, premium: true, reference: existing[0].reference });
          }
        } catch { /* stale/pending transaction; create a fresh checkout below */ }
      }
    } else {
      const existing = db.payments
        .filter(p => String(p.user_id) === String(req.auth.id)
          && ['initialized','pending'].includes(String(p.status))
          && Number(p.amount) === amount
          && String(p.currency || '').toUpperCase() === currency
          && (now - new Date(p.created_at || 0).getTime()) < recentWindowMs)
        .sort((a,b) => new Date(b.created_at || 0) - new Date(a.created_at || 0))[0];
      if (existing) {
        try {
          const providerData = await verifyPaystack(existing.reference);
          if (providerData?.status === 'success') {
            const activated = await markPremium(existing.reference, providerData);
            if (activated) return res.json({ already_paid: true, premium: true, reference: existing.reference });
          }
        } catch { /* stale/pending transaction; create a fresh checkout below */ }
      }
    }

    const reference = makePaystackReference();

    // Persist the internal order BEFORE contacting Paystack. This closes the
    // small race where a very fast charge.success webhook could arrive before
    // the payment row exists.
    if (pool) {
      await sql(
        `INSERT INTO payments(reference,user_id,amount,currency,status,provider_reference)
         VALUES($1,$2,$3,$4,$5,$6)`,
        [reference, req.auth.id, amount, currency, 'initialized', reference]
      );
    } else {
      db.payments.push({
        reference,
        user_id: req.auth.id,
        amount,
        currency,
        status: 'initialized',
        provider_reference: reference,
        created_at: new Date().toISOString()
      });
      saveLocalDb();
    }

    try {
      const paystackData = await initializePaystackTransaction(user, reference);
      const providerReference = String(paystackData.reference || reference);

      if (providerReference !== reference) {
        throw new Error('Paystack returned a mismatched transaction reference.');
      }

      if (pool) {
        await sql(
          `UPDATE payments SET provider_reference=$1,status=$2 WHERE reference=$3`,
          [providerReference, 'pending', reference]
        );
      } else {
        const stored = db.payments.find(p => String(p.reference) === reference);
        if (stored) {
          stored.provider_reference = providerReference;
          stored.status = 'pending';
        }
        saveLocalDb();
      }

      return res.json({
        authorization_url: paystackData.authorization_url,
        reference: providerReference
      });
    } catch (error) {
      // Keep the order record for auditability, but do not leave a failed
      // initialization looking like an active checkout.
      if (pool) {
        await sql('UPDATE payments SET status=$1 WHERE reference=$2', ['failed', reference]);
      } else {
        const stored = db.payments.find(p => String(p.reference) === reference);
        if (stored) stored.status = 'failed';
        saveLocalDb();
      }
      throw error;
    }
  } catch (error) {
    if (error && error.message) error.publicPaymentMessage = error.message;
    next(error);
  }
});

async function verifyPaystack(reference) {
  const cleanReference = cleanText(reference);
  if (!cleanReference) throw new Error('Missing Paystack reference.');
  if (!paystackConfigured()) throw new Error('Paystack is not configured.');

  const response = await fetch(
    'https://api.paystack.co/transaction/verify/' + encodeURIComponent(cleanReference),
    { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } }
  );

  let data;
  try { data = await response.json(); }
  catch { throw new Error('Invalid response from Paystack verification.'); }

  if (!response.ok || !data?.status || !data?.data) {
    throw new Error(data?.message || 'Paystack verification failed.');
  }
  return data.data;
}

async function markPremium(reference, paymentData) {
  const cleanReference = cleanText(reference);
  if (!cleanReference || !paymentData || paymentData.status !== 'success') return false;

  // Always compare the provider transaction against the exact internal order.
  // This prevents a successful transaction for another user/reference from
  // activating Premium on the wrong account.
  const payment = await findPaymentByReference(cleanReference);
  if (!payment) return false;

  const metadataUserId = paymentData.metadata?.user_id != null
    ? String(paymentData.metadata.user_id)
    : '';
  const storedUserId = String(payment.user_id);
  if (!metadataUserId || metadataUserId !== storedUserId) return false;

  const providerReference = String(paymentData.reference || cleanReference);
  if (providerReference !== cleanReference) return false;

  const paidMinor = Number(paymentData.amount);
  const expectedMinor = paymentAmountInMinorUnits(PREMIUM_PRICE);
  const paidCurrency = String(paymentData.currency || '').toUpperCase();
  if (!Number.isSafeInteger(paidMinor) || paidMinor !== expectedMinor) return false;
  if (paidCurrency !== PREMIUM_CURRENCY) return false;

  const storedAmount = Number(payment.amount);
  const storedCurrency = String(payment.currency || '').toUpperCase();
  if (storedAmount !== PREMIUM_PRICE || storedCurrency !== PREMIUM_CURRENCY) return false;

  const providerId = String(paymentData.id || cleanReference);

  if (pool) {
    const users = await sql('SELECT id,premium FROM users WHERE id=$1 LIMIT 1', [storedUserId]);
    if (!users.length) return false;

    // Idempotent: webhook + callback can both arrive for the same payment.
    if (String(payment.status).toLowerCase() === 'success' && users[0].premium) return true;

    // One SQL statement keeps the two state changes atomic without relying on
    // separate pooled connections for BEGIN/COMMIT.
    await sql(
      `WITH activated_user AS (
         UPDATE users SET premium=true WHERE id=$1 RETURNING id
       )
       UPDATE payments
          SET status=$2, provider_reference=$3
        WHERE reference=$4
          AND user_id=$1`,
      [storedUserId, 'success', providerId, cleanReference]
    );
    return true;
  }

  const user = db.users.find(u => String(u.id) === storedUserId);
  if (!user) return false;
  const localPayment = db.payments.find(p => String(p.reference) === cleanReference);
  if (!localPayment) return false;

  if (String(localPayment.status).toLowerCase() === 'success' && user.premium) return true;

  localPayment.status = 'success';
  localPayment.provider_reference = providerId;
  localPayment.paid_at = new Date().toISOString();
  user.premium = true;
  saveLocalDb();
  return true;
}

app.get('/api/payments/callback', async (req, res) => {
  try {
    const reference = cleanText(req.query.reference);
    if (!reference) return res.redirect('/?payment=missing');

    // The browser callback is only a convenience redirect. The backend
    // verifies the transaction with Paystack before granting Premium.
    const paymentData = await verifyPaystack(reference);
    const success = await markPremium(reference, paymentData);
    return res.redirect(success ? '/?payment=success' : '/?payment=failed');
  } catch (error) {
    console.error('Paystack callback error:', error.message);
    return res.redirect('/?payment=failed');
  }
});

app.post('/api/payments/webhook', async (req, res) => {
  try {
    if (!paystackConfigured()) return res.sendStatus(204);

    const signature = req.get('x-paystack-signature') || '';
    const rawBody = req.rawBody || Buffer.from(JSON.stringify(req.body || {}));
    const expectedSignature = crypto
      .createHmac('sha512', process.env.PAYSTACK_SECRET_KEY)
      .update(rawBody)
      .digest('hex');

    const received = Buffer.from(signature, 'utf8');
    const expected = Buffer.from(expectedSignature, 'utf8');
    if (received.length !== expected.length || !crypto.timingSafeEqual(received, expected)) {
      return res.sendStatus(401);
    }

    const event = req.body && typeof req.body === 'object'
      ? req.body
      : JSON.parse(rawBody.toString('utf8'));

    if (event.event === 'charge.success' && event.data?.reference) {
      // Do not trust the webhook payload alone for granting Premium. Re-fetch
      // the transaction from Paystack, then run the same strict checks used by
      // the customer callback.
      const verified = await verifyPaystack(String(event.data.reference));
      const success = await markPremium(String(event.data.reference), verified);
      if (!success) {
        console.error('Paystack webhook rejected: payment/order validation failed.', String(event.data.reference));
        return res.sendStatus(400);
      }
    }

    // Paystack expects a 200 acknowledgement. Other event types are safely
    // acknowledged but do not grant Premium.
    return res.sendStatus(200);
  } catch (error) {
    console.error('Paystack webhook error:', error.message);
    // Non-2xx lets Paystack retry a failed webhook delivery.
    return res.sendStatus(500);
  }
});

app.post('/api/upgrade',requireAuth,(req,res)=>res.status(410).json({error:'The old upgrade endpoint is disabled. Use /api/payments/initialize.'}));

app.use(express.static(path.join(ROOT,'public'),{extensions:['html']}));
app.get(/^(?!\/api(?:\/|$)).*/,(req,res,next)=>{const indexPath=path.join(ROOT,'public','index.html');if(!fs.existsSync(indexPath))return res.status(500).json({error:'public/index.html is missing.'});res.sendFile(indexPath,error=>{if(error)next(error);});});
app.use((error,req,res,next)=>{console.error(error);if(res.headersSent)return next(error);if(error && error.publicPaymentMessage)return res.status(502).json({error:String(error.publicPaymentMessage)});res.status(500).json({error:isProduction?'Server error':String(error.message||'Server error')});});

async function startServer(){
  try{
    questionBank=loadQuestionBank();
    if(!questionBank.length)throw new Error('question.json contains no valid questions.');
    await initDb();
    app.listen(PORT,()=>{console.log('==========================================');console.log(`DENexPharm running on port ${PORT}`);console.log(`Environment: ${isProduction?'production':'development'}`);console.log(`Database: ${pool?'PostgreSQL':'JSON fallback'}`);console.log(`Question bank: ${questionBank.length} questions`);console.log(`Free questions per country/level/subject: ${FREE_QUESTIONS_PER_SUBJECT}`);console.log(`Premium price: ${PREMIUM_PRICE} ${PREMIUM_CURRENCY}`);console.log(`Paystack: ${paystackConfigured() ? (paystackIsLive() ? 'LIVE' : 'NON-LIVE') : 'NOT CONFIGURED'}`);console.log('==========================================');});
  }catch(error){console.error('==========================================');console.error('DENexPharm startup failed:');console.error(error);console.error('==========================================');process.exit(1);}
}
startServer();
