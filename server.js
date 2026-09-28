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
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_IN_PRODUCTION';
const isProduction = process.env.NODE_ENV === 'production';
const frontendOrigin = process.env.FRONTEND_ORIGIN ? process.env.FRONTEND_ORIGIN.split(',').map(x => x.trim()).filter(Boolean) : true;
const MAX_BODY = process.env.MAX_BODY || '1mb';

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], questions: [], scores: [], payments: [] }, null, 2));
let db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
for (const k of ['users', 'questions', 'scores', 'payments']) if (!Array.isArray(db[k])) db[k] = [];

const pool = process.env.DATABASE_URL ? new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: Number(process.env.DB_POOL_MAX || 10)
}) : null;

function saveDb() { fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2)); }
function id() { return crypto.randomUUID(); }
function safeUser(u) { return { id: u.id, email: u.email, name: u.name, university: u.university || '', country: u.country || '', level: u.level || '200', xp: Number(u.xp || 0), premium: !!u.premium, admin: !!u.admin }; }
function signUser(u) { return jwt.sign({ id: u.id, email: u.email, admin: !!u.admin }, JWT_SECRET, { expiresIn: '30d' }); }
function auth(req) {
  const h = req.get('authorization') || '';
  if (!h.startsWith('Bearer ')) return null;
  try { return jwt.verify(h.slice(7), JWT_SECRET); } catch { return null; }
}
function requireAuth(req, res, next) { const a = auth(req); if (!a) return res.status(401).json({ error: 'Sign in required' }); req.auth = a; next(); }
function requireAdmin(req, res, next) { const a = auth(req); if (!a?.admin) return res.status(403).json({ error: 'Admin access required' }); req.auth = a; next(); }
async function sql(text, params = []) { if (!pool) return null; return (await pool.query(text, params)).rows; }
async function initDb() {
  if (!pool) return;
  const schema = fs.readFileSync(path.join(ROOT, 'schema.sql'), 'utf8');
  await pool.query(schema);
  const adminEmail = (process.env.ADMIN_EMAIL || '').trim().toLowerCase();
  const adminPassword = process.env.ADMIN_PASSWORD || '';
  if (adminEmail && adminPassword && adminEmail !== 'admin@example.com') {
    const hash = await bcrypt.hash(adminPassword, 12);
    await pool.query(`INSERT INTO users (email,password_hash,name,admin) VALUES ($1,$2,$3,true) ON CONFLICT (email) DO UPDATE SET admin=true`, [adminEmail, hash, 'DENexPharm Admin']);
  }
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: frontendOrigin, credentials: true }));
app.use(express.json({ limit: MAX_BODY, verify: (req, res, buf) => { req.rawBody = buf; } }));
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: 'draft-8', legacyHeaders: false }));
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: 'draft-8', legacyHeaders: false });

app.get('/api/health', async (req, res) => res.json({ ok: true, version: '4.0.0', database: !!pool, payments: !!process.env.PAYSTACK_SECRET_KEY }));

app.post('/api/auth/register', authLimiter, async (req, res, next) => {
  try {
    const { name, email, password, university = '', country = '', level = '200' } = req.body || {};
    if (!name?.trim() || !email?.trim() || !password) return res.status(400).json({ error: 'Name, email and password are required' });
    if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const em = email.trim().toLowerCase();
    if (pool) {
      if ((await sql('SELECT id FROM users WHERE email=$1', [em])).length) return res.status(409).json({ error: 'Email already registered' });
      const hash = await bcrypt.hash(password, 12);
      const rows = await sql('INSERT INTO users(email,password_hash,name,university,country,level) VALUES($1,$2,$3,$4,$5,$6) RETURNING *', [em, hash, name.trim(), university, country, level]);
      const user = rows[0]; return res.status(201).json({ token: signUser(user), user: safeUser(user) });
    }
    if (db.users.some(u => u.email === em)) return res.status(409).json({ error: 'Email already registered' });
    const user = { id: id(), email: em, password_hash: await bcrypt.hash(password, 12), name: name.trim(), university, country, level, xp: 0, premium: false, admin: false, created_at: new Date().toISOString() };
    db.users.push(user); saveDb(); res.status(201).json({ token: signUser(user), user: safeUser(user) });
  } catch (e) { next(e); }
});

app.post('/api/auth/login', authLimiter, async (req, res, next) => {
  try {
    const em = String(req.body?.email || '').trim().toLowerCase();
    let user = pool ? (await sql('SELECT * FROM users WHERE email=$1', [em]))[0] : db.users.find(u => u.email === em);
    if (!user || !(await bcrypt.compare(req.body?.password || '', user.password_hash))) return res.status(401).json({ error: 'Invalid email or password' });
    res.json({ token: signUser(user), user: safeUser(user) });
  } catch (e) { next(e); }
});

app.get('/api/me', requireAuth, async (req, res, next) => {
  try { const user = pool ? (await sql('SELECT * FROM users WHERE id=$1', [req.auth.id]))[0] : db.users.find(u => String(u.id) === String(req.auth.id)); if (!user) return res.status(404).json({ error: 'User not found' }); res.json({ user: safeUser(user) }); } catch (e) { next(e); }
});

app.get('/api/questions', async (req, res, next) => {
  try {
    const subject = req.query.subject ? String(req.query.subject) : null;
    let questions = pool ? await sql(`SELECT id,subject,question,options,answer_index,explanation FROM questions WHERE active=true ${subject ? 'AND subject=$1' : ''} ORDER BY id`, subject ? [subject] : []) : db.questions.filter(q => q.active !== false && (!subject || q.subject === subject));
    res.json({ questions });
  } catch (e) { next(e); }
});

app.post('/api/scores', requireAuth, async (req, res, next) => {
  try {
    const subject = String(req.body?.subject || 'General'); const score = Math.max(0, Number(req.body?.score || 0)); const total = Math.max(1, Number(req.body?.total || 1));
    const xp = Math.min(score * 10, total * 10);
    if (pool) { await sql('INSERT INTO scores(user_id,subject,score,total) VALUES($1,$2,$3,$4)', [req.auth.id, subject, score, total]); await sql('UPDATE users SET xp=xp+$1 WHERE id=$2', [xp, req.auth.id]); }
    else { db.scores.push({ id: id(), user_id: req.auth.id, subject, score, total, created_at: new Date().toISOString() }); const u = db.users.find(x => String(x.id) === String(req.auth.id)); if (u) u.xp = Number(u.xp || 0) + xp; saveDb(); }
    res.status(201).json({ ok: true, xp });
  } catch (e) { next(e); }
});

app.get('/api/leaderboard', async (req, res, next) => {
  try { const leaderboard = pool ? await sql('SELECT id,name,university,country,xp FROM users ORDER BY xp DESC, name ASC LIMIT 100') : db.users.map(safeUser).sort((a,b) => b.xp-a.xp || a.name.localeCompare(b.name)).slice(0,100); res.json({ leaderboard }); } catch (e) { next(e); }
});

app.get('/api/admin/questions', requireAdmin, async (req, res, next) => { try { res.json({ questions: pool ? await sql('SELECT * FROM questions ORDER BY id DESC') : db.questions }); } catch(e){next(e);} });
app.post('/api/admin/questions', requireAdmin, async (req, res, next) => {
  try { const b=req.body||{}; if(!b.subject||!b.question||!Array.isArray(b.options)||b.options.length!==4||!Number.isInteger(Number(b.answer_index))) return res.status(400).json({error:'Subject, question, exactly four options and answer_index are required'}); if(pool){const r=await sql('INSERT INTO questions(subject,question,options,answer_index,explanation) VALUES($1,$2,$3,$4,$5) RETURNING *',[b.subject,b.question,b.options,Number(b.answer_index),b.explanation||'']);return res.status(201).json({question:r[0]});} const q={id:id(),subject:b.subject,question:b.question,options:b.options,answer_index:Number(b.answer_index),explanation:b.explanation||'',active:true,updated_at:new Date().toISOString()};db.questions.push(q);saveDb();res.status(201).json({question:q}); } catch(e){next(e);} });

app.post('/api/payments/initialize', requireAuth, async (req,res,next)=>{
  try {
    if(!process.env.PAYSTACK_SECRET_KEY) return res.status(503).json({error:'Paystack is not configured yet. Add PAYSTACK_SECRET_KEY in Render environment variables.'});
    const amount=Number(req.body?.amount || process.env.PREMIUM_PRICE || 5000); const currency=String(req.body?.currency || process.env.PREMIUM_CURRENCY || 'NGN').toUpperCase();
    if(!Number.isFinite(amount)||amount<=0) return res.status(400).json({error:'Invalid payment amount'});
    const user=pool?(await sql('SELECT * FROM users WHERE id=$1',[req.auth.id]))[0]:db.users.find(u=>String(u.id)===String(req.auth.id)); if(!user)return res.status(404).json({error:'User not found'});
    const reference='DENEX_'+Date.now()+'_'+crypto.randomBytes(5).toString('hex').toUpperCase();
    const r=await fetch('https://api.paystack.co/transaction/initialize',{method:'POST',headers:{Authorization:'Bearer '+process.env.PAYSTACK_SECRET_KEY,'Content-Type':'application/json'},body:JSON.stringify({email:user.email,amount:Math.round(amount*100),currency,reference,metadata:{user_id:String(req.auth.id),product:'DENexPharm Premium'},callback_url:process.env.PAYSTACK_CALLBACK_URL||undefined})});
    const d=await r.json(); if(!r.ok||!d.status) return res.status(502).json({error:d.message||'Payment initialization failed'});
    if(pool) await sql('INSERT INTO payments(reference,user_id,amount,currency,status) VALUES($1,$2,$3,$4,$5)',[reference,req.auth.id,amount,currency,'initialized']); else {db.payments.push({reference,user_id:req.auth.id,amount,currency,status:'initialized'});saveDb();}
    res.json({authorization_url:d.data.authorization_url,reference:d.data.reference});
  }catch(e){next(e);}
});

async function verifyPaystack(reference){
  if(!process.env.PAYSTACK_SECRET_KEY) throw new Error('Paystack not configured');
  const r=await fetch('https://api.paystack.co/transaction/verify/'+encodeURIComponent(reference),{headers:{Authorization:'Bearer '+process.env.PAYSTACK_SECRET_KEY}}); const d=await r.json(); if(!r.ok||!d.status) throw new Error(d.message||'Verification failed'); return d.data;
}
async function markPremium(reference, data){
  if (data?.status !== 'success') return false;
  const uid=data?.metadata?.user_id; if(!uid) return false;
  if(pool){await sql('UPDATE users SET premium=true WHERE id=$1',[uid]);await sql('UPDATE payments SET status=$1,provider_reference=$2 WHERE reference=$3',['success',String(data.id||reference),reference]);}
  else {const u=db.users.find(x=>String(x.id)===String(uid)); if(u)u.premium=true; const p=db.payments.find(x=>x.reference===reference); if(p){p.status='success';p.provider_reference=String(data.id||reference);} saveDb();}
  return true;
}
app.get('/api/payments/callback', async(req,res)=>{try{const reference=String(req.query.reference||'');if(!reference)return res.redirect('/?payment=missing');const data=await verifyPaystack(reference);await markPremium(reference,data);res.redirect('/?payment=success');}catch(e){res.redirect('/?payment=failed');}});
app.post('/api/payments/webhook', async(req,res)=>{try{if(!process.env.PAYSTACK_SECRET_KEY)return res.sendStatus(204);const raw=req.rawBody||Buffer.from(JSON.stringify(req.body||{}));const sig=crypto.createHmac('sha512',process.env.PAYSTACK_SECRET_KEY).update(raw).digest('hex');if(sig!==req.get('x-paystack-signature'))return res.sendStatus(401);const event=typeof req.body==='object'?req.body:JSON.parse(raw.toString());if(event.event==='charge.success')await markPremium(event.data.reference,event.data);res.sendStatus(200);}catch(e){res.sendStatus(400);}});

app.post('/api/upgrade', requireAuth, async (req,res)=>res.status(410).json({error:'Use /api/payments/initialize for verified Premium payments.'}));

app.use(express.static(path.join(ROOT,'public'), { extensions:['html'] }));
app.get(/^(?!\/api\/).*/, (req,res,next)=>{ res.sendFile(path.join(ROOT,'public','index.html'), err => err ? next(err) : undefined); });
app.use((err,req,res,next)=>{ console.error(err); res.status(500).json({error:isProduction?'Server error':err.message}); });

initDb().then(()=>app.listen(PORT,()=>console.log(`DENexPharm v4.0.0 running on port ${PORT}`))).catch(err=>{console.error('Startup failed:',err);process.exit(1);});
